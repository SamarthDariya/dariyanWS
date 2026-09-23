package iam

import (
	"context"
	"errors"
	"testing"

	commonv1 "dariyanws/gen/dariya/common/v1"
	iamv1 "dariyanws/gen/dariya/iam/v1"
	"dariyanws/internal/apierr"
)

func (f *fixture) authorizer(dev bool) *Authorizer {
	return NewAuthorizer(f.iam, AuthorizerOptions{Dev: dev})
}

func authorizeReq(principalARN, action, resourceARN string) *iamv1.AuthorizeRequest {
	return &iamv1.AuthorizeRequest{
		Principal:   &commonv1.Principal{PrincipalArn: principalARN},
		Action:      action,
		ResourceArn: resourceARN,
	}
}

func TestAuthorizeAllowsWhatAPolicyGrants(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	acct := f.account(t)
	principal := "arn:dariya:iam:hind-1:" + acct + ":user/root"
	resource := "arn:dariya:func:hind-1:" + acct + ":function/resize"

	created, err := f.iam.CreatePolicy(ctx, &iamv1.CreatePolicyRequest{
		AccountId: acct, Name: "invoke", Document: invokeDoc(resource),
	})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	if _, err := f.iam.AttachPolicy(ctx, &iamv1.AttachPolicyRequest{
		PolicyArn: created.GetPolicy().GetPolicyArn(), PrincipalArn: principal,
	}); err != nil {
		t.Fatalf("AttachPolicy: %v", err)
	}

	resp, err := f.authorizer(true).Authorize(ctx, authorizeReq(principal, "func:Invoke", resource))
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if resp.GetDecision() != iamv1.Decision_DECISION_ALLOW {
		t.Fatalf("decision = %v, reason = %q", resp.GetDecision(), resp.GetReason())
	}
	if resp.GetMatchedSid() != "invoke" {
		t.Errorf("matched sid = %q", resp.GetMatchedSid())
	}
}

func TestAuthorizeDeniesByDefault(t *testing.T) {
	f := newFixture(t)
	acct := f.account(t)

	resp, err := f.authorizer(false).Authorize(context.Background(), authorizeReq(
		"arn:dariya:iam:hind-1:"+acct+":user/root",
		"func:Invoke",
		"arn:dariya:func:hind-1:"+acct+":function/resize"))
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if resp.GetDecision() != iamv1.Decision_DECISION_IMPLICIT_DENY {
		t.Errorf("decision = %v, want IMPLICIT_DENY", resp.GetDecision())
	}
}

// The check that does not depend on any policy being written correctly. A careless
// "Resource": "*" must not be able to reach another tenant.
func TestAuthorizeRefusesCrossAccountEvenWithAWildcardPolicy(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	attacker, victim := f.account(t), f.account(t)
	principal := "arn:dariya:iam:hind-1:" + attacker + ":user/root"

	// The broadest policy the system can express, attached to the attacker's own principal.
	created, err := f.iam.CreatePolicy(ctx, &iamv1.CreatePolicyRequest{
		AccountId: attacker, Name: "everything",
		Document: &iamv1.PolicyDocument{Statements: []*iamv1.Statement{{
			Sid: "all", Effect: iamv1.Effect_EFFECT_ALLOW,
			Actions: []string{"*"}, Resources: []string{"*"},
		}}},
	})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	if _, err := f.iam.AttachPolicy(ctx, &iamv1.AttachPolicyRequest{
		PolicyArn: created.GetPolicy().GetPolicyArn(), PrincipalArn: principal,
	}); err != nil {
		t.Fatalf("AttachPolicy: %v", err)
	}

	victimResource := "arn:dariya:func:hind-1:" + victim + ":function/secret"
	resp, err := f.authorizer(true).Authorize(ctx,
		authorizeReq(principal, "func:Invoke", victimResource))
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if resp.GetDecision() == iamv1.Decision_DECISION_ALLOW {
		t.Fatal("an allow-everything policy reached another account's resource")
	}
	if resp.GetDecision() != iamv1.Decision_DECISION_EXPLICIT_DENY {
		t.Errorf("decision = %v, want EXPLICIT_DENY", resp.GetDecision())
	}

	// And the same policy must still work inside its own account, or the check is too broad.
	ownResource := "arn:dariya:func:hind-1:" + attacker + ":function/mine"
	own, err := f.authorizer(false).Authorize(ctx, authorizeReq(principal, "func:Invoke", ownResource))
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if own.GetDecision() != iamv1.Decision_DECISION_ALLOW {
		t.Errorf("the wildcard policy was refused inside its own account: %v", own.GetDecision())
	}
}

// A denial that explains itself describes a policy to someone not allowed to read it.
func TestReasonOnlyInDev(t *testing.T) {
	f := newFixture(t)
	acct := f.account(t)
	req := authorizeReq(
		"arn:dariya:iam:hind-1:"+acct+":user/root",
		"func:Invoke",
		"arn:dariya:func:hind-1:"+acct+":function/x")

	prod, err := f.authorizer(false).Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if prod.GetReason() != "" {
		t.Errorf("production explained a denial: %q", prod.GetReason())
	}

	dev, err := f.authorizer(true).Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if dev.GetReason() == "" {
		t.Error("dev mode did not explain a denial")
	}
}

func TestAuthorizeValidatesItsInput(t *testing.T) {
	f := newFixture(t)
	acct := f.account(t)
	good := "arn:dariya:iam:hind-1:" + acct + ":user/root"

	cases := map[string]*iamv1.AuthorizeRequest{
		"no principal":       authorizeReq("", "func:Invoke", "arn:dariya:func:hind-1:"+acct+":function/x"),
		"no action":          authorizeReq(good, "", "arn:dariya:func:hind-1:"+acct+":function/x"),
		"malformed resource": authorizeReq(good, "func:Invoke", "not-an-arn"),
		"malformed principal": authorizeReq("not-an-arn", "func:Invoke",
			"arn:dariya:func:hind-1:"+acct+":function/x"),
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := f.authorizer(false).Authorize(context.Background(), req)
			if got := apierr.From(err).Code; got != apierr.CodeValidation {
				t.Errorf("code = %s, want %s", got, apierr.CodeValidation)
			}
		})
	}
}

// A failure to read policies must surface as an error, not as a denial. A denial would be
// indistinguishable from a real one and would hide an outage as a permissions problem — the bug
// report nobody can diagnose.
func TestReadFailureIsAnErrorNotADenial(t *testing.T) {
	broken := failingSource{err: errors.New("connection refused")}
	a := NewAuthorizer(broken, AuthorizerOptions{})

	_, err := a.Authorize(context.Background(), authorizeReq(
		"arn:dariya:iam:hind-1:000000000001:user/root",
		"func:Invoke",
		"arn:dariya:func:hind-1:000000000001:function/x"))
	if err == nil {
		t.Fatal("a failed policy read produced a decision instead of an error")
	}
}

type failingSource struct{ err error }

func (f failingSource) PoliciesFor(context.Context, string) ([]AttachedPolicy, error) {
	return nil, f.err
}

// E2's lesson applied to the second lookup: it must not hit Postgres once per request.
func TestPoliciesAreCached(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	acct := f.account(t)
	principal := "arn:dariya:iam:hind-1:" + acct + ":user/root"
	resource := "arn:dariya:func:hind-1:" + acct + ":function/x"

	a := f.authorizer(false)
	for i := 0; i < 20; i++ {
		if _, err := a.Authorize(ctx, authorizeReq(principal, "func:Invoke", resource)); err != nil {
			t.Fatalf("Authorize %d: %v", i, err)
		}
	}

	s := a.Stats()
	if s.Misses != 1 || s.Hits != 19 {
		t.Errorf("cache stats = %+v, want 1 miss and 19 hits", s)
	}
}

// "No policies" is a cacheable positive, not an error — otherwise the most common state of a new
// account is the one that bypasses the cache.
func TestEmptyPolicySetIsCached(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	acct := f.account(t)

	a := f.authorizer(false)
	req := authorizeReq(
		"arn:dariya:iam:hind-1:"+acct+":user/nobody",
		"func:Invoke",
		"arn:dariya:func:hind-1:"+acct+":function/x")

	for i := 0; i < 5; i++ {
		if _, err := a.Authorize(ctx, req); err != nil {
			t.Fatalf("Authorize: %v", err)
		}
	}
	if s := a.Stats(); s.Misses != 1 {
		t.Errorf("an empty policy set was loaded %d times, want 1", s.Misses)
	}
}

// Attaching a policy must take effect at once on the process that served the attach.
func TestInvalidatePrincipal(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	acct := f.account(t)
	principal := "arn:dariya:iam:hind-1:" + acct + ":user/root"
	resource := "arn:dariya:func:hind-1:" + acct + ":function/x"

	a := f.authorizer(false)
	req := authorizeReq(principal, "func:Invoke", resource)

	if resp, _ := a.Authorize(ctx, req); resp.GetDecision() == iamv1.Decision_DECISION_ALLOW {
		t.Fatal("allowed before any policy existed")
	}

	created, err := f.iam.CreatePolicy(ctx, &iamv1.CreatePolicyRequest{
		AccountId: acct, Name: "p", Document: invokeDoc(resource),
	})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	if _, err := f.iam.AttachPolicy(ctx, &iamv1.AttachPolicyRequest{
		PolicyArn: created.GetPolicy().GetPolicyArn(), PrincipalArn: principal,
	}); err != nil {
		t.Fatalf("AttachPolicy: %v", err)
	}

	// Still denied: the empty result is cached, which is the cost being accepted.
	if resp, _ := a.Authorize(ctx, req); resp.GetDecision() == iamv1.Decision_DECISION_ALLOW {
		t.Error("the cache was bypassed; this test no longer proves anything about the TTL")
	}

	a.InvalidatePrincipal(principal)

	if resp, _ := a.Authorize(ctx, req); resp.GetDecision() != iamv1.Decision_DECISION_ALLOW {
		t.Error("invalidation did not take effect")
	}
}

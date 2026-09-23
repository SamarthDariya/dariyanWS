package iam

import (
	"context"
	"testing"
	"time"

	commonv1 "dariyanws/gen/dariya/common/v1"
	controlv1 "dariyanws/gen/dariya/control/v1"
	iamv1 "dariyanws/gen/dariya/iam/v1"
	"dariyanws/internal/apierr"
	"dariyanws/internal/control"
	"dariyanws/internal/secrets"
	"dariyanws/internal/store"
)

const testRegion = "hind-1"

type fixture struct {
	iam      *Server
	accounts *control.AccountsServer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	st := store.OpenTest(t)
	store.TruncateAll(t, st)

	key, err := secrets.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	kr, err := secrets.NewKeyring(map[string][]byte{"test": key}, "test")
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}

	clock := func() time.Time { return time.UnixMilli(1_700_000_000_000) }
	return &fixture{
		iam:      NewServer(st, testRegion, clock),
		accounts: control.NewAccountsServer(st, kr, testRegion, clock),
	}
}

func (f *fixture) account(t *testing.T) string {
	t.Helper()
	resp, err := f.accounts.CreateAccount(context.Background(),
		&controlv1.CreateAccountRequest{Name: "t"})
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	return resp.GetAccount().GetAccountId()
}

func invokeDoc(resource string) *iamv1.PolicyDocument {
	return &iamv1.PolicyDocument{Statements: []*iamv1.Statement{{
		Sid:       "invoke",
		Effect:    iamv1.Effect_EFFECT_ALLOW,
		Actions:   []string{"func:Invoke"},
		Resources: []string{resource},
	}}}
}

func TestCreateAndGetPolicy(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	acct := f.account(t)

	created, err := f.iam.CreatePolicy(ctx, &iamv1.CreatePolicyRequest{
		AccountId: acct, Name: "invoke-all", Document: invokeDoc("*"),
	})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	want := PolicyARN(testRegion, acct, "invoke-all")
	if got := created.GetPolicy().GetPolicyArn(); got != want {
		t.Errorf("policy arn = %q, want %q", got, want)
	}
	// A document with no version gets the dated default, so the evaluation rules can change
	// later without reinterpreting policies written against the old ones.
	if created.GetPolicy().GetDocument().GetVersion() != DocumentVersion {
		t.Errorf("version = %q", created.GetPolicy().GetDocument().GetVersion())
	}

	// protojson has to round-trip faithfully, because it is what the table stores.
	read, err := f.iam.GetPolicy(ctx, &iamv1.GetPolicyRequest{PolicyArn: want})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	stmts := read.GetPolicy().GetDocument().GetStatements()
	if len(stmts) != 1 || stmts[0].GetSid() != "invoke" ||
		stmts[0].GetEffect() != iamv1.Effect_EFFECT_ALLOW ||
		len(stmts[0].GetActions()) != 1 || stmts[0].GetActions()[0] != "func:Invoke" {
		t.Errorf("document did not round trip: %+v", stmts)
	}
}

// An upsert here would let a retry with a different document quietly replace a policy someone
// else wrote.
func TestDuplicateNameIsAConflict(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	acct := f.account(t)

	req := &iamv1.CreatePolicyRequest{AccountId: acct, Name: "dup", Document: invokeDoc("*")}
	if _, err := f.iam.CreatePolicy(ctx, req); err != nil {
		t.Fatalf("first: %v", err)
	}
	_, err := f.iam.CreatePolicy(ctx, req)
	if got := apierr.From(err).Code; got != apierr.CodeAlreadyExists {
		t.Errorf("code = %s, want %s", got, apierr.CodeAlreadyExists)
	}
}

func TestCreatePolicyIsIdempotent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	acct := f.account(t)

	req := &iamv1.CreatePolicyRequest{
		AccountId: acct, Name: "idem", Document: invokeDoc("*"), ClientToken: "tok-1",
	}
	first, err := f.iam.CreatePolicy(ctx, req)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := f.iam.CreatePolicy(ctx, req)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if first.GetPolicy().GetPolicyArn() != second.GetPolicy().GetPolicyArn() {
		t.Error("a retry produced a different policy")
	}
}

func TestInvalidDocumentIsRejectedAtWriteTime(t *testing.T) {
	f := newFixture(t)
	acct := f.account(t)

	_, err := f.iam.CreatePolicy(context.Background(), &iamv1.CreatePolicyRequest{
		AccountId: acct, Name: "empty",
		Document: &iamv1.PolicyDocument{Statements: []*iamv1.Statement{{
			Sid: "nothing", Effect: iamv1.Effect_EFFECT_ALLOW, Actions: []string{"func:Invoke"},
			// no resources: can never match, reads like a grant
		}}},
	})
	if got := apierr.From(err).Code; got != apierr.CodeValidation {
		t.Errorf("code = %s, want %s", got, apierr.CodeValidation)
	}
}

func TestAttachAndEvaluate(t *testing.T) {
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
	policyARN := created.GetPolicy().GetPolicyArn()

	// Before attachment, the default answer is no.
	policies, err := f.iam.PoliciesFor(ctx, principal)
	if err != nil {
		t.Fatalf("PoliciesFor: %v", err)
	}
	if d := Evaluate(policies, Request{Action: "func:Invoke", ResourceARN: resource}); d.Allowed() {
		t.Fatal("an unattached policy granted access")
	}

	if _, err := f.iam.AttachPolicy(ctx, &iamv1.AttachPolicyRequest{
		PolicyArn: policyARN, PrincipalArn: principal,
	}); err != nil {
		t.Fatalf("AttachPolicy: %v", err)
	}

	policies, err = f.iam.PoliciesFor(ctx, principal)
	if err != nil {
		t.Fatalf("PoliciesFor: %v", err)
	}
	if d := Evaluate(policies, Request{Action: "func:Invoke", ResourceARN: resource}); !d.Allowed() {
		t.Errorf("an attached policy did not grant access: %+v", d)
	}
}

// Attaching a policy across accounts is a cross-tenant privilege grant performed by an API that
// looks like bookkeeping.
func TestAttachRefusesForeignPrincipal(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a, b := f.account(t), f.account(t)

	created, err := f.iam.CreatePolicy(ctx, &iamv1.CreatePolicyRequest{
		AccountId: a, Name: "p", Document: invokeDoc("*"),
	})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	_, err = f.iam.AttachPolicy(ctx, &iamv1.AttachPolicyRequest{
		PolicyArn:    created.GetPolicy().GetPolicyArn(),
		PrincipalArn: "arn:dariya:iam:hind-1:" + b + ":user/root",
	})
	if err == nil {
		t.Fatal("a policy was attached to another account's principal")
	}
	if got := apierr.From(err).Code; got != apierr.CodeValidation {
		t.Errorf("code = %s", got)
	}
}

func TestAttachIsIdempotent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	acct := f.account(t)
	principal := "arn:dariya:iam:hind-1:" + acct + ":user/root"

	created, _ := f.iam.CreatePolicy(ctx, &iamv1.CreatePolicyRequest{
		AccountId: acct, Name: "p", Document: invokeDoc("*"),
	})
	req := &iamv1.AttachPolicyRequest{
		PolicyArn: created.GetPolicy().GetPolicyArn(), PrincipalArn: principal,
	}

	for i := 0; i < 3; i++ {
		if _, err := f.iam.AttachPolicy(ctx, req); err != nil {
			t.Fatalf("attach %d: %v", i, err)
		}
	}
	policies, err := f.iam.PoliciesFor(ctx, principal)
	if err != nil {
		t.Fatalf("PoliciesFor: %v", err)
	}
	if len(policies) != 1 {
		t.Errorf("attaching three times produced %d attachments", len(policies))
	}
}

// Someone detaching is usually revoking. "It was already gone" and "you detached the wrong thing"
// must not look identical.
func TestDetachUnattachedIsNotFound(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	acct := f.account(t)

	created, _ := f.iam.CreatePolicy(ctx, &iamv1.CreatePolicyRequest{
		AccountId: acct, Name: "p", Document: invokeDoc("*"),
	})
	_, err := f.iam.DetachPolicy(ctx, &iamv1.DetachPolicyRequest{
		PolicyArn:    created.GetPolicy().GetPolicyArn(),
		PrincipalArn: "arn:dariya:iam:hind-1:" + acct + ":user/nobody",
	})
	if got := apierr.From(err).Code; got != apierr.CodeNotFound {
		t.Errorf("code = %s, want %s", got, apierr.CodeNotFound)
	}
}

// A two-step revocation is a revocation that gets half done, so deleting a policy must take its
// attachments with it.
func TestDeleteCascadesToAttachments(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	acct := f.account(t)
	principal := "arn:dariya:iam:hind-1:" + acct + ":user/root"

	created, _ := f.iam.CreatePolicy(ctx, &iamv1.CreatePolicyRequest{
		AccountId: acct, Name: "p", Document: invokeDoc("*"),
	})
	policyARN := created.GetPolicy().GetPolicyArn()

	if _, err := f.iam.AttachPolicy(ctx, &iamv1.AttachPolicyRequest{
		PolicyArn: policyARN, PrincipalArn: principal,
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if _, err := f.iam.DeletePolicy(ctx, &iamv1.DeletePolicyRequest{PolicyArn: policyARN}); err != nil {
		t.Fatalf("delete: %v", err)
	}

	policies, err := f.iam.PoliciesFor(ctx, principal)
	if err != nil {
		t.Fatalf("PoliciesFor: %v", err)
	}
	if len(policies) != 0 {
		t.Errorf("deleting a policy left %d attachments behind", len(policies))
	}
}

func TestListPoliciesPaginates(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	acct := f.account(t)

	const total = 5
	for i := 0; i < total; i++ {
		if _, err := f.iam.CreatePolicy(ctx, &iamv1.CreatePolicyRequest{
			AccountId: acct, Name: "p" + string(rune('a'+i)), Document: invokeDoc("*"),
		}); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}

	seen := map[string]bool{}
	token := ""
	for pages := 0; ; pages++ {
		if pages > total {
			t.Fatal("pagination did not terminate")
		}
		resp, err := f.iam.ListPolicies(ctx, &iamv1.ListPoliciesRequest{
			AccountId: acct, Page: &commonv1.PageRequest{MaxResults: 2, NextToken: token},
		})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		for _, p := range resp.GetPolicies() {
			if seen[p.GetPolicyArn()] {
				t.Errorf("policy %s appeared twice", p.GetPolicyArn())
			}
			seen[p.GetPolicyArn()] = true
		}
		if token = resp.GetPage().GetNextToken(); token == "" {
			break
		}
	}
	if len(seen) != total {
		t.Errorf("saw %d policies, want %d", len(seen), total)
	}
}

// One account must not see another's policies, even with a valid page token.
func TestListIsScopedToTheAccount(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a, b := f.account(t), f.account(t)

	if _, err := f.iam.CreatePolicy(ctx, &iamv1.CreatePolicyRequest{
		AccountId: a, Name: "secret", Document: invokeDoc("*"),
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	resp, err := f.iam.ListPolicies(ctx, &iamv1.ListPoliciesRequest{AccountId: b})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(resp.GetPolicies()) != 0 {
		t.Errorf("account %s saw %d policies belonging to %s", b, len(resp.GetPolicies()), a)
	}
}

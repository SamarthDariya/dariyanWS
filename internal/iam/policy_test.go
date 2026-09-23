package iam

import (
	"testing"

	iamv1 "dariyanws/gen/dariya/iam/v1"
)

const (
	fnA     = "arn:dariya:func:hind-1:000000000001:function/a"
	fnB     = "arn:dariya:func:hind-1:000000000001:function/b"
	qOrders = "arn:dariya:kyu:hind-1:000000000001:queue/orders"
	// Same resource path, different account. The string is one character from fnA's owner and
	// must never match a policy written for it.
	fnAOther = "arn:dariya:func:hind-1:000000000002:function/a"
)

func statement(sid string, effect iamv1.Effect, actions, resources []string) *iamv1.Statement {
	return &iamv1.Statement{Sid: sid, Effect: effect, Actions: actions, Resources: resources}
}

func policy(arn string, statements ...*iamv1.Statement) AttachedPolicy {
	return AttachedPolicy{
		PolicyARN: arn,
		Document:  &iamv1.PolicyDocument{Version: "2026-09-01", Statements: statements},
	}
}

func allow(sid string, actions, resources []string) *iamv1.Statement {
	return statement(sid, iamv1.Effect_EFFECT_ALLOW, actions, resources)
}

func deny(sid string, actions, resources []string) *iamv1.Statement {
	return statement(sid, iamv1.Effect_EFFECT_DENY, actions, resources)
}

// Rule 3, and the most important test in the package: nothing is permitted by default.
func TestNoPoliciesMeansDenied(t *testing.T) {
	d := Evaluate(nil, Request{Action: "func:Invoke", ResourceARN: fnA})

	if d.Allowed() {
		t.Fatal("a principal with no policies was allowed")
	}
	if d.Effect != iamv1.Decision_DECISION_IMPLICIT_DENY {
		t.Errorf("effect = %v, want IMPLICIT_DENY", d.Effect)
	}
	// The emptiness is the diagnosis: "nothing mentions this", not "something said no".
	if d.PolicyARN != "" || d.SID != "" {
		t.Errorf("an implicit deny named a statement: %+v", d)
	}
}

func TestExactAllow(t *testing.T) {
	p := policy("arn:policy/1", allow("s1", []string{"func:Invoke"}, []string{fnA}))

	d := Evaluate([]AttachedPolicy{p}, Request{Action: "func:Invoke", ResourceARN: fnA})
	if !d.Allowed() {
		t.Fatalf("exact match was denied: %+v", d)
	}
	if d.SID != "s1" || d.PolicyARN != "arn:policy/1" {
		t.Errorf("decision did not name the statement that made it: %+v", d)
	}
}

func TestWrongResourceIsDenied(t *testing.T) {
	p := policy("arn:policy/1", allow("s1", []string{"func:Invoke"}, []string{fnA}))

	if d := Evaluate([]AttachedPolicy{p}, Request{Action: "func:Invoke", ResourceARN: fnB}); d.Allowed() {
		t.Error("a policy for function/a allowed function/b")
	}
}

func TestWrongActionIsDenied(t *testing.T) {
	p := policy("arn:policy/1", allow("s1", []string{"func:Invoke"}, []string{fnA}))

	if d := Evaluate([]AttachedPolicy{p}, Request{Action: "func:DeleteFunction", ResourceARN: fnA}); d.Allowed() {
		t.Error("an Invoke grant allowed DeleteFunction")
	}
}

// Rule 1. A deny must beat an allow regardless of which policy it lives in or what order the
// policies arrive in — which is why both orderings are tested.
func TestDenyWinsRegardlessOfOrder(t *testing.T) {
	allowAll := policy("arn:policy/allow", allow("a", []string{"func:*"}, []string{"*"}))
	denyOne := policy("arn:policy/deny", deny("d", []string{"func:Invoke"}, []string{fnA}))

	for _, order := range [][]AttachedPolicy{
		{allowAll, denyOne},
		{denyOne, allowAll},
	} {
		d := Evaluate(order, Request{Action: "func:Invoke", ResourceARN: fnA})
		if d.Allowed() {
			t.Fatal("an explicit deny was overridden by an allow")
		}
		if d.Effect != iamv1.Decision_DECISION_EXPLICIT_DENY {
			t.Errorf("effect = %v, want EXPLICIT_DENY", d.Effect)
		}
		if d.SID != "d" {
			t.Errorf("deny decision named %q", d.SID)
		}
	}
}

// A deny in one statement must not suppress an unrelated allow in the same policy.
func TestDenyIsScopedToWhatItMatches(t *testing.T) {
	p := policy("arn:policy/1",
		allow("a", []string{"func:Invoke"}, []string{"arn:dariya:func:hind-1:000000000001:function/*"}),
		deny("d", []string{"func:Invoke"}, []string{fnB}),
	)

	if d := Evaluate([]AttachedPolicy{p}, Request{Action: "func:Invoke", ResourceARN: fnA}); !d.Allowed() {
		t.Errorf("a deny on function/b blocked function/a: %+v", d)
	}
	if d := Evaluate([]AttachedPolicy{p}, Request{Action: "func:Invoke", ResourceARN: fnB}); d.Allowed() {
		t.Error("a deny on function/b did not block function/b")
	}
}

func TestWildcards(t *testing.T) {
	cases := []struct {
		name    string
		actions []string
		res     []string
		req     Request
		want    bool
	}{
		{"service wildcard action", []string{"kyu:*"}, []string{"*"},
			Request{Action: "kyu:SendMessage", ResourceARN: qOrders}, true},
		{"service wildcard does not cross services", []string{"kyu:*"}, []string{"*"},
			Request{Action: "func:Invoke", ResourceARN: fnA}, false},
		{"resource prefix", []string{"func:Invoke"},
			[]string{"arn:dariya:func:hind-1:000000000001:function/*"},
			Request{Action: "func:Invoke", ResourceARN: fnA}, true},
		{"bare star allows anything", []string{"*"}, []string{"*"},
			Request{Action: "func:Invoke", ResourceARN: fnA}, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := policy("arn:policy/1", allow("s", c.actions, c.res))
			if got := Evaluate([]AttachedPolicy{p}, c.req).Allowed(); got != c.want {
				t.Errorf("allowed = %v, want %v", got, c.want)
			}
		})
	}
}

// The wildcard that matters most, because getting it wrong is a cross-tenant breach rather than
// an inconvenience: a prefix written for one account must not match another's ARN.
func TestResourceWildcardDoesNotCrossAccounts(t *testing.T) {
	p := policy("arn:policy/1", allow("s",
		[]string{"func:Invoke"},
		[]string{"arn:dariya:func:hind-1:000000000001:function/*"}))

	if d := Evaluate([]AttachedPolicy{p}, Request{Action: "func:Invoke", ResourceARN: fnAOther}); d.Allowed() {
		t.Error("a policy scoped to account ...001 allowed a resource in account ...002")
	}
}

// A "*" in the middle is treated as a literal. Between two failure modes for a typo, quietly
// restrictive beats quietly permissive.
func TestStarIsOnlyAWildcardAtTheEnd(t *testing.T) {
	if Match("arn:*:function/a", fnA) {
		t.Error("a mid-string star matched as a wildcard")
	}
	if !Match("arn:dariya:func:hind-1:000000000001:function/*", fnA) {
		t.Error("a trailing star failed to match")
	}
}

// A proto3 zero value must never be the permissive answer. A client that forgets to set the
// effect field must not thereby grant access.
func TestUnspecifiedEffectGrantsNothing(t *testing.T) {
	p := policy("arn:policy/1",
		statement("s", iamv1.Effect_EFFECT_UNSPECIFIED, []string{"*"}, []string{"*"}))

	if d := Evaluate([]AttachedPolicy{p}, Request{Action: "func:Invoke", ResourceARN: fnA}); d.Allowed() {
		t.Error("a statement with no effect allowed a request")
	}
}

// The first allow found wins, but only among allows — so which one is reported must not depend on
// a deny appearing later, which TestDenyWinsRegardlessOfOrder already covers from the other side.
func TestMultipleAllowsReportTheFirst(t *testing.T) {
	p1 := policy("arn:policy/1", allow("first", []string{"func:Invoke"}, []string{fnA}))
	p2 := policy("arn:policy/2", allow("second", []string{"func:*"}, []string{"*"}))

	d := Evaluate([]AttachedPolicy{p1, p2}, Request{Action: "func:Invoke", ResourceARN: fnA})
	if !d.Allowed() || d.SID != "first" {
		t.Errorf("decision = %+v, want the first allow", d)
	}
}

func TestValidateDocument(t *testing.T) {
	cases := map[string]*iamv1.PolicyDocument{
		"nil":            nil,
		"no statements":  {Version: "2026-09-01"},
		"no effect":      {Statements: []*iamv1.Statement{statement("s", iamv1.Effect_EFFECT_UNSPECIFIED, []string{"a"}, []string{"b"})}},
		"no actions":     {Statements: []*iamv1.Statement{allow("s", nil, []string{"b"})}},
		"no resources":   {Statements: []*iamv1.Statement{allow("s", []string{"a"}, nil)}},
		"empty action":   {Statements: []*iamv1.Statement{allow("s", []string{""}, []string{"b"})}},
		"empty resource": {Statements: []*iamv1.Statement{allow("s", []string{"a"}, []string{""})}},
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateDocument(doc); err == nil {
				t.Error("accepted")
			}
		})
	}

	valid := &iamv1.PolicyDocument{
		Version:    "2026-09-01",
		Statements: []*iamv1.Statement{allow("s", []string{"func:Invoke"}, []string{fnA})},
	}
	if err := ValidateDocument(valid); err != nil {
		t.Errorf("rejected a valid document: %v", err)
	}
}

// The error has to say which statement, or a policy with eight of them is a guessing game.
func TestValidationErrorNamesTheStatement(t *testing.T) {
	doc := &iamv1.PolicyDocument{Statements: []*iamv1.Statement{
		allow("ok", []string{"func:Invoke"}, []string{fnA}),
		allow("bad", nil, []string{fnA}),
	}}

	err := ValidateDocument(doc)
	if err == nil {
		t.Fatal("accepted")
	}
	var ve *ValidationError
	if !asValidationError(err, &ve) || ve.Index != 1 {
		t.Errorf("error = %v, want one naming statement 1", err)
	}
}

func asValidationError(err error, target **ValidationError) bool {
	v, ok := err.(*ValidationError)
	if ok {
		*target = v
	}
	return ok
}

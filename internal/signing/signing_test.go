package signing

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

var (
	testNow    = time.Date(2026, 9, 18, 19, 4, 5, 0, time.UTC)
	testCred   = Credentials{AccessKeyID: "DARIYAKEYABCDEFGHIJK", Secret: []byte("shhh-signing-secret")}
	testRegion = "hind-1"
	testSvc    = "func"
)

func testRequest() Request {
	return Request{
		Method: "POST",
		Path:   "/2026-09-18/functions/resize-image/invocations",
		Query:  url.Values{"qualifier": {"live"}},
		Body:   []byte(`{"hello":"world"}`),
	}
}

func signed(t *testing.T, req Request, now time.Time) VerifyInput {
	t.Helper()
	auth, headers := Sign(req, testCred, testRegion, testSvc, now)
	sig, err := ParseAuthorization(auth)
	if err != nil {
		t.Fatalf("ParseAuthorization(%q): %v", auth, err)
	}
	return VerifyInput{
		Request:             req,
		Signature:           sig,
		DateHeaderValue:     headers[DateHeader],
		ContentSHA256Header: headers[ContentSHA256Header],
		Secret:              testCred.Secret,
		Region:              testRegion,
		Service:             testSvc,
		Now:                 now,
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	if err := Verify(signed(t, testRequest(), testNow)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestParseAuthorization(t *testing.T) {
	auth, _ := Sign(testRequest(), testCred, testRegion, testSvc, testNow)
	sig, err := ParseAuthorization(auth)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if sig.Scope.AccessKeyID != testCred.AccessKeyID {
		t.Errorf("access key id = %q", sig.Scope.AccessKeyID)
	}
	if sig.Scope.Date != "20260918" || sig.Scope.Region != testRegion || sig.Scope.Service != testSvc {
		t.Errorf("scope = %+v", sig.Scope)
	}
	if len(sig.Signature) != 64 {
		t.Errorf("signature is %d hex chars, want 64", len(sig.Signature))
	}
}

// The failure that matters most: a modified body must not verify. This is the whole reason the
// canonical string carries a body hash.
func TestTamperedBodyFails(t *testing.T) {
	in := signed(t, testRequest(), testNow)
	in.Request.Body = []byte(`{"hello":"mars"}`)
	in.ContentSHA256Header = "" // pretend the attacker also dropped the convenience header

	err := Verify(in)
	if err == nil {
		t.Fatal("tampered body verified")
	}
	if f := err.(*Error).Failure; f != FailSignature {
		t.Errorf("failure = %s, want %s", f, FailSignature)
	}
}

// With the content hash header present, a mangled body is reported as itself rather than as a
// generic signature mismatch — that distinction is most of the debuggability of this scheme.
func TestBodyHashHeaderPinpointsAMangledBody(t *testing.T) {
	in := signed(t, testRequest(), testNow)
	in.Request.Body = []byte(`{"hello":"mars"}`)

	err := Verify(in)
	if err == nil {
		t.Fatal("mangled body verified")
	}
	if f := err.(*Error).Failure; f != FailBodyHash {
		t.Errorf("failure = %s, want %s", f, FailBodyHash)
	}
}

func TestTamperedRequestFieldsFail(t *testing.T) {
	cases := map[string]func(*VerifyInput){
		"method": func(in *VerifyInput) { in.Request.Method = "DELETE" },
		"path":   func(in *VerifyInput) { in.Request.Path = "/2026-09-18/functions/other/invocations" },
		"query":  func(in *VerifyInput) { in.Request.Query = url.Values{"qualifier": {"staging"}} },
		"added query param": func(in *VerifyInput) {
			in.Request.Query.Set("elevated", "true")
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			in := signed(t, testRequest(), testNow)
			tamper(&in)
			if err := Verify(in); err == nil {
				t.Errorf("tampered %s verified", name)
			}
		})
	}
}

// Query parameter order is not something a client controls reliably — Go's url.Values is a map.
// A signature that depended on it would fail roughly one request in a hundred.
func TestQueryOrderDoesNotMatter(t *testing.T) {
	req := testRequest()
	req.Query = url.Values{"b": {"2"}, "a": {"1"}, "c": {"3"}}
	first := CanonicalString(req, Scope{AccessKeyID: "k", Date: "20260918", Region: testRegion, Service: testSvc}, "20260918T190405Z")

	for i := 0; i < 20; i++ {
		req2 := testRequest()
		req2.Query = url.Values{"c": {"3"}, "a": {"1"}, "b": {"2"}}
		again := CanonicalString(req2, Scope{AccessKeyID: "k", Date: "20260918", Region: testRegion, Service: testSvc}, "20260918T190405Z")
		if again != first {
			t.Fatalf("canonical string depends on map order:\n%q\n%q", first, again)
		}
	}
}

// A repeated parameter must canonicalise stably regardless of the order the values arrive in.
func TestRepeatedQueryValuesAreSorted(t *testing.T) {
	a := testRequest()
	a.Query = url.Values{"tag": {"z", "a"}}
	b := testRequest()
	b.Query = url.Values{"tag": {"a", "z"}}

	scope := Scope{AccessKeyID: "k", Date: "20260918", Region: testRegion, Service: testSvc}
	if CanonicalString(a, scope, "20260918T190405Z") != CanonicalString(b, scope, "20260918T190405Z") {
		t.Error("repeated query values are order-dependent")
	}
}

// "/a b" and "/a%20b" must sign the same, or a caller gets an unexplained 403 for a path they
// consider identical.
func TestPathEncodingIsCanonical(t *testing.T) {
	scope := Scope{AccessKeyID: "k", Date: "20260918", Region: testRegion, Service: testSvc}
	space := Request{Method: "GET", Path: "/queues/my queue"}
	if got := CanonicalString(space, scope, "20260918T190405Z"); !strings.Contains(got, "my%20queue") {
		t.Errorf("space was not percent-encoded:\n%s", got)
	}
}

func TestSkewWindow(t *testing.T) {
	cases := []struct {
		name  string
		drift time.Duration
		ok    bool
	}{
		{"fresh", 0, true},
		{"just inside, late", MaxSkew - time.Second, true},
		{"just inside, early", -(MaxSkew - time.Second), true},
		{"too old", MaxSkew + time.Second, false},
		// A clock that runs fast is as much a clock problem as one that runs slow, and rejecting
		// only the past leaves that client with no useful error.
		{"too far in the future", -(MaxSkew + time.Second), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := signed(t, testRequest(), testNow)
			in.Now = testNow.Add(c.drift)

			err := Verify(in)
			if c.ok && err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if !c.ok {
				if err == nil {
					t.Fatal("accepted")
				}
				if f := err.(*Error).Failure; f != FailSkew {
					t.Errorf("failure = %s, want %s", f, FailSkew)
				}
			}
		})
	}
}

// A signature made for one service must not be replayable at another. This is what the credential
// scope is for, and it is why the scope is inside the signed string.
func TestScopeIsEnforced(t *testing.T) {
	in := signed(t, testRequest(), testNow)
	in.Service = "kyu"
	err := Verify(in)
	if err == nil {
		t.Fatal("a signature scoped to func was accepted by kyu")
	}
	if f := err.(*Error).Failure; f != FailScopeMismatch {
		t.Errorf("failure = %s, want %s", f, FailScopeMismatch)
	}

	in = signed(t, testRequest(), testNow)
	in.Region = "hind-2"
	if err := Verify(in); err == nil {
		t.Fatal("a signature scoped to hind-1 was accepted by hind-2")
	}
}

func TestWrongSecretFails(t *testing.T) {
	in := signed(t, testRequest(), testNow)
	in.Secret = []byte("not-the-secret")
	err := Verify(in)
	if err == nil {
		t.Fatal("wrong secret verified")
	}
	if f := err.(*Error).Failure; f != FailSignature {
		t.Errorf("failure = %s, want %s", f, FailSignature)
	}
}

func TestMalformedHeaders(t *testing.T) {
	cases := map[string]struct {
		header string
		want   Failure
	}{
		"empty":            {"", FailMalformedHeader},
		"wrong algorithm":  {"AWS4-HMAC-SHA256 Credential=a/b/c/d, Signature=ff", FailUnknownAlgo},
		"short credential": {Algorithm + " Credential=a/b/c, Signature=ff", FailMalformedCred},
		"no signature":     {Algorithm + " Credential=a/20260918/hind-1/func", FailMalformedHeader},
		"not key=value":    {Algorithm + " Credential", FailMalformedHeader},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseAuthorization(c.header)
			if err == nil {
				t.Fatalf("accepted %q", c.header)
			}
			if f := err.(*Error).Failure; f != c.want {
				t.Errorf("failure = %s, want %s", f, c.want)
			}
		})
	}
}

// An unknown parameter must be ignored, so a later scheme can add one without every deployed
// verifier failing closed on it.
func TestUnknownParametersAreIgnored(t *testing.T) {
	auth, _ := Sign(testRequest(), testCred, testRegion, testSvc, testNow)
	if _, err := ParseAuthorization(auth + ", Future=whatever"); err != nil {
		t.Errorf("unknown parameter rejected: %v", err)
	}
}

func TestDateHeaderChecks(t *testing.T) {
	in := signed(t, testRequest(), testNow)
	in.DateHeaderValue = ""
	if err := Verify(in); err == nil || err.(*Error).Failure != FailMissingDate {
		t.Errorf("missing date: %v", err)
	}

	in = signed(t, testRequest(), testNow)
	in.DateHeaderValue = "2026-09-18T19:04:05Z" // RFC 3339, not our format
	if err := Verify(in); err == nil || err.(*Error).Failure != FailMalformedDate {
		t.Errorf("malformed date: %v", err)
	}

	// The scope date and the header date must agree. Both are signed, so a mismatch would fail the
	// MAC regardless — reporting it specifically says which of the two is wrong.
	in = signed(t, testRequest(), testNow)
	in.Signature.Scope.Date = "20260917"
	if err := Verify(in); err == nil || err.(*Error).Failure != FailDateMismatch {
		t.Errorf("date mismatch: %v", err)
	}
}

func TestEmptyBodyHashesConsistently(t *testing.T) {
	req := Request{Method: "GET", Path: "/accounts"}
	in := signed(t, req, testNow)
	if err := Verify(in); err != nil {
		t.Fatalf("empty body did not verify: %v", err)
	}
	// sha256 of the empty string, not a sentinel: one rule instead of two.
	if got := HashBody(nil); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("empty body hash = %s", got)
	}
}

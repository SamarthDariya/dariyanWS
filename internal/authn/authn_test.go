package authn

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dariyanws/internal/apierr"
	"dariyanws/internal/control"
	"dariyanws/internal/httpx"
	"dariyanws/internal/signing"
)

const (
	testRegion  = "hind-1"
	testService = "ws"
	testKeyID   = "DARIYAKEYABCDEFGHIJKLMNO"
	testAccount = "000000000001"
)

var (
	testSecret = []byte("a-signing-secret")
	testNow    = time.Date(2026, 9, 23, 6, 45, 17, 0, time.UTC)
)

// fakeResolver stands in for the control plane, so this package's tests need no database.
type fakeResolver struct {
	key *control.SigningKey
	err error
}

func (f fakeResolver) ResolveSigningKey(context.Context, string) (*control.SigningKey, error) {
	return f.key, f.err
}

func goodResolver() fakeResolver {
	return fakeResolver{key: &control.SigningKey{
		AccessKeyID:  testKeyID,
		AccountID:    testAccount,
		PrincipalARN: "arn:dariya:iam:hind-1:" + testAccount + ":user/root",
		Secret:       testSecret,
	}}
}

func testConfig(r KeyResolver, dev bool) Config {
	return Config{
		Keys:    r,
		Region:  testRegion,
		Service: func(*http.Request) string { return testService },
		Dev:     dev,
		Now:     func() time.Time { return testNow },
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// handler records what reached it, so tests can assert both the principal and that the body
// survived being consumed for hashing.
type spyHandler struct {
	called    bool
	accountID string
	body      string
}

func (s *spyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.called = true
	if p, ok := httpx.PrincipalFrom(r.Context()); ok {
		s.accountID = p.GetAccountId()
	}
	b, _ := io.ReadAll(r.Body)
	s.body = string(b)
	w.WriteHeader(http.StatusOK)
}

func signedRequest(t *testing.T, method, target, body string, at time.Time, service string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))

	auth, headers := signing.Sign(
		signing.RequestFromHTTP(req, []byte(body)),
		signing.Credentials{AccessKeyID: testKeyID, Secret: testSecret},
		testRegion, service, at)

	req.Header.Set("Authorization", auth)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Body = io.NopCloser(strings.NewReader(body))
	return req
}

func serve(t *testing.T, cfg Config, req *http.Request) (*httptest.ResponseRecorder, *spyHandler) {
	t.Helper()
	spy := &spyHandler{}
	h := httpx.Chain(spy, httpx.WithRequestID, Middleware(cfg))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, spy
}

func TestValidSignaturePasses(t *testing.T) {
	req := signedRequest(t, "POST", "/ping?x=1", `{"hello":"world"}`, testNow, testService)
	rec, spy := serve(t, testConfig(goodResolver(), false), req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !spy.called {
		t.Fatal("handler was not reached")
	}
	if spy.accountID != testAccount {
		t.Errorf("handler saw account %q, want %q", spy.accountID, testAccount)
	}
	// The middleware consumed the body to hash it; the handler must still get every byte.
	if spy.body != `{"hello":"world"}` {
		t.Errorf("handler saw body %q", spy.body)
	}
}

func TestMissingAuthorizationIsRejected(t *testing.T) {
	req := httptest.NewRequest("GET", "/ping", nil)
	rec, spy := serve(t, testConfig(goodResolver(), false), req)

	if spy.called {
		t.Fatal("an unsigned request reached the handler")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// The rule this package exists to enforce: an unknown key id, a revoked key, a wrong secret and a
// tampered body must be indistinguishable to the caller. Anything else turns credential stuffing
// into enumeration, and an access key id is half a credential.
func TestAllAuthenticationFailuresLookIdentical(t *testing.T) {
	type failure struct {
		name string
		cfg  Config
		req  *http.Request
	}

	tampered := signedRequest(t, "POST", "/ping", `{"a":1}`, testNow, testService)
	tampered.Body = io.NopCloser(strings.NewReader(`{"a":2}`))
	tampered.Header.Del(signing.ContentSHA256Header) // an attacker would not help us

	wrongSecret := goodResolver()
	wrongSecret.key.Secret = []byte("different-secret")

	failures := []failure{
		{"unknown key id",
			testConfig(fakeResolver{err: apierr.NotFound("no access key")}, false),
			signedRequest(t, "GET", "/ping", "", testNow, testService)},
		{"revoked key",
			testConfig(fakeResolver{err: apierr.NotFound("no access key")}, false),
			signedRequest(t, "GET", "/ping", "", testNow, testService)},
		{"wrong secret",
			testConfig(wrongSecret, false),
			signedRequest(t, "GET", "/ping", "", testNow, testService)},
		{"tampered body",
			testConfig(goodResolver(), false), tampered},
		{"expired",
			testConfig(goodResolver(), false),
			signedRequest(t, "GET", "/ping", "", testNow.Add(-2*signing.MaxSkew), testService)},
		{"wrong service scope",
			testConfig(goodResolver(), false),
			signedRequest(t, "GET", "/ping", "", testNow, "func")},
	}

	var first string
	for i, f := range failures {
		rec, spy := serve(t, f.cfg, f.req)
		if spy.called {
			t.Fatalf("%s: reached the handler", f.name)
		}
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", f.name, rec.Code)
		}

		body := rec.Body.String()
		// The request id differs per request by design; strip it before comparing.
		normalised := stripRequestID(t, body)
		if i == 0 {
			first = normalised
			continue
		}
		if normalised != first {
			t.Errorf("%s produced a distinguishable response:\n got: %s\nwant: %s",
				f.name, normalised, first)
		}
	}
}

func stripRequestID(t *testing.T, body string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("response is not JSON: %s", body)
	}
	delete(m, "request_id")
	out, _ := json.Marshal(m)
	return string(out)
}

// In development the same failures must say exactly which check rejected them, or every debugging
// session starts by guessing.
func TestDevModeNamesTheFailedCheck(t *testing.T) {
	req := signedRequest(t, "GET", "/ping", "", testNow.Add(-2*signing.MaxSkew), testService)
	rec, _ := serve(t, testConfig(goodResolver(), true), req)

	var body struct {
		Details map[string]string `json:"details"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("not JSON: %s", rec.Body.String())
	}
	if got := body.Details["check"]; got != string(signing.FailSkew) {
		t.Errorf("check = %q, want %q", got, signing.FailSkew)
	}
}

func TestProductionHidesTheFailedCheck(t *testing.T) {
	req := signedRequest(t, "GET", "/ping", "", testNow.Add(-2*signing.MaxSkew), testService)
	rec, _ := serve(t, testConfig(goodResolver(), false), req)

	if strings.Contains(rec.Body.String(), string(signing.FailSkew)) {
		t.Errorf("production named the failed check: %s", rec.Body.String())
	}
}

// The signature covers the body, so the body must be buffered before the request can be
// authenticated — which means an unauthenticated caller controls the allocation.
func TestOversizedBodyIsRejected(t *testing.T) {
	big := strings.Repeat("x", MaxBodyBytes+1)
	req := signedRequest(t, "POST", "/ping", "", testNow, testService)
	req.Body = io.NopCloser(strings.NewReader(big))

	rec, spy := serve(t, testConfig(goodResolver(), false), req)
	if spy.called {
		t.Fatal("an oversized body reached the handler")
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// At M5 the service comes from the route. A signature scoped to one service must not work on
// another's path, and this is the test that will keep that true when ServiceFor becomes the router.
func TestServiceScopeComesFromTheRoute(t *testing.T) {
	cfg := testConfig(goodResolver(), false)
	cfg.Service = func(r *http.Request) string {
		if strings.HasPrefix(r.URL.Path, "/func/") {
			return "func"
		}
		return "ws"
	}

	// Signed for func, sent to a func path: fine.
	if rec, spy := serve(t, cfg, signedRequest(t, "GET", "/func/x", "", testNow, "func")); !spy.called {
		t.Errorf("a correctly scoped request was rejected: %s", rec.Body.String())
	}
	// Signed for func, sent to a control-plane path: rejected.
	if _, spy := serve(t, cfg, signedRequest(t, "GET", "/accounts", "", testNow, "func")); spy.called {
		t.Error("a func-scoped signature was accepted on a control-plane path")
	}
}

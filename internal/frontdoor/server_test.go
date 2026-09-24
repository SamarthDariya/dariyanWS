package frontdoor

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	capabilityv1 "dariyanws/gen/dariya/capability/v1"
	commonv1 "dariyanws/gen/dariya/common/v1"
	controlv1 "dariyanws/gen/dariya/control/v1"
	iamv1 "dariyanws/gen/dariya/iam/v1"
	"dariyanws/internal/authn"
	"dariyanws/internal/authz"
	"dariyanws/internal/capability"
	"dariyanws/internal/control"
	"dariyanws/internal/httpx"
	"dariyanws/internal/iam"
	"dariyanws/internal/router"
	"dariyanws/internal/secrets"
	"dariyanws/internal/servicekit"
	"dariyanws/internal/signing"
	"dariyanws/internal/store"

	"google.golang.org/protobuf/proto"
)

const testRegion = "hind-1"

// newRegion boots the whole control plane against a real Postgres and returns a live HTTP server.
//
// Deliberately an integration test: M2.1 and M2.2 already cover the pieces in isolation, so what
// is left to prove is that the assembled thing works — real credentials, real encryption, real
// signature, real socket.
func newRegion(t *testing.T) (*httptest.Server, *control.AccountsServer, *iam.Server) {
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

	accounts := control.NewAccountsServer(st, kr, testRegion, time.Now)
	policies := iam.NewServer(st, testRegion, time.Now)

	minter, _ := testTokenKeys(t)
	handler, _, err := NewHandler(accounts, policies, st, Options{
		Region: testRegion,
		Dev:    false,
		Mint:   minter,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, accounts, policies
}

// grantPing gives an account's root user the one permission /ping requires.
//
// Every test that expects a 200 has to do this now, which is the point of M3.4: nothing is
// exempt, so a route that works without a policy would be a bug rather than a convenience.
func grantPing(t *testing.T, policies *iam.Server, accountID string) {
	t.Helper()
	ctx := context.Background()

	created, err := policies.CreatePolicy(ctx, &iamv1.CreatePolicyRequest{
		AccountId: accountID,
		Name:      "ping",
		Document: &iamv1.PolicyDocument{Statements: []*iamv1.Statement{{
			Sid:       "ping",
			Effect:    iamv1.Effect_EFFECT_ALLOW,
			Actions:   []string{ActionPing},
			Resources: []string{PingResourceARN(testRegion, accountID)},
		}}},
	})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	if _, err := policies.AttachPolicy(ctx, &iamv1.AttachPolicyRequest{
		PolicyArn:    created.GetPolicy().GetPolicyArn(),
		PrincipalArn: "arn:dariya:iam:" + testRegion + ":" + accountID + ":user/root",
	}); err != nil {
		t.Fatalf("AttachPolicy: %v", err)
	}
}

// credentials mints a real account and access key, exactly as `make dev-token` does.
func credentials(t *testing.T, accounts *control.AccountsServer) (accountID string, cred signing.Credentials) {
	t.Helper()
	ctx := context.Background()

	acct, err := accounts.CreateAccount(ctx, &controlv1.CreateAccountRequest{Name: "test"})
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	accountID = acct.GetAccount().GetAccountId()

	key, err := accounts.CreateAccessKey(ctx, &controlv1.CreateAccessKeyRequest{AccountId: accountID})
	if err != nil {
		t.Fatalf("CreateAccessKey: %v", err)
	}
	return accountID, signing.Credentials{
		AccessKeyID: key.GetAccessKey().GetAccessKeyId(),
		Secret:      []byte(key.GetAccessKey().GetSecretAccessKey()),
	}
}

func signedGet(t *testing.T, base, path string, cred signing.Credentials) *http.Request {
	t.Helper()

	req, err := http.NewRequest("GET", base+path, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	auth, headers := signing.Sign(
		signing.Request{Method: "GET", Path: req.URL.Path, Query: req.URL.Query()},
		cred, testRegion, ServiceName, time.Now())

	req.Header.Set("Authorization", auth)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// The M2 proof: a real signature made with a real credential, over a real socket, comes back with
// the caller's own account id. Signing, encryption, key resolution, verification and principal
// propagation all have to work for this to pass.
func TestSignedPingRoundTrip(t *testing.T) {
	srv, accounts, policies := newRegion(t)
	accountID, cred := credentials(t, accounts)
	grantPing(t, policies, accountID)

	resp, err := http.DefaultClient.Do(signedGet(t, srv.URL, "/ping", cred))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}

	var got map[string]string
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("not JSON: %s", body)
	}
	if got["account_id"] != accountID {
		t.Errorf("account_id = %q, want %q", got["account_id"], accountID)
	}

	// Every response carries an id, in the header and in the body, and they agree.
	if h := resp.Header.Get(httpx.RequestIDHeader); h == "" || h != got["request_id"] {
		t.Errorf("request id header = %q, body = %q", h, got["request_id"])
	}
}

func TestUnsignedPingIsRejected(t *testing.T) {
	srv, _, _ := newRegion(t)

	resp, err := http.Get(srv.URL + "/ping")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if resp.Header.Get(httpx.RequestIDHeader) == "" {
		t.Error("a rejected request came back with no request id to quote")
	}
}

// A credential deleted through the control plane stops working immediately — and since M2.5 that
// is a property of the invalidation hook, not of there being no cache.
//
// The distinction matters and is the reason this comment is longer than the test. Revocation is
// immediate on the process that served the delete, because DeleteAccessKey calls Invalidate.
// Any OTHER front door would keep honouring the credential until its entry expires, which is the
// cost BREAK.md records and control.TestRevocationIsBoundedByTheTTL asserts directly. With one
// front door the two are the same thing; with two they are not, and this test would keep passing
// while the guarantee quietly weakened.
func TestDeletedCredentialStopsWorkingAtOnce(t *testing.T) {
	srv, accounts, policies := newRegion(t)
	acctID, cred := credentials(t, accounts)
	grantPing(t, policies, acctID)

	resp, err := http.DefaultClient.Do(signedGet(t, srv.URL, "/ping", cred))
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first request status = %d", resp.StatusCode)
	}

	if _, err := accounts.DeleteAccessKey(context.Background(),
		&controlv1.DeleteAccessKeyRequest{AccessKeyId: cred.AccessKeyID}); err != nil {
		t.Fatalf("DeleteAccessKey: %v", err)
	}

	resp, err = http.DefaultClient.Do(signedGet(t, srv.URL, "/ping", cred))
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a revoked credential still worked: status = %d", resp.StatusCode)
	}
}

// Two probes, two jobs. /healthz must not touch the database, or a slow query turns into an
// orchestrator restarting a process that was serving fine.
func TestProbes(t *testing.T) {
	srv, _, _ := newRegion(t)

	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status = %d", path, resp.StatusCode)
		}
	}
}

// The tampering case, end to end rather than against a fake: a signature made for one path must
// not carry a request to another.
func TestTamperedQueryIsRejected(t *testing.T) {
	srv, accounts, policies := newRegion(t)
	acctID, cred := credentials(t, accounts)
	grantPing(t, policies, acctID)

	// The query is covered by the signature just as the path is, and unlike the path it can be
	// tampered with while still landing on an authenticated route.
	req := signedGet(t, srv.URL, "/ping", cred)
	req.URL.RawQuery = "elevated=true"

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("a tampered query was accepted: status = %d, body = %s", resp.StatusCode, body)
	}
}

func TestServeDrainsOnCancel(t *testing.T) {
	st := store.OpenTest(t)
	handler, _, err := NewHandler(
		control.NewAccountsServer(st, testKeyring(t), testRegion, time.Now),
		iam.NewServer(st, testRegion, time.Now),
		st,
		Options{Region: testRegion, Log: slog.New(slog.NewTextHandler(io.Discard, nil))},
	)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, "127.0.0.1:0", handler, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned %v, want a clean drain", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Serve did not return after its context was cancelled")
	}
}

func testKeyring(t *testing.T) *secrets.Keyring {
	t.Helper()
	key, err := secrets.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	kr, err := secrets.NewKeyring(map[string][]byte{"test": key}, "test")
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return kr
}

// Benchmark helpers. Kept beside the tests because they share the region fixture, and separated
// from it because a benchmark must not truncate tables out from under a parallel test.

func openBenchStore(b *testing.B) *store.Store {
	b.Helper()
	st, err := store.Open(context.Background(), store.DefaultTestDSN)
	if err != nil {
		b.Skipf("no Postgres: %v — run `make region-up`", err)
	}
	b.Cleanup(st.Close)
	if err := st.Migrate(context.Background()); err != nil {
		b.Fatalf("migrate: %v", err)
	}
	return st
}

func benchKeyring(b *testing.B) *secrets.Keyring {
	b.Helper()
	key, err := secrets.GenerateKey()
	if err != nil {
		b.Fatalf("GenerateKey: %v", err)
	}
	kr, err := secrets.NewKeyring(map[string][]byte{"bench": key}, "bench")
	if err != nil {
		b.Fatalf("NewKeyring: %v", err)
	}
	return kr
}

func fixedPrincipal() *commonv1.Principal {
	return &commonv1.Principal{
		AccountId:    "000000000000",
		PrincipalArn: "arn:dariya:iam:hind-1:000000000000:user/root",
	}
}

// The cache has to be in the path, or E2b measures nothing. Asserted through the front door
// rather than against the resolver, because the wiring is the part that can silently be missing.
func TestKeyCacheIsInThePath(t *testing.T) {
	st := store.OpenTest(t)
	store.TruncateAll(t, st)

	accounts := control.NewAccountsServer(st, testKeyring(t), testRegion, time.Now)
	policies := iam.NewServer(st, testRegion, time.Now)

	handler, cache, err := NewHandler(accounts, policies, st, Options{
		Region: testRegion,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	if cache == nil {
		t.Fatal("no cache was built")
	}

	srv := httptest.NewServer(handler)
	defer srv.Close()

	acctID, cred := credentials(t, accounts)
	grantPing(t, policies, acctID)

	for i := 0; i < 20; i++ {
		resp, err := http.DefaultClient.Do(signedGet(t, srv.URL, "/ping", cred))
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status %d", i, resp.StatusCode)
		}
	}

	stats := cache.Stats()
	if stats.Misses != 1 {
		t.Errorf("cache missed %d times for 20 identical callers, want 1", stats.Misses)
	}
	if stats.Hits != 19 {
		t.Errorf("cache hits = %d, want 19", stats.Hits)
	}
}

// With the cache disabled the front door must go back to Postgres every time, or E2b has no
// control to compare against.
func TestKeyCacheCanBeDisabled(t *testing.T) {
	st := store.OpenTest(t)
	accounts := control.NewAccountsServer(st, testKeyring(t), testRegion, time.Now)

	_, cache, err := NewHandler(accounts, iam.NewServer(st, testRegion, time.Now), st, Options{
		Region:          testRegion,
		DisableKeyCache: true,
		Log:             slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	if cache != nil {
		t.Error("DisableKeyCache still built a cache")
	}
}

// The point of M3.4: a perfectly valid signature is no longer enough. Authentication says who,
// authorization says whether, and /ping is not exempt from the second question.
func TestAuthenticatedButUnauthorizedIsForbidden(t *testing.T) {
	srv, accounts, _ := newRegion(t)
	_, cred := credentials(t, accounts) // deliberately no grantPing

	resp, err := http.DefaultClient.Do(signedGet(t, srv.URL, "/ping", cred))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	// 403, not 401: the caller proved who they are and was refused anyway. Collapsing the two
	// would tell a legitimate user their credentials are broken when their permissions are.
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 403; body = %s", resp.StatusCode, body)
	}

	var e struct {
		Code    string            `json:"code"`
		Details map[string]string `json:"details"`
	}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &e); err != nil {
		t.Fatalf("not JSON: %s", body)
	}
	if e.Code != "AccessDenied" {
		t.Errorf("code = %q, want AccessDenied", e.Code)
	}
	// Production must not reveal which statement decided, or whether any policy exists at all.
	if len(e.Details) != 0 {
		t.Errorf("production leaked policy detail: %v", e.Details)
	}
}

// Granting a permission must take effect at once on the process that served the grant, rather
// than at the end of the policy cache's TTL.
func TestGrantTakesEffectImmediately(t *testing.T) {
	srv, accounts, policies := newRegion(t)
	acctID, cred := credentials(t, accounts)

	resp, err := http.DefaultClient.Do(signedGet(t, srv.URL, "/ping", cred))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status before the grant = %d, want 403", resp.StatusCode)
	}

	grantPing(t, policies, acctID)

	resp, err = http.DefaultClient.Do(signedGet(t, srv.URL, "/ping", cred))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status after the grant = %d, want 200; body = %s", resp.StatusCode, body)
	}
}

// And revoking must too, in the direction that matters more.
func TestRevokeTakesEffectImmediately(t *testing.T) {
	srv, accounts, policies := newRegion(t)
	acctID, cred := credentials(t, accounts)
	grantPing(t, policies, acctID)

	resp, err := http.DefaultClient.Do(signedGet(t, srv.URL, "/ping", cred))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status before the revoke = %d, want 200", resp.StatusCode)
	}

	if _, err := policies.DeletePolicy(context.Background(), &iamv1.DeletePolicyRequest{
		PolicyArn: iam.PolicyARN(testRegion, acctID, "ping"),
	}); err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}

	resp, err = http.DefaultClient.Do(signedGet(t, srv.URL, "/ping", cred))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status after the revoke = %d, want 403 — DeletePolicy must invalidate every "+
			"principal it was attached to, which it can only do by reading them before the "+
			"cascade destroys the evidence", resp.StatusCode)
	}
}

// testTokenKeys builds a matched mint/verify pair, as `dariyactl keygen` does for a real region.
func testTokenKeys(t *testing.T) (*capability.Minter, *capability.Verifier) {
	t.Helper()

	seed, pub, err := capability.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	minter, err := capability.NewMinter("test", seed, capability.DefaultTTL, time.Now)
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	return minter, capability.NewVerifier(map[string]ed25519.PublicKey{"test": pub}, time.Now)
}

// The token must reach the handler, and must NOT reach the caller. A capability in a response is
// a bearer credential handed to the party who already authenticated for the same thing — with a
// different expiry and no way to revoke it.
func TestCapabilityIsMintedAndStaysServerSide(t *testing.T) {
	st := store.OpenTest(t)
	store.TruncateAll(t, st)

	accounts := control.NewAccountsServer(st, testKeyring(t), testRegion, time.Now)
	policies := iam.NewServer(st, testRegion, time.Now)
	minter, _ := testTokenKeys(t)

	handler, _, err := NewHandler(accounts, policies, st, Options{
		Region: testRegion,
		Mint:   minter,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	// Wrap the whole chain so the capability can be observed exactly where a proxied service
	// would find it: on the inbound request, after authz.
	observed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	})
	srv := httptest.NewServer(observed)
	defer srv.Close()

	acctID, cred := credentials(t, accounts)
	grantPing(t, policies, acctID)

	resp, err := http.DefaultClient.Do(signedGet(t, srv.URL, "/ping", cred))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}

	var got map[string]string
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("not JSON: %s", body)
	}

	// The response says a capability exists and which key signed it, and carries no token.
	if got["capability_key_id"] != "test" {
		t.Errorf("capability_key_id = %q, want \"test\"", got["capability_key_id"])
	}
	if resp.Header.Get(httpx.CapabilityHeader) != "" {
		t.Error("the capability was returned to the caller in a response header")
	}
	for k, v := range got {
		if strings.Contains(strings.ToLower(k), "capability") && k != "capability_key_id" {
			t.Errorf("response leaked capability material in %q: %q", k, v)
		}
	}
}

// What a downstream service will do at M5, done here in process: read the header, verify offline,
// and find a decision it can act on.
func TestCapabilityHeaderVerifiesOffline(t *testing.T) {
	st := store.OpenTest(t)
	store.TruncateAll(t, st)

	accounts := control.NewAccountsServer(st, testKeyring(t), testRegion, time.Now)
	policies := iam.NewServer(st, testRegion, time.Now)
	minter, verifier := testTokenKeys(t)

	var header string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header = r.Header.Get(httpx.CapabilityHeader)
		w.WriteHeader(http.StatusOK)
	})

	acctID := func() string {
		resp, err := accounts.CreateAccount(context.Background(),
			&controlv1.CreateAccountRequest{Name: "t"})
		if err != nil {
			t.Fatalf("CreateAccount: %v", err)
		}
		return resp.GetAccount().GetAccountId()
	}()
	grantPing(t, policies, acctID)

	keyResp, err := accounts.CreateAccessKey(context.Background(),
		&controlv1.CreateAccessKeyRequest{AccountId: acctID})
	if err != nil {
		t.Fatalf("CreateAccessKey: %v", err)
	}
	cred := signing.Credentials{
		AccessKeyID: keyResp.GetAccessKey().GetAccessKeyId(),
		Secret:      []byte(keyResp.GetAccessKey().GetSecretAccessKey()),
	}

	authorizer := iam.NewAuthorizer(policies, iam.AuthorizerOptions{})
	chain := httpx.Chain(inner,
		httpx.WithRequestID,
		authn.Middleware(authn.Config{
			Keys:    accounts,
			Region:  testRegion,
			Service: func(*http.Request) string { return ServiceName },
			Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		}),
		authz.Middleware(authz.Config{
			Decide: authorizer,
			Mint:   minter,
			Target: func(_ *http.Request, p *commonv1.Principal) (authz.Target, error) {
				return authz.Target{
					Action:      ActionPing,
					ResourceARN: PingResourceARN(testRegion, p.GetAccountId()),
				}, nil
			},
			Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		}),
	)

	srv := httptest.NewServer(chain)
	defer srv.Close()

	resp, err := http.DefaultClient.Do(signedGet(t, srv.URL, "/ping", cred))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	if header == "" {
		t.Fatal("no capability header reached the handler")
	}
	raw, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		t.Fatalf("header is not base64: %v", err)
	}
	var token capabilityv1.SignedCapability
	if err := proto.Unmarshal(raw, &token); err != nil {
		t.Fatalf("header is not a SignedCapability: %v", err)
	}

	cap, err := verifier.Verify(&token)
	if err != nil {
		t.Fatalf("a service holding only the public key could not verify: %v", err)
	}
	if cap.GetAction() != ActionPing {
		t.Errorf("action = %q", cap.GetAction())
	}
	if cap.GetResourceArn() != PingResourceARN(testRegion, acctID) {
		t.Errorf("resource = %q", cap.GetResourceArn())
	}
	if cap.GetAccountId() != acctID {
		t.Errorf("account = %q", cap.GetAccountId())
	}
}

// M5.3's proof: a signed request crosses the front door, is authorized against policy, carries a
// capability over a real proxy hop, and is honoured by a service that verifies it offline.
//
// That is every piece of the system in one request, and it is the precondition for E1 — the data
// plane cannot outlive the control plane until it is a separate process that decides for itself.
func TestEndToEndThroughTheProxy(t *testing.T) {
	st := store.OpenTest(t)
	store.TruncateAll(t, st)

	accounts := control.NewAccountsServer(st, testKeyring(t), testRegion, time.Now)
	policies := iam.NewServer(st, testRegion, time.Now)
	minter, verifier := testTokenKeys(t)

	// A data plane, written the only way servicekit allows.
	guard := servicekit.NewGuard(verifier, "func", testRegion)
	dataPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/f/"), "/invocations")

		cap, err := guard.Authorize(r, servicekit.Intent{
			Action:       "func:Invoke",
			ResourceType: "function",
			ResourceID:   name,
		})
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(err.Error()))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"served":     name,
			"account_id": cap.GetAccountId(),
			"action":     cap.GetAction(),
		})
	}))
	defer dataPlane.Close()

	handler, _, err := NewHandler(accounts, policies, st, Options{
		Region: testRegion,
		Mint:   minter,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Routes: []router.Route{{
			Service:  "func",
			Prefix:   "/f/",
			Action:   "func:Invoke",
			Resource: router.PathResource(testRegion, "func", "function", "/f/"),
			Upstream: dataPlane.URL,
		}},
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	front := httptest.NewServer(handler)
	defer front.Close()

	acctID, cred := credentials(t, accounts)

	// A policy granting func:Invoke on one function only.
	created, err := policies.CreatePolicy(context.Background(), &iamv1.CreatePolicyRequest{
		AccountId: acctID, Name: "invoke-resize",
		Document: &iamv1.PolicyDocument{Statements: []*iamv1.Statement{{
			Sid: "invoke", Effect: iamv1.Effect_EFFECT_ALLOW,
			Actions:   []string{"func:Invoke"},
			Resources: []string{"arn:dariya:func:" + testRegion + ":" + acctID + ":function/resize"},
		}}},
	})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	if _, err := policies.AttachPolicy(context.Background(), &iamv1.AttachPolicyRequest{
		PolicyArn:    created.GetPolicy().GetPolicyArn(),
		PrincipalArn: "arn:dariya:iam:" + testRegion + ":" + acctID + ":user/root",
	}); err != nil {
		t.Fatalf("AttachPolicy: %v", err)
	}

	// Signed for the func service, because the route says so — not for ws.
	invoke := func(t *testing.T, function string) *http.Response {
		t.Helper()
		path := "/f/" + function + "/invocations"

		req, err := http.NewRequest("POST", front.URL+path, nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		auth, headers := signing.Sign(
			signing.Request{Method: "POST", Path: path},
			cred, testRegion, "func", time.Now())
		req.Header.Set("Authorization", auth)
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		return resp
	}

	t.Run("the granted function", func(t *testing.T) {
		resp := invoke(t, "resize")
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
		}

		var got map[string]string
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("not JSON: %s", body)
		}
		if got["served"] != "resize" || got["account_id"] != acctID {
			t.Errorf("the data plane served %v", got)
		}
	})

	// Refused at the front door by policy, so the data plane never sees it — which is the
	// division of labour decision 6 describes: IAM decides, the service enforces.
	t.Run("a function the policy does not grant", func(t *testing.T) {
		resp := invoke(t, "delete-everything")
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("status = %d, want 403; body = %s", resp.StatusCode, body)
		}
	})

	// The route decides the signature's scope. A ws-scoped signature on a func route is refused
	// by authn, before policy is consulted at all.
	t.Run("signature scoped to the wrong service", func(t *testing.T) {
		path := "/f/resize/invocations"
		req, _ := http.NewRequest("POST", front.URL+path, nil)
		auth, headers := signing.Sign(
			signing.Request{Method: "POST", Path: path},
			cred, testRegion, ServiceName, time.Now()) // "ws", not "func"
		req.Header.Set("Authorization", auth)
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
	})
}

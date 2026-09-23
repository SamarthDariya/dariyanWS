package frontdoor

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	controlv1 "dariyanws/gen/dariya/control/v1"
	"dariyanws/internal/control"
	"dariyanws/internal/httpx"
	"dariyanws/internal/secrets"
	"dariyanws/internal/signing"
	"dariyanws/internal/store"
)

const testRegion = "hind-1"

// newRegion boots the whole control plane against a real Postgres and returns a live HTTP server.
//
// Deliberately an integration test: M2.1 and M2.2 already cover the pieces in isolation, so what
// is left to prove is that the assembled thing works — real credentials, real encryption, real
// signature, real socket.
func newRegion(t *testing.T) (*httptest.Server, *control.AccountsServer) {
	t.Helper()

	st := store.OpenTest(t)
	if _, err := st.Pool().Exec(context.Background(),
		`TRUNCATE access_keys, accounts, idempotency`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	key, err := secrets.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	kr, err := secrets.NewKeyring(map[string][]byte{"test": key}, "test")
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}

	accounts := control.NewAccountsServer(st, kr, testRegion, time.Now)
	handler := NewHandler(accounts, st, Options{
		Region: testRegion,
		Dev:    false,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, accounts
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
	srv, accounts := newRegion(t)
	accountID, cred := credentials(t, accounts)

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
	srv, _ := newRegion(t)

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

// A credential deleted through the control plane must stop working immediately, with no cache and
// no state column standing between the delete and the signing path.
func TestDeletedCredentialStopsWorkingAtOnce(t *testing.T) {
	srv, accounts := newRegion(t)
	_, cred := credentials(t, accounts)

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
	srv, _ := newRegion(t)

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
	srv, accounts := newRegion(t)
	_, cred := credentials(t, accounts)

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
	handler := NewHandler(
		control.NewAccountsServer(st, testKeyring(t), testRegion, time.Now),
		st,
		Options{Region: testRegion, Log: slog.New(slog.NewTextHandler(io.Discard, nil))},
	)

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

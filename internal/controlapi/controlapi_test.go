package controlapi_test

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

	controlv1 "dariyanws/gen/dariya/control/v1"
	"dariyanws/internal/capability"
	"dariyanws/internal/control"
	"dariyanws/internal/frontdoor"
	"dariyanws/internal/iam"
	"dariyanws/internal/secrets"
	"dariyanws/internal/signing"
	"dariyanws/internal/store"

	iamv1 "dariyanws/gen/dariya/iam/v1"
)

// Tested through the front door rather than against the handlers directly, because almost
// everything interesting about these routes is the chain around them: the signature scope, the
// policy check, and the fact that the account comes from the principal. A handler test with a
// hand-made request would assert the handler's behaviour and miss all three.

const region = "hind-1"

type region_ struct {
	server   *httptest.Server
	accounts *control.AccountsServer
	policies *iam.Server
}

func newRegion(t *testing.T) *region_ {
	t.Helper()

	st := store.OpenTest(t)
	store.TruncateAll(t, st)

	masterKey, err := secrets.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	kr, err := secrets.NewKeyring(map[string][]byte{"test": masterKey}, "test")
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}

	seed, pub, err := capability.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	minter, err := capability.NewMinter("test", seed, capability.DefaultTTL, time.Now)
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	_ = pub

	accounts := control.NewAccountsServer(st, kr, region, time.Now)
	policies := iam.NewServer(st, region, time.Now)

	handler, _, err := frontdoor.NewHandler(accounts, policies, st, frontdoor.Options{
		Region: region,
		Mint:   minter,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &region_{server: srv, accounts: accounts, policies: policies}
}

// admin mints an account whose root user may do anything inside it, as `dariyactl bootstrap`
// does — which is the only way a console user could reach these routes at all.
func (rg *region_) admin(t *testing.T) (string, signing.Credentials) {
	t.Helper()
	ctx := context.Background()

	acct, err := rg.accounts.CreateAccount(ctx, &controlv1.CreateAccountRequest{Name: "t"})
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	id := acct.GetAccount().GetAccountId()

	created, err := rg.policies.CreatePolicy(ctx, &iamv1.CreatePolicyRequest{
		AccountId: id, Name: "admin",
		Document: &iamv1.PolicyDocument{Statements: []*iamv1.Statement{{
			Sid: "all", Effect: iamv1.Effect_EFFECT_ALLOW,
			Actions: []string{"*"}, Resources: []string{"*"},
		}}},
	})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	if _, err := rg.policies.AttachPolicy(ctx, &iamv1.AttachPolicyRequest{
		PolicyArn:    created.GetPolicy().GetPolicyArn(),
		PrincipalArn: "arn:dariya:iam:" + region + ":" + id + ":user/root",
	}); err != nil {
		t.Fatalf("AttachPolicy: %v", err)
	}

	key, err := rg.accounts.CreateAccessKey(ctx, &controlv1.CreateAccessKeyRequest{AccountId: id})
	if err != nil {
		t.Fatalf("CreateAccessKey: %v", err)
	}
	return id, signing.Credentials{
		AccessKeyID: key.GetAccessKey().GetAccessKeyId(),
		Secret:      []byte(key.GetAccessKey().GetSecretAccessKey()),
	}
}

// call signs and sends a request, the way a console's generated client will.
func (rg *region_) call(t *testing.T, cred signing.Credentials, method, path, body string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(method, rg.server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	u := req.URL
	auth, headers := signing.Sign(
		signing.Request{Method: method, Path: u.Path, Query: u.Query(), Body: []byte(body)},
		cred, region, "iam", time.Now())

	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Body = io.NopCloser(strings.NewReader(body))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return resp
}

func decode(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("response is not JSON (%d): %s", resp.StatusCode, body)
	}
	return out
}

func TestGetAccount(t *testing.T) {
	rg := newRegion(t)
	id, cred := rg.admin(t)

	resp := rg.call(t, cred, "GET", "/2026-09-01/account", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	if got := decode(t, resp)["accountId"]; got != id {
		t.Errorf("accountId = %v, want %s", got, id)
	}
}

func TestAccessKeyLifecycle(t *testing.T) {
	rg := newRegion(t)
	_, cred := rg.admin(t)

	create := rg.call(t, cred, "POST", "/2026-09-01/access-keys", `{}`)
	defer create.Body.Close()
	if create.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(create.Body)
		t.Fatalf("create status = %d, body = %s", create.StatusCode, body)
	}

	created := decode(t, create)
	keyID, _ := created["accessKeyId"].(string)
	if keyID == "" {
		t.Fatalf("no access key id in %v", created)
	}
	if secret, _ := created["secretAccessKey"].(string); secret == "" {
		t.Error("create did not return a secret, which is the only time it ever can")
	}

	list := rg.call(t, cred, "GET", "/2026-09-01/access-keys", "")
	defer list.Body.Close()
	body, _ := io.ReadAll(list.Body)
	if strings.Contains(string(body), "\"secretAccessKey\":\"D") ||
		strings.Contains(string(body), "secretAccessKey\": \"D") {
		t.Errorf("a list leaked a secret: %s", body)
	}

	del := rg.call(t, cred, "DELETE", "/2026-09-01/access-keys/"+keyID, "")
	defer del.Body.Close()
	if del.StatusCode != http.StatusNoContent {
		t.Errorf("delete status = %d, want 204", del.StatusCode)
	}
}

func TestPolicyLifecycle(t *testing.T) {
	rg := newRegion(t)
	id, cred := rg.admin(t)

	doc := `{"document":{"statements":[{"sid":"s","effect":"EFFECT_ALLOW",` +
		`"actions":["func:Invoke"],"resources":["arn:dariya:func:hind-1:` + id + `:function/*"]}]}}`

	create := rg.call(t, cred, "PUT", "/2026-09-01/policies/invoke-all", doc)
	defer create.Body.Close()
	if create.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(create.Body)
		t.Fatalf("create status = %d, body = %s", create.StatusCode, body)
	}
	if got := decode(t, create)["name"]; got != "invoke-all" {
		t.Errorf("name = %v", got)
	}

	get := rg.call(t, cred, "GET", "/2026-09-01/policies/invoke-all", "")
	defer get.Body.Close()
	if get.StatusCode != http.StatusOK {
		t.Fatalf("get status = %d", get.StatusCode)
	}

	attach := rg.call(t, cred, "POST", "/2026-09-01/policies/invoke-all/attachments",
		`{"principalArn":"arn:dariya:iam:hind-1:`+id+`:user/root"}`)
	defer attach.Body.Close()
	if attach.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(attach.Body)
		t.Fatalf("attach status = %d, body = %s", attach.StatusCode, body)
	}

	detach := rg.call(t, cred, "POST", "/2026-09-01/policies/invoke-all/detachments",
		`{"principalArn":"arn:dariya:iam:hind-1:`+id+`:user/root"}`)
	defer detach.Body.Close()
	if detach.StatusCode != http.StatusNoContent {
		t.Errorf("detach status = %d, want 204", detach.StatusCode)
	}

	list := rg.call(t, cred, "GET", "/2026-09-01/policies", "")
	defer list.Body.Close()
	if list.StatusCode != http.StatusOK {
		t.Errorf("list status = %d", list.StatusCode)
	}

	del := rg.call(t, cred, "DELETE", "/2026-09-01/policies/invoke-all", "")
	defer del.Body.Close()
	if del.StatusCode != http.StatusNoContent {
		t.Errorf("delete status = %d, want 204", del.StatusCode)
	}
}

// The property the whole package is arranged around: a caller acts on their own account, and
// there is no field they can send that changes which one.
func TestAccountIdInTheBodyIsIgnored(t *testing.T) {
	rg := newRegion(t)
	mine, cred := rg.admin(t)
	theirs, _ := rg.admin(t)

	resp := rg.call(t, cred, "POST", "/2026-09-01/access-keys",
		`{"accountId":"`+theirs+`"}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	if got := decode(t, resp)["accountId"]; got != mine {
		t.Errorf("a key was minted for account %v; the caller is %s", got, mine)
	}
}

// Every route is authorized, so a caller with credentials but no policy gets nothing.
func TestNoPolicyMeansNoAccess(t *testing.T) {
	rg := newRegion(t)
	ctx := context.Background()

	acct, err := rg.accounts.CreateAccount(ctx, &controlv1.CreateAccountRequest{Name: "bare"})
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	key, err := rg.accounts.CreateAccessKey(ctx, &controlv1.CreateAccessKeyRequest{
		AccountId: acct.GetAccount().GetAccountId(),
	})
	if err != nil {
		t.Fatalf("CreateAccessKey: %v", err)
	}
	cred := signing.Credentials{
		AccessKeyID: key.GetAccessKey().GetAccessKeyId(),
		Secret:      []byte(key.GetAccessKey().GetSecretAccessKey()),
	}

	for _, path := range []string{"/2026-09-01/account", "/2026-09-01/access-keys", "/2026-09-01/policies"} {
		resp := rg.call(t, cred, "GET", path, "")
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 403", path, resp.StatusCode)
		}
	}
}

// There is no route that names an account, and the absence is the safeguard: creating a tenant
// is not something a tenant does, and listing them is an operator view across the whole cloud.
//
// Both come back 401 rather than 404, which is deliberate and worth stating. An unmatched path
// is treated by authn as belonging to the control plane, so a signature scoped to iam does not
// satisfy it — meaning "this route does not exist" and "your signature is for something else"
// are the same answer. That is the price of refusing to let an unauthenticated caller map the
// API by watching 404s, and it is the right side to err on.
func TestNoRouteCreatesOrListsAccounts(t *testing.T) {
	rg := newRegion(t)
	_, cred := rg.admin(t)

	for _, c := range []struct{ method, path string }{
		{"POST", "/2026-09-01/accounts"},
		{"GET", "/2026-09-01/accounts"},
		{"GET", "/2026-09-01/accounts/000000000002"},
	} {
		resp := rg.call(t, cred, c.method, c.path, `{"name":"x"}`)
		resp.Body.Close()
		if resp.StatusCode/100 == 2 {
			t.Errorf("%s %s succeeded with status %d", c.method, c.path, resp.StatusCode)
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s: status = %d, want 401 (unmatched paths demand a control-plane "+
				"signature)", c.method, c.path, resp.StatusCode)
		}
	}
}

// These routes belong to the iam service, so a signature scoped to something else does not reach
// them — the route table decides the scope, not the handler.
func TestSignatureMustBeScopedToIam(t *testing.T) {
	rg := newRegion(t)
	_, cred := rg.admin(t)

	path := "/2026-09-01/account"
	req, _ := http.NewRequest("GET", rg.server.URL+path, nil)
	auth, headers := signing.Sign(
		signing.Request{Method: "GET", Path: path},
		cred, region, "func", time.Now()) // wrong service
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
}

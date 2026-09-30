package nache

import (
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

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	nachev1 "dariyanws/gen/dariya/nache/v1"
	"dariyanws/internal/capability"
	"dariyanws/internal/httpx"
	"dariyanws/internal/nache/store"
	"dariyanws/internal/servicekit"
)

const (
	acctA = "000000000001"
	acctB = "000000000002"
)

type apiHarness struct {
	t      *testing.T
	srv    *httptest.Server
	minter *capability.Minter
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func testGuard(t *testing.T) (*capability.Minter, *servicekit.Guard) {
	t.Helper()
	seed, pub, err := capability.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	m, err := capability.NewMinter("k1", seed, capability.DefaultTTL, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	v := capability.NewVerifier(map[string]ed25519.PublicKey{"k1": pub}, time.Now)
	return m, servicekit.NewGuard(v, Service, "hind-1")
}

func newAPIHarness(t *testing.T, maxClusters int) (*apiHarness, *store.Store) {
	t.Helper()
	st := store.OpenTest(t, "api")
	m, g := testGuard(t)
	api := NewAPI(st, g, APIConfig{Region: "hind-1", MaxClustersPerAccount: maxClusters, Log: discardLog()})
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return &apiHarness{t: t, srv: srv, minter: m}, st
}

func clusterARN(account, name string) string {
	return "arn:dariya:nache:hind-1:" + account + ":cluster/" + name
}

func (h *apiHarness) call(method, path, account, action, resource, body string) (int, []byte) {
	h.t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, h.srv.URL+Prefix+path, reader)
	token, err := h.minter.Mint(capability.Claims{AccountID: account,
		PrincipalARN: "arn:dariya:iam:hind-1:" + account + ":user/root",
		Action:       action, ResourceARN: resource, RequestID: "r"})
	if err != nil {
		h.t.Fatal(err)
	}
	raw, _ := proto.Marshal(token)
	req.Header.Set(httpx.CapabilityHeader, base64.StdEncoding.EncodeToString(raw))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (h *apiHarness) create(account, name string) (int, *nachev1.CacheCluster, []byte) {
	status, raw := h.call("PUT", "/clusters/"+name, account, "nache:CreateCacheCluster", clusterARN(account, name), "")
	var resp nachev1.CreateCacheClusterResponse
	_ = protojson.Unmarshal(raw, &resp)
	return status, resp.GetCluster(), raw
}

func code(raw []byte) string {
	var e struct{ Code string }
	_ = json.Unmarshal(raw, &e)
	return e.Code
}

func TestCreateIsAcceptedNotDone(t *testing.T) {
	h, _ := newAPIHarness(t, 5)

	status, c, raw := h.create(acctA, "sessions")
	if status != http.StatusAccepted {
		t.Fatalf("Create = %d: %s", status, raw)
	}
	if c.GetState().String() != "RESOURCE_STATE_CREATING" {
		t.Fatalf("state = %v", c.GetState())
	}
	// The endpoint exists from the start: it is derived from the name, not from a node.
	if c.GetEndpoint() != "sessions."+acctA+".nache.dariya.internal:6379" {
		t.Fatalf("endpoint = %q", c.GetEndpoint())
	}
	if c.GetArn() != clusterARN(acctA, "sessions") || len(c.GetNodes()) != 0 {
		t.Fatalf("cluster = %v", c)
	}

	if status, _, raw := h.create(acctA, "sessions"); status != http.StatusOK {
		t.Fatalf("repeat Create = %d: %s", status, raw)
	}
}

func TestAccountsAreSeparate(t *testing.T) {
	h, _ := newAPIHarness(t, 5)
	h.create(acctA, "c1")

	status, _ := h.call("GET", "/clusters/c1", acctB, "nache:DescribeCacheCluster", clusterARN(acctB, "c1"), "")
	if status != http.StatusNotFound {
		t.Fatalf("B describing A's name = %d, want 404", status)
	}
	status, _ = h.call("GET", "/clusters/c1", acctB, "nache:DescribeCacheCluster", clusterARN(acctA, "c1"), "")
	if status != http.StatusForbidden {
		t.Fatalf("B holding a capability for A's cluster = %d, want 403", status)
	}
	status, raw := h.call("GET", "/clusters", acctB, "nache:ListCacheClusters",
		"arn:dariya:nache:hind-1:"+acctB+":account/"+acctB, "")
	var list nachev1.ListCacheClustersResponse
	_ = protojson.Unmarshal(raw, &list)
	if status != http.StatusOK || len(list.GetClusters()) != 0 {
		t.Fatalf("B's list = %d: %s", status, raw)
	}
}

func TestDeleteIsAcceptedAndHoldsTheName(t *testing.T) {
	h, _ := newAPIHarness(t, 5)
	h.create(acctA, "c1")

	status, raw := h.call("DELETE", "/clusters/c1", acctA, "nache:DeleteCacheCluster", clusterARN(acctA, "c1"), "")
	if status != http.StatusAccepted || !strings.Contains(string(raw), "RESOURCE_STATE_DELETING") {
		t.Fatalf("Delete = %d: %s", status, raw)
	}
	status, _, raw = h.create(acctA, "c1")
	if status != http.StatusConflict {
		t.Fatalf("Create while deleting = %d: %s", status, raw)
	}
	status, _ = h.call("DELETE", "/clusters/nope", acctA, "nache:DeleteCacheCluster", clusterARN(acctA, "nope"), "")
	if status != http.StatusNotFound {
		t.Fatalf("Delete missing = %d", status)
	}
}

func TestQuotaAndValidation(t *testing.T) {
	h, _ := newAPIHarness(t, 1)
	h.create(acctA, "one")

	if status, _, raw := h.create(acctA, "two"); status != http.StatusBadRequest || code(raw) != "LimitExceeded" {
		t.Fatalf("over quota = %d: %s", status, raw)
	}
	if status, _, _ := h.create(acctA, "one"); status != http.StatusOK {
		t.Fatalf("repeat at the limit = %d", status)
	}
	if status, _, _ := h.create(acctA, strings.Repeat("a", 41)); status != http.StatusBadRequest {
		t.Fatalf("a 41-character name was accepted")
	}
	status, raw := h.call("PUT", "/clusters/x", acctA, "nache:CreateCacheCluster", clusterARN(acctA, "x"),
		`{"nodeType":"huge"}`)
	if status != http.StatusBadRequest {
		t.Fatalf("an unknown setting = %d: %s", status, raw)
	}
}

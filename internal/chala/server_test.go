package chala

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	chalav1 "dariyanws/gen/dariya/chala/v1"
	"dariyanws/internal/capability"
	"dariyanws/internal/chala/docker"
	"dariyanws/internal/httpx"
	"dariyanws/internal/servicekit"
)

// Against the real daemon, skipping without one. What is under test is mostly what chala asks
// Docker for and what Docker then does, and a fake would only agree with the author.

const region = "hind-1"

type harness struct {
	t      *testing.T
	srv    *httptest.Server
	minter *capability.Minter
	docker *docker.Client
}

// testAccount returns a fresh twelve-digit account, so parallel runs and leftovers from a crashed
// run cannot see each other's instances.
func testAccount(t *testing.T) string {
	n, err := rand.Int(rand.Reader, big.NewInt(1e11))
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("9%011d", n.Int64())
}

func newHarness(t *testing.T, maxInstances int, accounts ...string) *harness {
	t.Helper()
	return newHarnessWith(t, Config{MaxInstancesPerAccount: maxInstances}, accounts...)
}

func newHarnessWith(t *testing.T, cfg Config, accounts ...string) *harness {
	t.Helper()
	d := docker.New(docker.DefaultSocket())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := d.Ping(ctx); err != nil {
		t.Skipf("no Docker daemon (%v) — `open -a Docker` to run these", err)
	}

	seed, pub, err := capability.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	minter, err := capability.NewMinter("k1", seed, capability.DefaultTTL, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	verifier := capability.NewVerifier(map[string]ed25519.PublicKey{"k1": pub}, time.Now)

	cfg.Region, cfg.Log = region, discardLog()
	if cfg.Catalog == nil {
		cfg.Catalog = DefaultCatalog()
	}
	s, err := New(d, servicekit.NewGuard(verifier, Service, region), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PrepareImages(ctx, discardLog()); err != nil {
		t.Fatalf("PrepareImages: %v", err)
	}

	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		// Every container before any network: an attached instance sits on another account's
		// network, which cannot be removed while it is there.
		for _, acct := range accounts {
			ids, _ := d.ListContainers(ctx, []string{labelAccount + "=" + acct})
			for _, id := range ids {
				_ = d.RemoveContainer(ctx, id)
			}
		}
		for _, acct := range accounts {
			_ = d.RemoveNetwork(ctx, NetworkName(acct))
		}
	})
	return &harness{t: t, srv: srv, minter: minter, docker: d}
}

// call sends one request carrying a capability for (action, resource), as the front door would.
func (h *harness) call(method, path, account, action, resource string, body any) (int, []byte) {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, h.srv.URL+Prefix+path, reader)
	if err != nil {
		h.t.Fatal(err)
	}
	if action != "" {
		token, err := h.minter.Mint(capability.Claims{
			AccountID: account, PrincipalARN: "arn:dariya:iam:hind-1:" + account + ":user/root",
			Action: action, ResourceARN: resource, RequestID: "req",
		})
		if err != nil {
			h.t.Fatal(err)
		}
		raw, _ := proto.Marshal(token)
		req.Header.Set(httpx.CapabilityHeader, base64.StdEncoding.EncodeToString(raw))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (h *harness) run(account, name string, body map[string]any) (int, *chalav1.Instance, []byte) {
	h.t.Helper()
	status, raw := h.call("PUT", "/instances/"+name, account, "chala:RunInstance",
		ARN(region, account, name), body)
	if status != http.StatusOK {
		return status, nil, raw
	}
	var resp chalav1.RunInstanceResponse
	if err := protojson.Unmarshal(raw, &resp); err != nil {
		h.t.Fatalf("decoding RunInstance: %v: %s", err, raw)
	}
	return status, resp.GetInstance(), raw
}

func (h *harness) list(account, query string) []*chalav1.Instance {
	h.t.Helper()
	status, raw := h.call("GET", "/instances"+query, account, "chala:DescribeInstances",
		"arn:dariya:chala:hind-1:"+account+":account/"+account, nil)
	if status != http.StatusOK {
		h.t.Fatalf("DescribeInstances = %d: %s", status, raw)
	}
	var resp chalav1.DescribeInstancesResponse
	if err := protojson.Unmarshal(raw, &resp); err != nil {
		h.t.Fatalf("decoding DescribeInstances: %v", err)
	}
	return resp.GetInstances()
}

func errorCode(raw []byte) string {
	var e struct{ Code string }
	_ = json.Unmarshal(raw, &e)
	return e.Code
}

var shell = map[string]any{"imageId": "img-shell", "tags": map[string]string{"role": "client"}}

func TestInstanceLifecycle(t *testing.T) {
	acct := testAccount(t)
	h := newHarness(t, 5, acct)

	status, inst, raw := h.run(acct, "web-1", shell)
	if status != http.StatusOK {
		t.Fatalf("RunInstance = %d: %s", status, raw)
	}
	if inst.GetState() != chalav1.InstanceState_INSTANCE_STATE_RUNNING {
		t.Fatalf("state = %v", inst.GetState())
	}
	if inst.GetArn() != ARN(region, acct, "web-1") || inst.GetAccountId() != acct {
		t.Fatalf("identity = %s / %s", inst.GetArn(), inst.GetAccountId())
	}
	if inst.GetPrivateDnsName() != "web-1."+acct+".chala.dariya.internal" || inst.GetPrivateIp() == "" {
		t.Fatalf("addressing = %q / %q", inst.GetPrivateDnsName(), inst.GetPrivateIp())
	}
	if inst.GetTags()["role"] != "client" {
		t.Fatalf("tags = %v", inst.GetTags())
	}

	// The same PUT again is the same instance, not a second one.
	status, again, raw := h.run(acct, "web-1", shell)
	if status != http.StatusOK || again.GetPrivateIp() != inst.GetPrivateIp() {
		t.Fatalf("retry = %d %v: %s", status, again, raw)
	}

	// The same name asking for something else is refused rather than silently answered.
	status, _, raw = h.run(acct, "web-1", map[string]any{"imageId": "img-shell"})
	if status != http.StatusBadRequest || errorCode(raw) != "IdempotentParameterMismatch" {
		t.Fatalf("a different request under the same name = %d: %s", status, raw)
	}

	if status, _, raw := h.run(acct, "db-1", map[string]any{"imageId": "img-shell",
		"tags": map[string]string{"role": "server"}}); status != http.StatusOK {
		t.Fatalf("second instance = %d: %s", status, raw)
	}

	if got := h.list(acct, ""); len(got) != 2 {
		t.Fatalf("list = %d instances, want 2", len(got))
	}
	byTag := h.list(acct, "?tag.role=server")
	if len(byTag) != 1 || byTag[0].GetName() != "db-1" {
		t.Fatalf("list by tag = %v", byTag)
	}

	status, raw = h.call("DELETE", "/instances/web-1", acct, "chala:TerminateInstance",
		ARN(region, acct, "web-1"), nil)
	if status != http.StatusOK {
		t.Fatalf("TerminateInstance = %d: %s", status, raw)
	}
	status, _ = h.call("GET", "/instances/web-1", acct, "chala:DescribeInstance",
		ARN(region, acct, "web-1"), nil)
	if status != http.StatusNotFound {
		t.Fatalf("describe after terminate = %d, want 404", status)
	}
	status, _ = h.call("DELETE", "/instances/web-1", acct, "chala:TerminateInstance",
		ARN(region, acct, "web-1"), nil)
	if status != http.StatusNotFound {
		t.Fatalf("second terminate = %d, want 404", status)
	}
}

// Two accounts, one name. Each gets its own instance; neither can see the other's, by name or in
// a listing, and neither's capability reaches the other's resources.
func TestAccountsCannotSeeEachOther(t *testing.T) {
	a, b := testAccount(t), testAccount(t)
	h := newHarness(t, 5, a, b)

	_, instA, raw := h.run(a, "web", shell)
	if instA == nil {
		t.Fatalf("a: %s", raw)
	}
	_, instB, raw := h.run(b, "web", shell)
	if instB == nil {
		t.Fatalf("b: %s", raw)
	}
	if instA.GetPrivateDnsName() == instB.GetPrivateDnsName() {
		t.Fatalf("both accounts got the DNS name %s", instA.GetPrivateDnsName())
	}

	if got := h.list(b, ""); len(got) != 1 || got[0].GetAccountId() != b {
		t.Fatalf("b's listing = %v", got)
	}

	// b holding a perfectly valid capability for a's instance ARN. The front door refuses
	// cross-account before minting one; this is what chala does if it ever mints one anyway.
	status, _ := h.call("GET", "/instances/web", b, "chala:DescribeInstance", ARN(region, a, "web"), nil)
	if status != http.StatusForbidden {
		t.Fatalf("b describing with a's ARN = %d, want 403", status)
	}
}

// E4, again, for the second service: a capability for one instance must not act on another.
func TestCapabilityForOneInstanceDoesNotReachAnother(t *testing.T) {
	acct := testAccount(t)
	h := newHarness(t, 5, acct)

	status, raw := h.call("PUT", "/instances/b", acct, "chala:RunInstance", ARN(region, acct, "a"), shell)
	if status != http.StatusForbidden {
		t.Fatalf("a token for instance/a ran instance/b: %d %s", status, raw)
	}
	status, _ = h.call("PUT", "/instances/a", acct, "chala:TerminateInstance", ARN(region, acct, "a"), shell)
	if status != http.StatusForbidden {
		t.Fatalf("a Terminate token ran an instance: %d", status)
	}
	status, _ = h.call("PUT", "/instances/a", acct, "", "", shell)
	if status != http.StatusForbidden {
		t.Fatalf("no capability at all: %d", status)
	}
}

func TestValidation(t *testing.T) {
	acct := testAccount(t)
	h := newHarness(t, 5, acct)

	for name, c := range map[string]struct {
		name string
		body map[string]any
	}{
		"uppercase name":   {"Web", shell},
		"leading hyphen":   {"-web", shell},
		"unknown image":    {"web", map[string]any{"imageId": "img-anything-i-like"}},
		"registry ref":     {"web", map[string]any{"imageId": "alpine:latest"}},
		"bad tag key":      {"web", map[string]any{"imageId": "img-shell", "tags": map[string]string{"a b": "c"}}},
		"unknown field":    {"web", map[string]any{"imageId": "img-shell", "privileged": true}},
		"accountId smuggl": {"web", map[string]any{"imageId": "img-shell", "accountId": "000000000001"}},
	} {
		t.Run(name, func(t *testing.T) {
			status, _, raw := h.run(acct, c.name, c.body)
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", status, raw)
			}
		})
	}
}

func TestQuota(t *testing.T) {
	acct := testAccount(t)
	h := newHarness(t, 2, acct)

	for _, n := range []string{"one", "two"} {
		if status, _, raw := h.run(acct, n, shell); status != http.StatusOK {
			t.Fatalf("%s = %d: %s", n, status, raw)
		}
	}
	status, _, raw := h.run(acct, "three", shell)
	if status != http.StatusBadRequest || errorCode(raw) != "LimitExceeded" {
		t.Fatalf("third instance = %d: %s", status, raw)
	}
	// A retry of an existing instance at the limit is still answered.
	if status, _, raw := h.run(acct, "two", shell); status != http.StatusOK {
		t.Fatalf("retry at the limit = %d: %s", status, raw)
	}
}

// A RunInstance that created its container and died before starting it leaves a PENDING instance.
// The retry is what finishes it — the property the reconciler (decision 13g) will lean on.
func TestRetryStartsAPendingInstance(t *testing.T) {
	acct := testAccount(t)
	h := newHarness(t, 5, acct)
	ctx := context.Background()

	if err := h.docker.EnsureNetwork(ctx, docker.NetworkSpec{Name: NetworkName(acct), Internal: true,
		Labels: map[string]string{labelKind: kindNetwork, labelAccount: acct}}); err != nil {
		t.Fatal(err)
	}
	img := mustImage(t, "img-shell")
	if _, err := h.docker.CreateContainer(ctx, containerName(acct, "half"), docker.ContainerSpec{
		Image: img.Ref, Cmd: img.Cmd, Network: NetworkName(acct),
		Labels: instanceLabels(acct, "half", img.ID, map[string]string{"role": "client"}),
	}); err != nil {
		t.Fatal(err)
	}

	status, raw := h.call("GET", "/instances/half", acct, "chala:DescribeInstance", ARN(region, acct, "half"), nil)
	if status != http.StatusOK || !strings.Contains(string(raw), "INSTANCE_STATE_PENDING") {
		t.Fatalf("the half-created instance = %d: %s", status, raw)
	}

	status, inst, raw := h.run(acct, "half", shell)
	if status != http.StatusOK || inst.GetState() != chalav1.InstanceState_INSTANCE_STATE_RUNNING {
		t.Fatalf("retry = %d: %s", status, raw)
	}
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func mustImage(t *testing.T, id string) Image {
	t.Helper()
	for _, img := range DefaultCatalog() {
		if img.ID == id {
			return img
		}
	}
	t.Fatalf("no %s in the default catalog", id)
	return Image{}
}

package router

import (
	"net/http/httptest"
	"strings"
	"testing"

	commonv1 "dariyanws/gen/dariya/common/v1"
	"dariyanws/internal/apierr"
)

const (
	region  = "hind-1"
	account = "000000000001"
	other   = "000000000002"
)

func principal(accountID string) *commonv1.Principal {
	return &commonv1.Principal{
		AccountId:    accountID,
		PrincipalArn: "arn:dariya:iam:hind-1:" + accountID + ":user/root",
	}
}

func testTable(t *testing.T) *Table {
	t.Helper()
	table, err := NewTable(region, []Route{
		{
			Service: "ws", Prefix: "/ping", Action: "ws:Ping",
			Resource: AccountResource(region, "ws", "endpoint", "ping"),
		},
		{
			Service: "func", Prefix: "/2026-09-18/functions/", Action: "func:Invoke",
			Resource: PathResource(region, "func", "function", "/2026-09-18/functions/"),
			Upstream: "http://127.0.0.1:8081",
		},
		{
			Service: "kyu", Prefix: "/queues/", Action: "kyu:SendMessage",
			Resource: PathResource(region, "kyu", "queue", "/queues/"),
			Upstream: "http://127.0.0.1:8082",
		},
	})
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}
	return table
}

// The rule the package exists for: a route with no action cannot be registered, so there is no
// way to ship an authenticated-but-unauthorized corner.
func TestRouteWithoutAnActionIsRejected(t *testing.T) {
	_, err := NewTable(region, []Route{{
		Service: "func", Prefix: "/x",
		Resource: AccountResource(region, "func", "function", "x"),
	}})
	if err == nil {
		t.Fatal("a route with no action was accepted")
	}
	if !strings.Contains(err.Error(), "action") {
		t.Errorf("error does not name the problem: %v", err)
	}
}

func TestRouteWithoutAResourceIsRejected(t *testing.T) {
	_, err := NewTable(region, []Route{{Service: "func", Prefix: "/x", Action: "func:Invoke"}})
	if err == nil {
		t.Fatal("a route with no resource was accepted")
	}
}

func TestServiceForFollowsTheRoute(t *testing.T) {
	table := testTable(t)
	serviceFor := table.ServiceFor("ws")

	cases := map[string]string{
		"/ping":                               "ws",
		"/2026-09-18/functions/resize/invoke": "func",
		"/queues/orders/messages":             "kyu",
	}
	for path, want := range cases {
		if got := serviceFor(httptest.NewRequest("POST", path, nil)); got != want {
			t.Errorf("%s -> %q, want %q", path, got, want)
		}
	}
}

// authn runs before routing is known to be valid, so an unmatched path must still demand a
// signature — otherwise the route table is an unauthenticated map of the API.
func TestUnknownPathStillRequiresAControlPlaneSignature(t *testing.T) {
	table := testTable(t)
	if got := table.ServiceFor("ws")(httptest.NewRequest("GET", "/nothing/here", nil)); got != "ws" {
		t.Errorf("unmatched path -> %q, want the control plane's service", got)
	}
}

func TestTargetFor(t *testing.T) {
	table := testTable(t)
	targetFor := table.TargetFor()

	target, err := targetFor(
		httptest.NewRequest("POST", "/2026-09-18/functions/resize/invocations", nil),
		principal(account))
	if err != nil {
		t.Fatalf("TargetFor: %v", err)
	}
	if target.Action != "func:Invoke" {
		t.Errorf("action = %q", target.Action)
	}
	if want := "arn:dariya:func:hind-1:" + account + ":function/resize"; target.ResourceARN != want {
		t.Errorf("resource = %q, want %q", target.ResourceARN, want)
	}
}

// An unroutable request is an error, not a denial: it must not read in the logs as a permissions
// problem when it is a missing route.
func TestUnroutableIsNotFound(t *testing.T) {
	table := testTable(t)
	_, err := table.TargetFor()(httptest.NewRequest("GET", "/nothing/here", nil), principal(account))
	if got := apierr.From(err).Code; got != apierr.CodeNotFound {
		t.Errorf("code = %s, want %s", got, apierr.CodeNotFound)
	}
}

// The account in a resource ARN always comes from the authenticated principal. A path that
// carried it would be a caller-supplied claim about whose resource this is, which is the shape of
// every cross-tenant bug.
func TestResourceAccountComesFromThePrincipalNotThePath(t *testing.T) {
	table := testTable(t)
	targetFor := table.TargetFor()

	// The caller is account ...001 and puts ...002 in the path in every way they can.
	for _, path := range []string{
		"/2026-09-18/functions/resize/invocations",
		"/2026-09-18/functions/" + other + "/invocations",
	} {
		target, err := targetFor(httptest.NewRequest("POST", path, nil), principal(account))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if !strings.Contains(target.ResourceARN, ":"+account+":") {
			t.Errorf("%s -> %q, which is not scoped to the caller's account",
				path, target.ResourceARN)
		}
		if strings.Contains(target.ResourceARN, ":"+other+":") {
			t.Errorf("%s -> %q, which names an account from the path", path, target.ResourceARN)
		}
	}
}

// A resource id from the path must not be able to smuggle ARN structure or a wildcard, either of
// which would let a request match more of a policy than it should.
func TestPathResourceRejectsSmuggling(t *testing.T) {
	table := testTable(t)
	targetFor := table.TargetFor()

	for _, path := range []string{
		"/2026-09-18/functions/*/invocations",
		"/2026-09-18/functions/a:b/invocations",
		"/2026-09-18/functions//invocations",
		"/2026-09-18/functions/",
	} {
		if _, err := targetFor(httptest.NewRequest("POST", path, nil), principal(account)); err == nil {
			t.Errorf("%s was accepted as a resource name", path)
		}
	}
}

// Longest prefix wins, so a broad route and a specific one can coexist without ordering mattering.
func TestLongestPrefixWins(t *testing.T) {
	table, err := NewTable(region, []Route{
		{
			Service: "func", Prefix: "/2026-09-18/", Action: "func:List",
			Resource: AccountResource(region, "func", "function", "*all*"),
		},
		{
			Service: "func", Prefix: "/2026-09-18/functions/", Action: "func:Invoke",
			Resource: PathResource(region, "func", "function", "/2026-09-18/functions/"),
		},
	})
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}

	rt, ok := table.Match(httptest.NewRequest("POST", "/2026-09-18/functions/resize", nil))
	if !ok || rt.Action != "func:Invoke" {
		t.Errorf("matched %+v, want the more specific route", rt)
	}

	rt, ok = table.Match(httptest.NewRequest("GET", "/2026-09-18/other", nil))
	if !ok || rt.Action != "func:List" {
		t.Errorf("matched %+v, want the broader route", rt)
	}
}

func TestMethodNarrowsARoute(t *testing.T) {
	table, err := NewTable(region, []Route{
		{
			Service: "func", Method: "GET", Prefix: "/f/", Action: "func:GetFunction",
			Resource: PathResource(region, "func", "function", "/f/"),
		},
		{
			Service: "func", Method: "DELETE", Prefix: "/f/", Action: "func:DeleteFunction",
			Resource: PathResource(region, "func", "function", "/f/"),
		},
	})
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}

	if rt, _ := table.Match(httptest.NewRequest("GET", "/f/a", nil)); rt.Action != "func:GetFunction" {
		t.Errorf("GET matched %q", rt.Action)
	}
	if rt, _ := table.Match(httptest.NewRequest("DELETE", "/f/a", nil)); rt.Action != "func:DeleteFunction" {
		t.Errorf("DELETE matched %q", rt.Action)
	}
}

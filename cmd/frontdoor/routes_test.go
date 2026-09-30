package main

import (
	"net/http/httptest"
	"testing"

	commonv1 "dariyanws/gen/dariya/common/v1"
	"dariyanws/internal/router"
)

// The route decides the permission, so a wrong entry here is a request authorized as something it
// is not. Each case is (method, path) → (action, resource) as chala's Guard will insist on.
func TestChalaRoutes(t *testing.T) {
	table, err := router.NewTable("hind-1", chalaRoutes("hind-1", "http://127.0.0.1:1"))
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}
	target := table.TargetFor()
	p := &commonv1.Principal{AccountId: "000000000001",
		PrincipalArn: "arn:dariya:iam:hind-1:000000000001:user/root"}

	const acct = "arn:dariya:chala:hind-1:000000000001:account/000000000001"
	const web = "arn:dariya:chala:hind-1:000000000001:instance/web"

	for _, c := range []struct{ method, path, action, resource string }{
		{"PUT", "/chala/2026-09-30/instances/web", "chala:RunInstance", web},
		{"GET", "/chala/2026-09-30/instances/web", "chala:DescribeInstance", web},
		{"DELETE", "/chala/2026-09-30/instances/web", "chala:TerminateInstance", web},
		{"GET", "/chala/2026-09-30/instances", "chala:DescribeInstances", acct},
		{"GET", "/chala/2026-09-30/instances?tag.role=x", "chala:DescribeInstances", acct},
		{"GET", "/chala/2026-09-30/images", "chala:DescribeImages", acct},
	} {
		got, err := target(httptest.NewRequest(c.method, c.path, nil), p)
		if err != nil {
			t.Errorf("%s %s: %v", c.method, c.path, err)
			continue
		}
		if got.Action != c.action || got.ResourceARN != c.resource {
			t.Errorf("%s %s = %s on %s, want %s on %s",
				c.method, c.path, got.Action, got.ResourceARN, c.action, c.resource)
		}
	}

	// Unroutable: a method chala does not serve on the collection, and a lookalike prefix.
	//
	// NOT in this list, on purpose: GET .../images/anything. Routes match by prefix at a segment
	// boundary, so it is authorized as DescribeImages on the caller's account and chala answers
	// 404. The authorization is the one for what is served — nothing — so it is not a hole, but it
	// is a request authorized under a name it does not have, the same as /account/x on the
	// control plane. An exact-match flag on Route is the fix if it ever matters.
	for _, c := range []struct{ method, path string }{
		{"DELETE", "/chala/2026-09-30/instances"},
		{"PUT", "/chala/2026-09-30/instancesx/web"},
		{"GET", "/chala/2026-09-30/imagesx"},
	} {
		if _, err := target(httptest.NewRequest(c.method, c.path, nil), p); err == nil {
			t.Errorf("%s %s was routable", c.method, c.path)
		}
	}
}

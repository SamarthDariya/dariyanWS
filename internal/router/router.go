// Package router decides, for an incoming request, which service owns it and what permission it
// needs.
//
// Until M5 both answers were constants: every route belonged to the control plane and every
// request needed ws:Ping. The two middlewares that consume them — authn for the signature's
// service scope, authz for the action and resource — were written against function types from
// the start precisely so this package could replace them without touching either.
//
// # Why routing decides the permission too
//
// It would be possible to let each service declare what its own routes require. That is how it
// ends up inconsistent: two services spell the same operation differently, a new route ships with
// no permission at all and is reachable by anyone authenticated, and the front door cannot tell
// which is which. Keeping the table here means an unroutable request is refused before anything
// downstream sees it, and a route with no declared permission cannot exist — it would not be in
// the table, so there would be nothing to route.
package router

import (
	"fmt"
	"net/http"
	"strings"

	commonv1 "dariyanws/gen/dariya/common/v1"
	"dariyanws/internal/apierr"
	"dariyanws/internal/authz"
)

// Route is one entry in the table.
type Route struct {
	// Service is the ARN service segment, and also what a signature must be scoped to. A
	// signature for "func" presented on a "kyu" route is refused by authn before authz runs.
	Service string

	// Method is the HTTP method. Empty matches any, which is used only by probes.
	Method string

	// Prefix is matched against the path. Longest prefix wins, so "/2026-09-18/functions/" can
	// sit alongside a broader "/2026-09-18/" without ordering mattering.
	Prefix string

	// Action is the permission, service-qualified: "func:Invoke".
	Action string

	// Resource builds the concrete ARN this request acts on. It sees the authenticated principal,
	// so an ARN can be scoped to the caller's account without the path having to carry it — which
	// matters because a path that carried the account would let a caller write someone else's
	// into it.
	Resource func(r *http.Request, p *commonv1.Principal) (string, error)

	// Upstream is where the request is proxied. Empty means the front door serves it itself,
	// which is how the control-plane routes work until IAM moves out at v2.
	Upstream string
}

// Table is an immutable set of routes, consulted once per request.
type Table struct {
	routes []Route
	region string
}

func NewTable(region string, routes []Route) (*Table, error) {
	for i, rt := range routes {
		switch {
		case rt.Service == "":
			return nil, fmt.Errorf("router: route %d has no service", i)
		case rt.Prefix == "":
			return nil, fmt.Errorf("router: route %d has no prefix", i)
		case rt.Action == "":
			// The rule this package exists to enforce. A route with no action would be
			// authenticated and then served, which is the unauthorized corner that only ever
			// gets found by someone looking for one.
			return nil, fmt.Errorf("router: route %d (%s) has no action", i, rt.Prefix)
		case rt.Resource == nil:
			return nil, fmt.Errorf("router: route %d (%s) has no resource", i, rt.Prefix)
		}
	}
	return &Table{routes: routes, region: region}, nil
}

// Match finds the route for a request. Longest matching prefix wins.
func (t *Table) Match(r *http.Request) (Route, bool) {
	best := -1
	for i, rt := range t.routes {
		if rt.Method != "" && rt.Method != r.Method {
			continue
		}
		if !strings.HasPrefix(r.URL.Path, rt.Prefix) {
			continue
		}
		if best < 0 || len(rt.Prefix) > len(t.routes[best].Prefix) {
			best = i
		}
	}
	if best < 0 {
		return Route{}, false
	}
	return t.routes[best], true
}

// ServiceFor answers authn's question: which service must the signature be scoped to?
//
// An unmatched path returns the control plane's own service name rather than an error, because
// authn runs first and a 404 must not be reachable without a valid signature — otherwise the
// route table becomes an unauthenticated map of the API.
func (t *Table) ServiceFor(controlPlaneService string) func(*http.Request) string {
	return func(r *http.Request) string {
		if rt, ok := t.Match(r); ok {
			return rt.Service
		}
		return controlPlaneService
	}
}

// TargetFor answers authz's question: what permission does this request need?
func (t *Table) TargetFor() authz.TargetFor {
	return func(r *http.Request, p *commonv1.Principal) (authz.Target, error) {
		rt, ok := t.Match(r)
		if !ok {
			// Unroutable. Surfaced as NotFound to a caller who has already authenticated, which
			// is safe — they proved who they are — and as an error rather than a denial, so it
			// does not read in the logs as a permissions problem.
			return authz.Target{}, apierr.NotFound("no route for %s %s", r.Method, r.URL.Path)
		}

		resource, err := rt.Resource(r, p)
		if err != nil {
			return authz.Target{}, err
		}
		return authz.Target{Action: rt.Action, ResourceARN: resource}, nil
	}
}

// AccountResource builds an ARN for a resource owned by the caller, with a fixed id.
//
// The account always comes from the authenticated principal and never from the request. A path
// segment carrying an account id would be a caller-supplied claim about whose resource this is,
// which is the shape of every cross-tenant bug.
func AccountResource(region, service, resourceType, id string) func(*http.Request, *commonv1.Principal) (string, error) {
	return func(_ *http.Request, p *commonv1.Principal) (string, error) {
		return fmt.Sprintf("arn:dariya:%s:%s:%s:%s/%s",
			service, region, p.GetAccountId(), resourceType, id), nil
	}
}

// PathResource builds an ARN whose id is a path segment after the route's prefix.
//
// Only the id comes from the path; the account still comes from the principal. The segment is
// rejected if it contains a slash or is empty, so a caller cannot smuggle extra ARN structure
// into a resource name and widen what a policy matches.
func PathResource(region, service, resourceType, prefix string) func(*http.Request, *commonv1.Principal) (string, error) {
	return func(r *http.Request, p *commonv1.Principal) (string, error) {
		rest := strings.TrimPrefix(r.URL.Path, prefix)
		id, _, _ := strings.Cut(rest, "/")

		if id == "" {
			return "", apierr.Validation("the path does not name a %s", resourceType)
		}
		// A colon would let the id impersonate further ARN segments; a wildcard would let it
		// match more of a policy than it should.
		if strings.ContainsAny(id, ":*") {
			return "", apierr.Validation("a %s name may not contain ':' or '*'", resourceType)
		}

		return fmt.Sprintf("arn:dariya:%s:%s:%s:%s/%s",
			service, region, p.GetAccountId(), resourceType, id), nil
	}
}

package iam

import (
	"context"
	"time"

	iamv1 "dariyanws/gen/dariya/iam/v1"
	"dariyanws/internal/apierr"
	"dariyanws/internal/arn"
	"dariyanws/internal/ttlcache"
)

// Authorizer answers the one question on the hot path: may this principal do this, to this?
//
// It is a type of its own rather than a method on Server because it is the piece the front door
// holds, and because it owns a cache whose lifetime is the process rather than the request. The
// CRUD half of Server has no business being on that path.
type Authorizer struct {
	policies *ttlcache.Cache[[]AttachedPolicy]

	// Dev decides whether a denial explains itself. In production, telling a caller precisely
	// which statement denied them describes a policy to somebody not allowed to read it.
	Dev bool
}

// AuthorizerOptions configure the policy cache. Zero values take the ttlcache defaults.
type AuthorizerOptions struct {
	TTL        time.Duration
	MaxEntries int
	Now        func() time.Time
	Dev        bool
}

// NewAuthorizer wraps a policy source in the same cache the credential lookup got.
//
// The reason is E2 rather than symmetry: an uncached lookup per request was measured at 96.4% of
// the front door's cost, and Authorize adds a second one of exactly the same shape — a small
// indexed read whose answer is identical for every request from the same caller. Shipping it
// uncached would re-create the collapse E2 found, this time with two queries per request instead
// of one.
//
// There is no negative caching here, and its absence is deliberate. "This principal has no
// policies" is a perfectly cacheable positive result — an empty slice — so there is no error to
// cache. A failure to read policies must never be cached, because a cached read failure denies
// every request for the TTL, which is an outage rather than a stale answer.
func NewAuthorizer(source PolicySource, opts AuthorizerOptions) *Authorizer {
	return &Authorizer{
		Dev: opts.Dev,
		policies: ttlcache.New(source.PoliciesFor, ttlcache.Options{
			TTL:        opts.TTL,
			MaxEntries: opts.MaxEntries,
			Now:        opts.Now,
			// IsNegative is left nil: nothing is a definitive error here.
		}),
	}
}

// PolicySource is what an Authorizer reads from. *Server satisfies it.
type PolicySource interface {
	PoliciesFor(ctx context.Context, principalARN string) ([]AttachedPolicy, error)
}

// InvalidatePrincipal drops a principal's cached policies, so an attach or detach served by this
// process takes effect at once. The TTL remains the guarantee for any other process.
func (a *Authorizer) InvalidatePrincipal(principalARN string) { a.policies.Invalidate(principalARN) }

// Stats exposes the cache for logs and benchmarks.
func (a *Authorizer) Stats() ttlcache.Stats { return a.policies.Stats() }

// Authorize evaluates a concrete request against the principal's attached policies.
func (a *Authorizer) Authorize(ctx context.Context, req *iamv1.AuthorizeRequest) (*iamv1.AuthorizeResponse, error) {
	principal := req.GetPrincipal()
	if principal.GetPrincipalArn() == "" {
		return nil, apierr.Validation("principal.principal_arn is required")
	}
	if req.GetAction() == "" {
		return nil, apierr.Validation("action is required")
	}

	resource, err := arn.Parse(req.GetResourceArn())
	if err != nil {
		return nil, apierr.Validation("resource_arn is not a valid ARN: %v", err)
	}

	principalARN, err := arn.Parse(principal.GetPrincipalArn())
	if err != nil {
		return nil, apierr.Validation("principal_arn is not a valid ARN: %v", err)
	}

	// The check that does not depend on any policy existing.
	//
	// A principal may only ever act on resources in its own account, and no policy can grant
	// otherwise — cross-account access would arrive as a resource policy on the target, which v1
	// does not have. Enforcing it here rather than relying on every policy being written with a
	// correctly scoped ARN means a careless "Resource": "*" cannot reach another tenant. It is
	// the difference between tenant isolation being a property of the system and a property of
	// whoever last edited a policy.
	if principalARN.Account != resource.Account {
		return &iamv1.AuthorizeResponse{
			Decision: iamv1.Decision_DECISION_EXPLICIT_DENY,
			Reason:   a.reason("the principal and the resource are in different accounts"),
		}, nil
	}

	policies, err := a.policies.Get(ctx, principal.GetPrincipalArn())
	if err != nil {
		// Fail closed, loudly. The caller gets an error rather than a denial, because a denial
		// would be indistinguishable from a real one and would hide an outage as a permissions
		// problem — which is the bug report nobody can diagnose.
		return nil, err
	}

	decision := Evaluate(policies, Request{
		Action:      req.GetAction(),
		ResourceARN: req.GetResourceArn(),
	})

	return &iamv1.AuthorizeResponse{
		Decision:         decision.Effect,
		MatchedPolicyArn: decision.PolicyARN,
		MatchedSid:       decision.SID,
		Reason:           a.reason(explain(decision)),
	}, nil
}

func (a *Authorizer) reason(text string) string {
	if !a.Dev {
		return ""
	}
	return text
}

func explain(d Decision) string {
	switch d.Effect {
	case iamv1.Decision_DECISION_ALLOW:
		return "allowed by statement " + d.SID + " in " + d.PolicyARN
	case iamv1.Decision_DECISION_EXPLICIT_DENY:
		return "denied by statement " + d.SID + " in " + d.PolicyARN
	default:
		return "no attached policy matches this action and resource"
	}
}

// Authorize on the Server satisfies the generated gRPC interface, for callers that reach IAM over
// the wire rather than holding an Authorizer.
//
// It builds no cache: a per-call Authorizer would cache nothing and mislead anyone reading it into
// thinking the RPC path is as cheap as the in-process one. When IAM becomes its own process at v2
// the cache moves to whatever holds this Server, not to this method.
func (s *Server) Authorize(ctx context.Context, req *iamv1.AuthorizeRequest) (*iamv1.AuthorizeResponse, error) {
	uncached := &Authorizer{
		policies: ttlcache.New(s.PoliciesFor, ttlcache.Options{TTL: time.Nanosecond}),
	}
	return uncached.Authorize(ctx, req)
}

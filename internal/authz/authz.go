// Package authz turns a verified Principal into a permitted one, or into a 403.
//
// It is a separate middleware from authn, and separate for a reason that outlives the convenience:
// authentication asks "who is this" and authorization asks "may they". Those two questions fail
// differently, are cached differently, and — per DESIGN.md decision 6 — will be answered by two
// different services once IAM moves out at v2. A single middleware doing both would have to be
// split at exactly the moment that is hardest.
//
// This is also where the capability token gets minted at M4. Today the decision is made and acted
// on in one process; at M4 the decision starts travelling.
package authz

import (
	"context"
	"log/slog"
	"net/http"

	commonv1 "dariyanws/gen/dariya/common/v1"
	iamv1 "dariyanws/gen/dariya/iam/v1"
	"dariyanws/internal/apierr"
	"dariyanws/internal/httpx"
)

// Target is what a route is asking permission to do. Concrete: the resource is resolved before
// the question is asked, never a pattern.
type Target struct {
	Action      string
	ResourceARN string
}

// TargetFor maps a request to the permission it requires.
//
// Returning an error means the route could not be expressed as an action on a resource, which is
// a programming error rather than a client error — and is treated as a 500, because failing
// closed on something nobody can fix from the outside is better than guessing an action name.
//
// At M5 this becomes the router's job, the same way ServiceFor did for authn.
type TargetFor func(r *http.Request, p *commonv1.Principal) (Target, error)

// Config is what the middleware needs.
type Config struct {
	Decide Decider
	Target TargetFor

	// Dev lets a denial say which statement produced it. Off in production, where explaining a
	// denial describes a policy to someone not entitled to read it.
	Dev bool

	Log *slog.Logger
}

// Decider answers the authorization question. *iam.Authorizer satisfies it.
//
// Declared here as the narrow interface this package needs, rather than importing the concrete
// type, so the middleware can be tested against a fake with no database behind it.
type Decider interface {
	Authorize(ctx context.Context, req *iamv1.AuthorizeRequest) (*iamv1.AuthorizeResponse, error)
}

// Middleware refuses any request the policy engine does not allow.
func Middleware(cfg Config) httpx.Middleware {
	if cfg.Target == nil {
		panic("authz: Config.Target is required — a route with no action cannot be authorized")
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := httpx.PrincipalFrom(r.Context())
			if !ok {
				// Unreachable behind authn. Handled rather than assumed, because mounting this
				// middleware without authn in front of it must fail closed and loudly, not
				// authorize an empty principal — whose account id would be "", which every
				// storage key prefix matches.
				cfg.Log.Error("authz ran without authn",
					"request_id", httpx.RequestID(r.Context()), "path", r.URL.Path)
				httpx.WriteError(w, r, apierr.Internal(nil, "internal failure"), cfg.Dev)
				return
			}

			target, err := cfg.Target(r, principal)
			if err != nil {
				cfg.Log.Error("route has no authorization target",
					"request_id", httpx.RequestID(r.Context()), "path", r.URL.Path, "error", err)
				httpx.WriteError(w, r, apierr.Internal(err, "internal failure"), cfg.Dev)
				return
			}

			resp, err := cfg.Decide.Authorize(r.Context(), &iamv1.AuthorizeRequest{
				Principal:   principal,
				Action:      target.Action,
				ResourceArn: target.ResourceARN,
				RequestId:   httpx.RequestID(r.Context()),
			})
			if err != nil {
				// An error is not a denial. Surfacing it as 403 would hide an outage as a
				// permissions problem, and nobody has ever successfully debugged that.
				httpx.WriteError(w, r, err, cfg.Dev)
				return
			}

			if resp.GetDecision() != iamv1.Decision_DECISION_ALLOW {
				cfg.Log.Info("request denied",
					"request_id", httpx.RequestID(r.Context()),
					"account_id", principal.GetAccountId(),
					"principal", principal.GetPrincipalArn(),
					"action", target.Action,
					"resource", target.ResourceARN,
					"decision", resp.GetDecision().String(),
					"matched_policy", resp.GetMatchedPolicyArn(),
					"matched_sid", resp.GetMatchedSid())

				httpx.WriteError(w, r, denied(target, resp, cfg.Dev), cfg.Dev)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// denied builds the 403.
//
// Unlike an authentication failure, an authorization failure may say what was attempted: the
// caller is known, and telling them "you may not Invoke this function" reveals nothing they did
// not already supply. What it must not reveal is the policy — which statement matched, or that
// one exists — so MatchedSid never leaves the server outside dev mode.
func denied(target Target, resp *iamv1.AuthorizeResponse, dev bool) *apierr.Error {
	e := &apierr.Error{
		Code:    apierr.CodeAccessDenied,
		Message: "not authorized to perform " + target.Action + " on " + target.ResourceARN,
	}
	if dev {
		e.Details = map[string]string{
			"decision":       resp.GetDecision().String(),
			"matched_policy": resp.GetMatchedPolicyArn(),
			"matched_sid":    resp.GetMatchedSid(),
			"reason":         resp.GetReason(),
		}
	}
	return e
}

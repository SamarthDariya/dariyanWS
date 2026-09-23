// Package frontdoor assembles the single endpoint every request to this cloud enters through
// (DESIGN.md decision 2).
//
// # On concurrency, and what unit 1 already settled
//
// Go's net/http is goroutine-per-connection, which is the same shape as the thread-per-connection
// server `dariyaraah` measured — with goroutines instead of OS threads, so the per-connection cost
// that bounded unit 1 is not what bounds this. Unit 1's conclusion still applies though, because
// it was not really about threads: throughput is concurrency ÷ latency, and the server only
// chooses the concurrency. Here the concurrency ceiling is not goroutines, it is the Postgres
// pool that every signed request passes through to resolve an access key. That is the prediction
// E2 is written to test, and it is why the credential lookup is deliberately left uncached.
package frontdoor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	commonv1 "dariyanws/gen/dariya/common/v1"
	"dariyanws/internal/apierr"
	"dariyanws/internal/authn"
	"dariyanws/internal/authz"
	"dariyanws/internal/control"
	"dariyanws/internal/httpx"
	"dariyanws/internal/iam"
	"dariyanws/internal/store"
)

// ServiceName is the service that control-plane routes are scoped to in a signature.
//
// At M2 it is the only one. At M5 the router decides per route, and this becomes one entry in a
// table rather than a constant.
const ServiceName = "ws"

// ActionPing is the permission /ping requires.
//
// /ping exists to prove the path works, and from M3.4 the path includes authorization — so it
// requires a real permission rather than being exempt. An endpoint exempted "because it is only a
// test endpoint" is how a system ends up with an unauthenticated corner nobody remembers.
const ActionPing = "ws:Ping"

// PingResourceARN is what a ping acts on: the caller's own endpoint in this region.
//
// A resource is required because the policy language has no concept of an action without one, and
// inventing an exemption for actions that act on nothing would be a second evaluation path. The
// account in the ARN is the caller's, so a policy granting ws:Ping cannot be written once and
// reused across tenants.
func PingResourceARN(region, accountID string) string {
	return fmt.Sprintf("arn:dariya:ws:%s:%s:endpoint/ping", region, accountID)
}

// Options configure a front door.
type Options struct {
	Region string

	// KeyCacheTTL is how long a resolved access key is reused. Zero takes control.DefaultTTL,
	// which is deliberately the capability token lifetime, so the whole system has one answer to
	// "how long after a revocation can this still work?".
	KeyCacheTTL time.Duration

	// Mint turns each allow into a capability the service downstream can verify offline
	// (DESIGN.md decision 6). Nil leaves the decision in this process, which is what M3 did.
	Mint authz.Minter

	// CapabilityTTL bounds how long a minted decision can be acted on. Zero takes
	// capability.DefaultTTL.
	CapabilityTTL time.Duration

	// PolicyCacheTTL is how long a principal's attached policies are reused. Zero takes the
	// ttlcache default.
	PolicyCacheTTL time.Duration

	// DisableKeyCache restores the uncached path. It exists so E2's control can be re-run against
	// the same binary rather than against a remembered number from a previous commit.
	DisableKeyCache bool

	// Dev makes error responses say which check rejected a request. Off in production, where that
	// detail describes the system to the caller least entitled to it.
	Dev bool

	Log *slog.Logger
}

// NewHandler builds the routed, middleware-wrapped handler.
//
// Separated from listening so tests can exercise the whole chain — request ids, authentication,
// error rendering — over an in-process transport without binding a port.
func NewHandler(accounts *control.AccountsServer, policies *iam.Server, st *store.Store, opts Options) (http.Handler, *control.CachingResolver) {
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}

	// E2 measured the uncached lookup at 96.4% of everything the front door adds, with the pool
	// as the concurrency ceiling. The cache is that measurement's answer; see BREAK.md.
	var keys authn.KeyResolver = accounts
	var cache *control.CachingResolver
	if !opts.DisableKeyCache {
		cache = control.NewCachingResolver(accounts, control.CacheOptions{TTL: opts.KeyCacheTTL})
		// Revocation stays immediate on the process that served the delete; the TTL is the bound
		// for any other front door, which is a story that only starts mattering when there is one.
		accounts.OnKeyDeleted(cache.Invalidate)
		keys = cache
	}

	// The policy cache gets the same treatment as the credential cache, and for the same
	// measured reason (BREAK.md E2). Invalidation is wired both ways so a grant or a revocation
	// served by this process takes effect at once rather than at the end of a TTL.
	authorizer := iam.NewAuthorizer(policies, iam.AuthorizerOptions{
		TTL: opts.PolicyCacheTTL,
		Dev: opts.Dev,
	})
	policies.OnPrincipalChanged(authorizer.InvalidatePrincipal)

	mux := http.NewServeMux()

	// Authenticated and authorized. Everything the cloud actually does lives behind this chain,
	// authn outermost: there is no point asking what a caller may do before knowing who they are,
	// and authz fails closed if it ever finds itself without one.
	authenticated := httpx.Chain(
		http.HandlerFunc(handlePing),
		authn.Middleware(authn.Config{
			Keys:    keys,
			Region:  opts.Region,
			Service: func(*http.Request) string { return ServiceName },
			Dev:     opts.Dev,
			Log:     log,
		}),
		authz.Middleware(authz.Config{
			Decide: authorizer,
			Mint:   opts.Mint,
			Target: func(_ *http.Request, p *commonv1.Principal) (authz.Target, error) {
				return authz.Target{
					Action:      ActionPing,
					ResourceARN: PingResourceARN(opts.Region, p.GetAccountId()),
				}, nil
			},
			Dev: opts.Dev,
			Log: log,
		}),
	)
	mux.Handle("/ping", authenticated)

	// Unauthenticated probes.
	//
	// Split deliberately in two. /healthz answers "is this process alive" and touches nothing, so
	// an orchestrator restarting on a failed probe cannot be triggered by a slow database. /readyz
	// answers "can this process serve", which means the database, and is therefore the one an
	// unauthenticated caller could use to generate load — so it has its own short timeout.
	mux.HandleFunc("/healthz", handleHealthz)
	mux.Handle("/readyz", handleReadyz(st, opts.Dev))

	// Outermost first: an id before anything can log, recovery before anything can panic, and the
	// access log inside both so it can report the status recovery produced.
	return httpx.Chain(mux,
		httpx.WithRequestID,
		httpx.Recover(opts.Dev),
		httpx.AccessLog(log),
	), cache
}

// handlePing echoes the caller back to themselves.
//
// It exists so M2 is demonstrable: if this returns your account id, then signing, key resolution,
// verification and principal propagation all work end to end. It is not a health check — it
// requires a valid signature, and that is the point of it.
func handlePing(w http.ResponseWriter, r *http.Request) {
	p, ok := httpx.PrincipalFrom(r.Context())
	if !ok {
		// Unreachable behind the authn middleware. Handled rather than assumed, because the day
		// someone mounts this route outside the chain, the failure should be a 500 and not an
		// unauthenticated success.
		httpx.WriteError(w, r, apierr.Internal(nil, "internal failure"), false)
		return
	}

	body := map[string]string{
		"account_id":    p.GetAccountId(),
		"principal_arn": p.GetPrincipalArn(),
		"request_id":    httpx.RequestID(r.Context()),
	}

	// Which key signed the capability, and nothing else about it. The token itself must never
	// reach the caller: it is a bearer credential for the very request they already
	// authenticated, with a different expiry and no way to revoke it. What is useful to report
	// is that one exists and which key a service would need to check it.
	if token, ok := httpx.CapabilityFrom(r.Context()); ok {
		body["capability_key_id"] = token.GetKeyId()
	}

	httpx.WriteJSON(w, r, http.StatusOK, body)
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
}

func handleReadyz(st *store.Store, dev bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		if err := st.Pool().Ping(ctx); err != nil {
			httpx.WriteError(w, r, apierr.Internal(err, "the control-plane store is unreachable"), dev)
			return
		}
		httpx.WriteJSON(w, r, http.StatusOK, map[string]string{"status": "ready"})
	})
}

// Serve listens and serves until ctx is cancelled, then drains in-flight requests.
//
// Timeouts are set explicitly because Go's zero values are all "no timeout", which means one
// client holding a connection open and sending nothing occupies a goroutine forever. With every
// request funnelled through one process (decision 2), that is the cheapest possible denial of
// service against the whole cloud.
func Serve(ctx context.Context, addr string, handler http.Handler, log *slog.Logger) error {
	srv := &http.Server{
		Addr:    addr,
		Handler: handler,

		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("front door listening", "addr", addr)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err

	case <-ctx.Done():
		// A bounded drain: in-flight requests finish, new connections are refused, and a request
		// that will not end does not hold the process open forever.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		log.Info("front door draining")
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return nil
	}
}

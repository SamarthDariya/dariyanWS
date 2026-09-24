// Package proxy forwards an authenticated, authorized request to the service that owns the
// resource.
//
// This is the hop decision 2 bought: every request enters through one door, so the door has to
// hand it on. Written by hand rather than with httputil.ReverseProxy because the interesting
// behaviour here is what does NOT get forwarded, and a reverse proxy's defaults are tuned for
// forwarding as much as possible.
package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"dariyanws/internal/apierr"
	"dariyanws/internal/httpx"
	"dariyanws/internal/router"
)

// MaxResponseBytes caps what will be copied back from a service.
//
// A service is more trusted than a client, but "more trusted" is not "allowed to exhaust the
// front door's memory on behalf of every concurrent request". Six megabytes, matching the request
// cap in authn.
const MaxResponseBytes = 6 << 20

// hopByHopHeaders are meaningful to one connection and must not be forwarded (RFC 7230 §6.1).
// Forwarding Connection or Keep-Alive would let a client's connection preferences leak into the
// front door's pooled connection to a service, which is a different connection entirely.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// Options configure a Proxy.
type Options struct {
	Table *router.Table

	// Timeout bounds one upstream request. It must be shorter than the front door's own write
	// timeout, or the front door gives up on the client before it gives up on the service and
	// the caller gets a truncated response instead of a 504.
	Timeout time.Duration

	Dev bool
	Log *slog.Logger
}

// Proxy is an http.Handler. It expects to run behind authn and authz.
type Proxy struct {
	table   *router.Table
	client  *http.Client
	timeout time.Duration
	dev     bool
	log     *slog.Logger
}

func New(opts Options) *Proxy {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}

	return &Proxy{
		table:   opts.Table,
		timeout: timeout,
		dev:     opts.Dev,
		log:     log,
		client: &http.Client{
			// Redirects are not followed. A service answering 3xx is a service misconfigured,
			// and chasing it would let an upstream steer the front door at an arbitrary URL
			// while carrying a capability header.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				MaxIdleConns:        256,
				MaxIdleConnsPerHost: 64,
				IdleConnTimeout:     90 * time.Second,
				DialContext: (&net.Dialer{
					Timeout:   2 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
			},
		},
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route, ok := p.table.Match(r)
	if !ok {
		httpx.WriteError(w, r, apierr.NotFound("no route for %s %s", r.Method, r.URL.Path), p.dev)
		return
	}
	if route.Upstream == "" {
		// Unreachable by construction since M6: router.NewTable refuses a route with neither a
		// handler nor an upstream, and Table cannot be built any other way. Kept because the
		// invariant lives in another package, and a 500 here is a far better failure than a
		// request silently proxied to "" if a third kind of destination is ever added.
		httpx.WriteError(w, r, apierr.Internal(nil, "internal failure"), p.dev)
		p.log.Error("route has no upstream and no handler",
			"request_id", httpx.RequestID(r.Context()), "path", r.URL.Path)
		return
	}

	upstream, err := url.Parse(route.Upstream)
	if err != nil {
		httpx.WriteError(w, r, apierr.Internal(err, "internal failure"), p.dev)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), p.timeout)
	defer cancel()

	outbound, err := p.buildRequest(ctx, r, upstream)
	if err != nil {
		httpx.WriteError(w, r, apierr.Internal(err, "internal failure"), p.dev)
		return
	}

	resp, err := p.client.Do(outbound)
	if err != nil {
		p.writeUpstreamError(w, r, route, err)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	// The request id is the front door's, not the service's. A service that sets its own would
	// otherwise break the one identifier that ties the whole path together.
	w.Header().Set(httpx.RequestIDHeader, httpx.RequestID(r.Context()))
	w.WriteHeader(resp.StatusCode)

	if _, err := io.Copy(w, io.LimitReader(resp.Body, MaxResponseBytes)); err != nil {
		// The status line is already sent; the client sees a truncated body and nothing better
		// can be done for them. Logged so a truncated response is not a mystery.
		p.log.Error("copying an upstream response failed",
			"request_id", httpx.RequestID(r.Context()),
			"service", route.Service, "error", err)
	}
}

func (p *Proxy) buildRequest(ctx context.Context, r *http.Request, upstream *url.URL) (*http.Request, error) {
	target := *upstream
	target.Path = strings.TrimSuffix(upstream.Path, "/") + r.URL.Path
	target.RawQuery = r.URL.RawQuery

	outbound, err := http.NewRequestWithContext(ctx, r.Method, target.String(), r.Body)
	if err != nil {
		return nil, err
	}
	outbound.ContentLength = r.ContentLength

	copyHeaders(outbound.Header, r.Header)

	// The caller's edge credentials do not travel inward, and this is the most important line in
	// the package. The Authorization header is a valid signature over this exact request, replay-
	// able for the rest of its five-minute window (decision 5 has no nonce), so forwarding it
	// would hand every service a working credential for the caller it is serving. The service
	// gets the capability instead: narrower, shorter-lived, and useless for anything else.
	outbound.Header.Del("Authorization")
	outbound.Header.Del(signingDateHeader)
	outbound.Header.Del(signingContentHeader)

	for _, h := range hopByHopHeaders {
		outbound.Header.Del(h)
	}

	// Host is the upstream's, so a service naming itself in a redirect or a log sees its own
	// address rather than the front door's.
	outbound.Host = upstream.Host

	// What the service actually needs, both already set by the middlewares.
	outbound.Header.Set(httpx.RequestIDHeader, httpx.RequestID(r.Context()))

	return outbound, nil
}

// Header names duplicated from internal/signing rather than imported, to keep the proxy from
// depending on the signing package for two strings. If either changes, this list is stale — the
// test that asserts no signing header survives the hop is what catches that.
const (
	signingDateHeader    = "X-Dariya-Date"
	signingContentHeader = "X-Dariya-Content-Sha256"
)

// writeUpstreamError distinguishes the failures an operator needs to tell apart.
//
// A timeout, a refused connection and a broken stream have different causes and different fixes,
// and collapsing them into one 502 is how "the service is down" and "the service is slow" become
// the same ticket.
func (p *Proxy) writeUpstreamError(w http.ResponseWriter, r *http.Request, route router.Route, err error) {
	requestID := httpx.RequestID(r.Context())

	var apiErr *apierr.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		apiErr = &apierr.Error{
			Code:    apierr.CodeInternal,
			Message: "the " + route.Service + " service did not respond in time",
			Cause:   err,
		}
	case errors.Is(err, context.Canceled):
		// The client hung up. Nothing is written — there is nobody to write to — and it is not
		// logged as an error, because a caller disconnecting is normal.
		p.log.Info("client disconnected before the upstream replied",
			"request_id", requestID, "service", route.Service)
		return
	default:
		apiErr = &apierr.Error{
			Code:    apierr.CodeInternal,
			Message: "the " + route.Service + " service is unavailable",
			Cause:   err,
		}
	}

	apiErr.Details = map[string]string{"service": route.Service, "upstream_error": err.Error()}
	p.log.Error("upstream request failed",
		"request_id", requestID, "service", route.Service,
		"upstream", route.Upstream, "error", err)

	httpx.WriteError(w, r, apiErr, p.dev)
}

func copyHeaders(dst, src http.Header) {
	for name, values := range src {
		for _, v := range values {
			dst.Add(name, v)
		}
	}
}

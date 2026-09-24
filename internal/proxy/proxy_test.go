package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dariyanws/internal/httpx"
	"dariyanws/internal/router"
)

const region = "hind-1"

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// upstream records what actually arrived, which is what most of these tests are about.
type upstream struct {
	*httptest.Server
	gotHeaders http.Header
	gotPath    string
	gotQuery   string
	gotBody    string
	gotHost    string
}

func newUpstream(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *upstream {
	t.Helper()
	u := &upstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.gotHeaders = r.Header.Clone()
		u.gotPath = r.URL.Path
		u.gotQuery = r.URL.RawQuery
		u.gotHost = r.Host
		body, _ := io.ReadAll(r.Body)
		u.gotBody = string(body)

		if handler != nil {
			handler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(u.Close)
	return u
}

func newProxy(t *testing.T, upstreamURL string, timeout time.Duration) http.Handler {
	t.Helper()
	table, err := router.NewTable(region, []router.Route{{
		Service: "func", Prefix: "/f/", Action: "func:Invoke",
		Resource: router.PathResource(region, "func", "function", "/f/"),
		Upstream: upstreamURL,
	}})
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}

	p := New(Options{Table: table, Timeout: timeout, Log: discard()})
	return httpx.Chain(p, httpx.WithRequestID)
}

func TestForwardsMethodPathQueryAndBody(t *testing.T) {
	up := newUpstream(t, nil)
	h := newProxy(t, up.URL, 0)

	req := httptest.NewRequest("POST", "/f/resize/invocations?qualifier=live",
		strings.NewReader(`{"x":1}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if up.gotPath != "/f/resize/invocations" {
		t.Errorf("upstream path = %q", up.gotPath)
	}
	if up.gotQuery != "qualifier=live" {
		t.Errorf("upstream query = %q", up.gotQuery)
	}
	if up.gotBody != `{"x":1}` {
		t.Errorf("upstream body = %q", up.gotBody)
	}
	if rec.Body.String() != `{"ok":true}` {
		t.Errorf("response body = %q", rec.Body.String())
	}
}

// The most important test in the package. The caller's Authorization header is a valid signature
// over this exact request, replayable for the rest of its five-minute window because decision 5
// has no nonce. Forwarding it would hand every service a working credential for the caller it is
// serving.
func TestEdgeCredentialsDoNotTravelInward(t *testing.T) {
	up := newUpstream(t, nil)
	h := newProxy(t, up.URL, 0)

	req := httptest.NewRequest("POST", "/f/resize/invocations", nil)
	req.Header.Set("Authorization", "DARIYA1-HMAC-SHA256 Credential=DARIYAKEYX/2026.../ws, Signature=deadbeef")
	req.Header.Set("X-Dariya-Date", "20260923T120000Z")
	req.Header.Set("X-Dariya-Content-Sha256", "abc")
	req.Header.Set(httpx.CapabilityHeader, "a-capability")

	h.ServeHTTP(httptest.NewRecorder(), req)

	for _, header := range []string{"Authorization", "X-Dariya-Date", "X-Dariya-Content-Sha256"} {
		if got := up.gotHeaders.Get(header); got != "" {
			t.Errorf("%s reached the service: %q", header, got)
		}
	}
	// And the thing that SHOULD travel did.
	if got := up.gotHeaders.Get(httpx.CapabilityHeader); got != "a-capability" {
		t.Errorf("the capability did not reach the service: %q", got)
	}
}

func TestRequestIDTravelsAndIsNotOverridable(t *testing.T) {
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		// A service setting its own id would break the identifier that ties the path together.
		w.Header().Set(httpx.RequestIDHeader, "the-service-made-this-up")
		w.WriteHeader(http.StatusOK)
	})
	h := newProxy(t, up.URL, 0)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/f/a/invocations", nil))

	forwarded := up.gotHeaders.Get(httpx.RequestIDHeader)
	if forwarded == "" {
		t.Fatal("no request id reached the service")
	}
	if got := rec.Header().Get(httpx.RequestIDHeader); got != forwarded {
		t.Errorf("the service overrode the request id: response has %q, forwarded %q",
			got, forwarded)
	}
}

func TestHopByHopHeadersAreStripped(t *testing.T) {
	up := newUpstream(t, nil)
	h := newProxy(t, up.URL, 0)

	req := httptest.NewRequest("POST", "/f/a/invocations", nil)
	req.Header.Set("Connection", "close")
	req.Header.Set("Proxy-Authorization", "secret")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if got := up.gotHeaders.Get("Proxy-Authorization"); got != "" {
		t.Errorf("Proxy-Authorization reached the service: %q", got)
	}
}

func TestHostIsTheUpstreams(t *testing.T) {
	up := newUpstream(t, nil)
	h := newProxy(t, up.URL, 0)

	req := httptest.NewRequest("POST", "/f/a/invocations", nil)
	req.Host = "dariyanws.example"
	h.ServeHTTP(httptest.NewRecorder(), req)

	if strings.Contains(up.gotHost, "dariyanws.example") {
		t.Errorf("the front door's Host reached the service: %q", up.gotHost)
	}
}

// A timeout and an unreachable service have different causes and different fixes. Collapsing
// them is how "the service is down" and "the service is slow" become the same ticket.
func TestSlowUpstreamIsATimeout(t *testing.T) {
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})
	h := newProxy(t, up.URL, 50*time.Millisecond)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/f/a/invocations", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "did not respond in time") {
		t.Errorf("a timeout was not reported as one: %s", rec.Body.String())
	}
}

func TestUnreachableUpstream(t *testing.T) {
	// A port nothing is listening on.
	h := newProxy(t, "http://127.0.0.1:1", 0)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/f/a/invocations", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "unavailable") {
		t.Errorf("an unreachable service was not reported as one: %s", rec.Body.String())
	}
}

// An upstream answering 3xx is misconfigured. Following it would let a service steer the front
// door at an arbitrary URL while carrying a capability.
func TestRedirectsAreNotFollowed(t *testing.T) {
	var followed bool
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			followed = true
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	})
	h := newProxy(t, up.URL, 0)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/f/a/invocations", nil))

	if followed {
		t.Error("the proxy followed an upstream redirect")
	}
	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want the 302 passed through", rec.Code)
	}
}

// An upstream's status and headers reach the caller unchanged: a service's 404 is the caller's
// 404, not a 502.
func TestUpstreamStatusPassesThrough(t *testing.T) {
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Service-Says", "no")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"ResourceNotFound"}`))
	})
	h := newProxy(t, up.URL, 0)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/f/missing/invocations", nil))

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	if rec.Header().Get("X-Service-Says") != "no" {
		t.Error("upstream headers did not pass through")
	}
}

func TestUnroutableRequest(t *testing.T) {
	up := newUpstream(t, nil)
	h := newProxy(t, up.URL, 0)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/nothing", nil))

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

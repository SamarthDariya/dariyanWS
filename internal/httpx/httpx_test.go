package httpx

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	commonv1 "dariyanws/gen/dariya/common/v1"
	"dariyanws/internal/apierr"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type errBody struct {
	Code      string            `json:"code"`
	Message   string            `json:"message"`
	RequestID string            `json:"request_id"`
	Details   map[string]string `json:"details"`
}

func TestRequestIDIsMintedAndEchoed(t *testing.T) {
	var seen string
	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestID(r.Context())
		w.WriteHeader(http.StatusOK)
	}), WithRequestID)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))

	if seen == "" {
		t.Fatal("handler saw no request id on the context")
	}
	if got := rec.Header().Get(RequestIDHeader); got != seen {
		t.Errorf("header %s = %q, context had %q", RequestIDHeader, got, seen)
	}
}

// A client-supplied id must not be reused. Trusting it lets a caller forge collisions between
// unrelated requests and inject whatever they like into the logs.
func TestClientRequestIDIsNotTrusted(t *testing.T) {
	var seen string
	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestID(r.Context())
	}), WithRequestID)

	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set(RequestIDHeader, "attacker-chosen")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if seen == "attacker-chosen" {
		t.Error("the front door reused a client-supplied request id")
	}
}

func TestRequestIDsAreDistinct(t *testing.T) {
	h := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), WithRequestID)

	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
		id := rec.Header().Get(RequestIDHeader)
		if seen[id] {
			t.Fatalf("duplicate request id %s after %d requests", id, i)
		}
		seen[id] = true
	}
}

func TestWriteErrorShape(t *testing.T) {
	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		WriteError(w, r, apierr.NotFound("no account 000000000042"), false)
	}), WithRequestID)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content type = %q", ct)
	}

	var body errBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, rec.Body.String())
	}
	if body.Code != apierr.CodeNotFound {
		t.Errorf("code = %q", body.Code)
	}
	// The request id must be in the body, not only the header: it is what a user pastes into a
	// bug report, and nobody copies response headers.
	if body.RequestID == "" || body.RequestID != rec.Header().Get(RequestIDHeader) {
		t.Errorf("body request_id = %q, header = %q", body.RequestID, rec.Header().Get(RequestIDHeader))
	}
}

// Details describe which check rejected a request. In production that is a description of the
// system handed to the one caller who should not have it.
func TestErrorDetailsOnlyInDev(t *testing.T) {
	makeErr := func() error {
		return &apierr.Error{
			Code:    apierr.CodeInvalidSig,
			Message: "the request signature is invalid",
			Details: map[string]string{"check": "timestamp_outside_skew_window"},
		}
	}

	for _, dev := range []bool{false, true} {
		h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			WriteError(w, r, makeErr(), dev)
		}), WithRequestID)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))

		var body errBody
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("dev=%v: %v", dev, err)
		}
		if dev && len(body.Details) == 0 {
			t.Error("dev mode withheld the detail that makes a 403 debuggable")
		}
		if !dev && len(body.Details) != 0 {
			t.Errorf("production leaked details: %v", body.Details)
		}
	}
}

// The internal cause is for the log, never the response. It is where table names, DSNs and
// internal hostnames leak out.
func TestInternalCauseNeverReachesTheCaller(t *testing.T) {
	cause := "dial tcp 10.0.0.7:5432: connection refused"
	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		WriteError(w, r, apierr.Internal(io.EOF, "internal failure"), true)
	}), WithRequestID)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))

	if strings.Contains(rec.Body.String(), cause) || strings.Contains(rec.Body.String(), "EOF") {
		t.Errorf("internal cause leaked into the response: %s", rec.Body.String())
	}
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d", rec.Code)
	}
}

// Decision 2 put every request through one process, so a panicking handler would otherwise take
// the whole cloud down with it.
func TestRecoverContainsAPanic(t *testing.T) {
	h := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}), WithRequestID, Recover(false))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil)) // must not panic out of here

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	var body errBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("panic response is not the contract error shape: %s", rec.Body.String())
	}
	if body.RequestID == "" {
		t.Error("a panic response with no request id is unreportable")
	}
	if strings.Contains(rec.Body.String(), "boom") {
		t.Error("panic value leaked to the caller")
	}
}

// A handler must be able to tell "authentication did not run" from "the caller is account empty
// string" — the latter would match every storage key prefix.
func TestPrincipalAbsenceIsDistinguishable(t *testing.T) {
	req := httptest.NewRequest("GET", "/x", nil)
	if _, ok := PrincipalFrom(req.Context()); ok {
		t.Error("an unauthenticated context reported a principal")
	}

	ctx := WithPrincipal(req.Context(), &commonv1.Principal{
		AccountId:    "000000000001",
		PrincipalArn: "arn:dariya:iam:hind-1:000000000001:user/root",
	})
	p, ok := PrincipalFrom(ctx)
	if !ok || p.GetAccountId() != "000000000001" {
		t.Errorf("principal round trip failed: %v %v", p, ok)
	}
}

func TestAccessLogRuns(t *testing.T) {
	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, r, http.StatusTeapot, map[string]string{"ok": "yes"})
	}), WithRequestID, AccessLog(discardLogger()))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))

	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want 418", rec.Code)
	}
}

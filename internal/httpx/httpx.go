// Package httpx is the HTTP plumbing every request at the edge passes through: a request id, a
// contract-shaped error body, panic containment, and one access log line.
//
// It deliberately knows nothing about signatures or policy. Authentication is the next layer out
// (internal/httpx/authn.go), and keeping the two apart is what lets the error rendering be tested
// without a database and the authentication be tested without a socket.
package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	commonv1 "dariyanws/gen/dariya/common/v1"
	"dariyanws/internal/apierr"
)

// RequestIDHeader is echoed on every response, success or failure. It is the only way a path
// through five services is debuggable (DESIGN.md Part II), so it is never omitted and never
// conditional.
const RequestIDHeader = "X-Dariya-Request-Id"

type ctxKey int

const (
	ctxKeyRequestID ctxKey = iota
	ctxKeyPrincipal
)

// NewRequestID mints an identifier. Sixteen random bytes: short enough to paste into a message,
// long enough that ids from different processes will not collide, and carrying no timestamp or
// hostname that would leak topology to a caller who only needs something to quote back.
func NewRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A failing CSPRNG is not survivable, but a request id is not worth killing a request for.
		// Fall back to a constant that is obviously wrong in a log rather than silently unique.
		return "req-entropy-failure"
	}
	return hex.EncodeToString(b[:])
}

// RequestID reads the id off a context. Empty when called outside a request, which callers should
// treat as a programming error rather than paper over.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(ctxKeyRequestID).(string)
	return id
}

func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKeyRequestID, id)
}

// ---------------------------------------------------------------------------
// Principal
// ---------------------------------------------------------------------------

// PrincipalFrom reads the authenticated caller off a context.
//
// The second return is false when authentication has not run, and a handler must treat that as a
// refusal rather than as an anonymous caller. Returning a zero Principal with no ok flag would
// make a missing authn middleware look exactly like account "" — which every storage key prefix
// would then happily match.
func PrincipalFrom(ctx context.Context) (*commonv1.Principal, bool) {
	p, ok := ctx.Value(ctxKeyPrincipal).(*commonv1.Principal)
	return p, ok
}

// WithPrincipal attaches a verified caller. Only the authn middleware may call it.
func WithPrincipal(ctx context.Context, p *commonv1.Principal) context.Context {
	return context.WithValue(ctx, ctxKeyPrincipal, p)
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

// WriteJSON renders a success body.
func WriteJSON(w http.ResponseWriter, r *http.Request, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		// The status line is already on the wire; nothing can be done for the caller. Log it so a
		// truncated response is not a mystery.
		slog.Error("could not encode response body",
			"request_id", RequestID(r.Context()), "error", err)
	}
}

// WriteError renders an error in the contract shape: {code, message, request_id}.
//
// `dev` decides whether Details are included. In production, saying precisely which check rejected
// a request describes the system to the one caller who should not be told (DESIGN.md decision 5).
func WriteError(w http.ResponseWriter, r *http.Request, err error, dev bool) {
	e := apierr.From(err)
	e.RequestID = RequestID(r.Context())

	// The cause never reaches the caller, but it is the only useful thing in the log.
	if e.Cause != nil {
		slog.Error("request failed",
			"request_id", e.RequestID, "code", e.Code, "error", e.Cause)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.HTTPStatus())

	body := struct {
		Code      string            `json:"code"`
		Message   string            `json:"message"`
		RequestID string            `json:"request_id"`
		Details   map[string]string `json:"details,omitempty"`
	}{Code: e.Code, Message: e.Message, RequestID: e.RequestID}
	if dev {
		body.Details = e.Details
	}

	if encErr := json.NewEncoder(w).Encode(body); encErr != nil {
		slog.Error("could not encode error body", "request_id", e.RequestID, "error", encErr)
	}
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

// Middleware is the standard wrapper shape, so the chain reads outermost-first at the call site.
type Middleware func(http.Handler) http.Handler

// Chain applies middleware so that Chain(h, a, b) runs a, then b, then h.
func Chain(h http.Handler, mw ...Middleware) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

// WithRequestID mints an id and puts it on the context and the response.
//
// A client-supplied id is NOT trusted or reused. It would be convenient for tracing and it lets a
// caller forge collisions or inject log content, so the front door mints its own and echoes the
// client's under a separate header if it ever needs to.
func WithRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := NewRequestID()
		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(withRequestID(r.Context(), id)))
	})
}

// Recover turns a panic into a 500 with a request id.
//
// A panicking handler otherwise kills the whole front door, which — given decision 2 put every
// request through one process — means one bad code path takes down the entire cloud.
func Recover(dev bool) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if v := recover(); v != nil {
					slog.Error("panic in handler",
						"request_id", RequestID(r.Context()),
						"panic", v,
						"stack", string(debug.Stack()))
					WriteError(w, r, apierr.Internal(nil, "internal failure"), dev)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// statusRecorder captures what a handler wrote, so the access log can report it.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK // written implicitly by the first Write
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// AccessLog emits one structured line per request.
//
// It logs the principal when authentication has already run, which is why it sits inside the authn
// middleware in the chain rather than outside it: a log line that cannot say who made the request
// is most of the way to useless.
func AccessLog(log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w}

			next.ServeHTTP(rec, r)

			attrs := []any{
				"request_id", RequestID(r.Context()),
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"bytes", rec.bytes,
				"duration_ms", float64(time.Since(start).Microseconds()) / 1000,
			}
			if p, ok := PrincipalFrom(r.Context()); ok {
				attrs = append(attrs, "account_id", p.GetAccountId(), "principal", p.GetPrincipalArn())
			}
			log.Info("request", attrs...)
		})
	}
}

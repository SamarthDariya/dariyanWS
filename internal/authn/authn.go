// Package authn is the front door's authentication layer: it turns a signed HTTP request into a
// verified Principal, or into one deliberately uninformative 403.
//
// It sits between internal/httpx (which knows nothing about credentials) and internal/control
// (which knows nothing about HTTP). Keeping the three apart is why this can be tested with a fake
// resolver and no database, and why the signing rules can be tested with neither.
//
// DESIGN.md decision 6 makes this layer authentication only. Authorisation is a separate call to
// IAM at M3, and the result travels onward as a capability token at M4.
package authn

import (
	"bytes"
	"context"
	"crypto/subtle"
	"io"
	"log/slog"
	"net/http"
	"time"

	commonv1 "dariyanws/gen/dariya/common/v1"
	"dariyanws/internal/apierr"
	"dariyanws/internal/control"
	"dariyanws/internal/httpx"
	"dariyanws/internal/session"
	"dariyanws/internal/signing"
)

// MaxBodyBytes caps what will be read in order to hash it.
//
// A signature covers the body, so the body must be buffered before the request can be
// authenticated — which means an unauthenticated caller controls an allocation. Six megabytes
// matches the synchronous payload limit AWS puts on Lambda, and the cap is enforced before the
// signature is checked because there is no way to check it first.
const MaxBodyBytes = 6 << 20

// KeyResolver looks up signing material. *control.AccountsServer implements it.
type KeyResolver interface {
	ResolveSigningKey(ctx context.Context, accessKeyID string) (*control.SigningKey, error)
}

// SessionResolver turns a console session cookie into a principal. *session.Manager satisfies it.
//
// Optional: nil means signature authentication only, which is every caller except a browser.
type SessionResolver interface {
	Resolve(ctx context.Context, token string) (*session.Session, error)
}

// ServiceFor names the service a request is scoped to, which is part of the signature.
//
// At M2 every route belongs to the control plane itself. At M5 this becomes the router: the
// service is decided by the path, and a signature scoped to `func` stops working on a `kyu` route.
type ServiceFor func(*http.Request) string

// Config is what the middleware needs.
type Config struct {
	Keys    KeyResolver
	Region  string
	Service ServiceFor

	// Sessions enables the second authentication scheme (DESIGN.md decision 12). Both schemes
	// resolve to the same Principal and everything downstream is identical — two ways to prove
	// who you are, one way to decide what you may do.
	Sessions SessionResolver

	// Dev turns on the Details field of error responses. Signing failures are otherwise a single
	// opaque 403, which is correct in production and an afternoon lost in development.
	Dev bool

	// Now is injected for tests. Defaults to time.Now.
	Now func() time.Time

	Log *slog.Logger
}

// Middleware verifies the signature on every request it wraps.
//
// # Why every failure looks the same
//
// An unknown access key id, a revoked key, a wrong secret and a mangled body all return the same
// code and the same message. Distinguishing them would turn credential stuffing into enumeration:
// a caller could learn which access key ids exist by watching the error change, and an access key
// id is half a credential.
//
// The real reason goes three places instead: the log always, the Details field under Dev, and
// never the production response.
func Middleware(cfg Config) httpx.Middleware {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Service == nil {
		panic("authn: Config.Service is required — the service is part of the signature")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, body, err := authenticate(r, cfg)
			if err != nil {
				httpx.WriteError(w, r, err, cfg.Dev)
				return
			}

			// The signature path consumed the body to hash it; hand the same bytes to the
			// handler. Doing it here rather than in the handler means no handler can read a body
			// the signature never covered. The session path returns nil and leaves r.Body alone.
			if body != nil {
				r.Body = io.NopCloser(bytes.NewReader(body))
				r.ContentLength = int64(len(body))
			}

			next.ServeHTTP(w, r.WithContext(httpx.WithPrincipal(r.Context(), principal)))
		})
	}
}

// denied is the single response every authentication failure produces.
func denied(failure, detail string) *apierr.Error {
	return &apierr.Error{
		Code:    apierr.CodeInvalidSig,
		Message: "the request signature is invalid, or the credentials are unknown",
		Details: map[string]string{"check": failure, "detail": detail},
	}
}

func authenticate(r *http.Request, cfg Config) (*commonv1.Principal, []byte, error) {
	requestID := httpx.RequestID(r.Context())

	// A signature wins when one is offered. Checking the header rather than falling back on
	// failure means a caller who signed badly gets a signature error, not a confusing "no
	// session" — and means a stale cookie cannot mask a broken signing client.
	if r.Header.Get("Authorization") != "" {
		return authenticateSignature(r, cfg, requestID)
	}

	if cfg.Sessions != nil {
		if cookie, err := r.Cookie(session.CookieName); err == nil && cookie.Value != "" {
			return authenticateSession(r, cfg, requestID, cookie.Value)
		}
	}

	// Safe to name precisely: it tells an unauthenticated caller only that this endpoint
	// requires authentication, which the 401 already says.
	return nil, nil, &apierr.Error{
		Code:    apierr.CodeInvalidSig,
		Message: "an Authorization header or a session cookie is required",
	}
}

// authenticateSession resolves a console cookie.
//
// Every failure renders as the same 401 the signature path produces, for the same reason: an
// attacker must not learn whether a session token exists.
func authenticateSession(r *http.Request, cfg Config, requestID, token string) (*commonv1.Principal, []byte, error) {
	s, err := cfg.Sessions.Resolve(r.Context(), token)
	if err != nil {
		cfg.Log.Warn("session authentication failed",
			"request_id", requestID, "check", "resolve_session", "error", err)
		return nil, nil, denied("unknown_or_expired_session", "see the server log")
	}

	// CSRF, on anything that changes state. SameSite=Strict is the primary defence and this is
	// the second: a cookie sent by a page the user did not open cannot also carry a header that
	// page has no way to read.
	if !isSafeMethod(r.Method) {
		presented := r.Header.Get(session.CSRFHeader)
		if presented == "" || subtle.ConstantTimeCompare([]byte(presented), []byte(s.CSRFToken)) != 1 {
			cfg.Log.Warn("session authentication failed",
				"request_id", requestID, "check", "csrf_token", "method", r.Method)
			return nil, nil, denied("missing_or_wrong_csrf_token",
				"a "+session.CSRFHeader+" header matching the one issued at sign-in is required")
		}
	}

	// The body is not buffered here. Only the signature path has to read it in order to hash it;
	// making the session path pay the same cost — and the same 6MB ceiling — would be copying a
	// constraint rather than a requirement.
	return &commonv1.Principal{
		AccountId:    s.AccountID,
		PrincipalArn: s.PrincipalARN,
	}, nil, nil
}

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func authenticateSignature(r *http.Request, cfg Config, requestID string) (*commonv1.Principal, []byte, error) {
	auth := r.Header.Get("Authorization")

	sig, err := signing.ParseAuthorization(auth)
	if err != nil {
		return nil, nil, logAndDeny(cfg, requestID, err)
	}

	// Read the body before verifying, because the signature covers it. MaxBytesReader caps an
	// allocation an unauthenticated caller would otherwise control.
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, MaxBodyBytes))
	if err != nil {
		return nil, nil, &apierr.Error{
			Code:    apierr.CodeValidation,
			Message: "request body could not be read, or exceeds the size limit",
		}
	}

	key, err := cfg.Keys.ResolveSigningKey(r.Context(), sig.Scope.AccessKeyID)
	if err != nil {
		// NotFound and a decryption failure are rendered identically on purpose. Only the log
		// learns which happened.
		cfg.Log.Warn("authentication failed",
			"request_id", requestID,
			"access_key_id", sig.Scope.AccessKeyID,
			"check", "resolve_signing_key",
			"error", err)
		return nil, nil, denied("unknown_or_unusable_credentials", "see the server log")
	}

	verifyErr := signing.Verify(signing.VerifyInput{
		Request:             signing.RequestFromHTTP(r, body),
		Signature:           sig,
		DateHeaderValue:     r.Header.Get(signing.DateHeader),
		ContentSHA256Header: r.Header.Get(signing.ContentSHA256Header),
		Secret:              key.Secret,
		Region:              cfg.Region,
		Service:             cfg.Service(r),
		Now:                 cfg.Now(),
	})
	if verifyErr != nil {
		return nil, nil, logAndDeny(cfg, requestID, verifyErr)
	}

	return &commonv1.Principal{
		AccountId:    key.AccountID,
		PrincipalArn: key.PrincipalARN,
	}, body, nil
}

func logAndDeny(cfg Config, requestID string, err error) *apierr.Error {
	failure, detail := "malformed_request", err.Error()
	if se, ok := err.(*signing.Error); ok {
		failure, detail = string(se.Failure), se.Detail
	}
	cfg.Log.Warn("authentication failed",
		"request_id", requestID, "check", failure, "detail", detail)
	return denied(failure, detail)
}

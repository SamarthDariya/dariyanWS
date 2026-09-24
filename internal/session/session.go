// Package session implements console sign-in: the second way to authenticate at the front door.
//
// DESIGN.md decision 12. A browser cannot hold an access key secret — it would sit in
// localStorage, in memory, and in reach of every XSS — so the console exchanges the secret once,
// at sign-in, for a session cookie it can hold safely.
//
// # What a session is, and what it is not
//
// It is not a new tier of credential. Anyone holding an access key pair can obtain a session, and
// a session grants exactly what that principal already had. It is an envelope around an existing
// credential that a browser can carry: httpOnly so script cannot read it, short-lived so a theft
// expires, and server-side so signing out actually signs out.
//
// The weakness is worth naming rather than discovering: sign-in takes the access key secret over
// the wire in a request body. That is the one moment it is transmitted rather than used to sign,
// and it is why the sign-in route is the only unauthenticated route in the system and needs a
// rate limit before this is ever exposed beyond localhost.
package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"dariyanws/internal/apierr"
	"dariyanws/internal/store"
)

const (
	// CookieName is the session cookie.
	CookieName = "dariya_session"

	// CSRFHeader must carry the token returned at sign-in, on every mutating request.
	CSRFHeader = "X-Dariya-Csrf"

	// DefaultTTL is how long a console session lasts. Twelve hours: long enough for a working
	// day, short enough that a forgotten laptop stops being a credential overnight.
	DefaultTTL = 12 * time.Hour

	tokenBytes = 32
)

var (
	ErrNoSession      = errors.New("session: no session")
	ErrExpired        = errors.New("session: expired")
	ErrBadCredentials = errors.New("session: unknown access key or wrong secret")
)

// Session is what a valid cookie resolves to.
type Session struct {
	AccountID    string
	PrincipalARN string
	CSRFToken    string
	ExpiresAt    time.Time
}

// SigningKeyResolver is the credential lookup sign-in verifies against. *control.AccountsServer
// satisfies it; the caching wrapper does too, which is deliberate — sign-in is exactly as
// entitled to the cache as signature verification is.
type SigningKeyResolver interface {
	ResolveSigningKey(ctx context.Context, accessKeyID string) (*SigningKey, error)
}

// SigningKey mirrors control.SigningKey. Declared here so this package does not depend on the
// control plane's types for two fields.
type SigningKey struct {
	AccountID    string
	PrincipalARN string
	Secret       []byte
}

// Manager creates, resolves and destroys sessions.
type Manager struct {
	store *store.Store
	keys  SigningKeyResolver
	ttl   time.Duration
	now   func() time.Time
}

func NewManager(st *store.Store, keys SigningKeyResolver, ttl time.Duration, now func() time.Time) *Manager {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if now == nil {
		now = time.Now
	}
	return &Manager{store: st, keys: keys, ttl: ttl, now: now}
}

// Credentials are what a person types into a sign-in form.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
}

// SignIn verifies an access key pair and issues a session.
//
// The returned token is the only copy: the database holds its hash. Losing it means the session
// is unreachable, which is the correct failure — the alternative is a server able to impersonate
// every signed-in user.
func (m *Manager) SignIn(ctx context.Context, cred Credentials) (token string, s *Session, err error) {
	if cred.AccessKeyID == "" || cred.SecretAccessKey == "" {
		return "", nil, apierr.Validation("an access key id and secret access key are required")
	}

	key, lookupErr := m.keys.ResolveSigningKey(ctx, cred.AccessKeyID)

	// An unknown key and a wrong secret produce the same error, after the same work. Returning
	// early on an unknown key would make sign-in a key-id oracle, timing included.
	var storedSecret []byte
	if lookupErr == nil && key != nil {
		storedSecret = key.Secret
	}
	ok := subtle.ConstantTimeCompare(storedSecret, []byte(cred.SecretAccessKey)) == 1
	if lookupErr != nil || !ok {
		return "", nil, ErrBadCredentials
	}

	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, apierr.Internal(err, "could not generate a session token")
	}
	csrf := make([]byte, tokenBytes)
	if _, err := rand.Read(csrf); err != nil {
		return "", nil, apierr.Internal(err, "could not generate a CSRF token")
	}

	token = base64.RawURLEncoding.EncodeToString(raw)
	csrfToken := base64.RawURLEncoding.EncodeToString(csrf)
	sum := sha256.Sum256([]byte(token))

	now := m.now()
	expires := now.Add(m.ttl)

	if _, err := m.store.Pool().Exec(ctx,
		`INSERT INTO sessions
		   (token_sha256, account_id, principal_arn, csrf_token, created_at_ms, expires_at_ms)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		sum[:], key.AccountID, key.PrincipalARN, csrfToken,
		now.UnixMilli(), expires.UnixMilli()); err != nil {
		return "", nil, apierr.Internal(err, "could not create the session")
	}

	return token, &Session{
		AccountID:    key.AccountID,
		PrincipalARN: key.PrincipalARN,
		CSRFToken:    csrfToken,
		ExpiresAt:    expires,
	}, nil
}

// Resolve turns a cookie value into a session.
func (m *Manager) Resolve(ctx context.Context, token string) (*Session, error) {
	if token == "" {
		return nil, ErrNoSession
	}
	sum := sha256.Sum256([]byte(token))

	var s Session
	var expiresMS int64
	err := m.store.Pool().QueryRow(ctx,
		`SELECT account_id, principal_arn, csrf_token, expires_at_ms
		   FROM sessions WHERE token_sha256 = $1`, sum[:]).
		Scan(&s.AccountID, &s.PrincipalARN, &s.CSRFToken, &expiresMS)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, apierr.Internal(err, "could not read the session")
	}

	s.ExpiresAt = time.UnixMilli(expiresMS)
	if m.now().After(s.ExpiresAt) {
		// Left in the table for the sweeper rather than deleted here: a read path that writes
		// turns every expired cookie into a write, which is how an expired-session storm becomes
		// a database problem.
		return nil, ErrExpired
	}
	return &s, nil
}

// SignOut destroys a session. Idempotent: signing out twice is the state the caller wanted.
func (m *Manager) SignOut(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	sum := sha256.Sum256([]byte(token))

	if _, err := m.store.Pool().Exec(ctx,
		`DELETE FROM sessions WHERE token_sha256 = $1`, sum[:]); err != nil {
		return apierr.Internal(err, "could not sign out")
	}
	return nil
}

// SweepExpired deletes sessions past their expiry. Called on a timer by the front door.
func (m *Manager) SweepExpired(ctx context.Context) (int64, error) {
	tag, err := m.store.Pool().Exec(ctx,
		`DELETE FROM sessions WHERE expires_at_ms < $1`, m.now().UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("session: sweep: %w", err)
	}
	return tag.RowsAffected(), nil
}

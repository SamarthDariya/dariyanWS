// Package capability mints and verifies the token that carries an authorization decision from the
// front door to the service that acts on it.
//
// This is DESIGN.md decision 6, the decision the project exists to demonstrate. The front door
// verifies a signature, asks IAM once, and on allow mints one of these; the service holds only
// the Ed25519 public key and verifies **offline**. No network call to anything in dariyanWS on
// the data path — which is what makes "kill the control plane, watch the data plane keep serving"
// a real demonstration rather than a claim.
//
// # Signing over the exact bytes
//
// The signature covers `capability_bytes` verbatim, and the verifier checks it BEFORE parsing
// them. Protobuf serialisation is not canonical: field ordering and varint encoding may legally
// differ between implementations and versions, so a verifier that re-encoded a parsed message
// could compute a different byte string than the signer did and reject a valid token. Given a Go
// signer and a C++ verifier, that is the single most likely cross-language failure in the system.
//
// # A warning about this API, deliberately left in place for one milestone
//
// Verify checks the signature and the expiry, and returns the Capability. It does NOT check that
// the capability matches the request being served — the caller must compare Action and
// ResourceARN itself. BREAK.md E4 predicts that this shape makes the wrong thing easy to write,
// and M4.3 exists to demonstrate it on purpose before M4.4 changes it. If you are reading this
// after M4.4 and the comment is still here, the fix did not land.
package capability

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	capabilityv1 "dariyanws/gen/dariya/capability/v1"
)

// DefaultTTL is the capability lifetime from decision 6.
//
// Thirty seconds, matching the credential and policy caches, so the system has one answer to
// "how long after a change can a stale decision still be acted on?" rather than three.
const DefaultTTL = 30 * time.Second

// Env vars. The front door needs a private key; a service needs only public ones.
const (
	EnvSigningKey = "DARIYA_TOKEN_SIGNING_KEY" // id:base64(seed)
	EnvPublicKeys = "DARIYA_TOKEN_PUBLIC_KEYS" // id:base64(pub),id:base64(pub)
)

var (
	ErrNoSuchKey    = errors.New("capability: unknown signing key id")
	ErrBadSignature = errors.New("capability: signature does not verify")
	ErrExpired      = errors.New("capability: token has expired")
	ErrMalformed    = errors.New("capability: token is malformed")
)

// Claims are what the front door asserts.
type Claims struct {
	AccountID       string // owner of the resource
	CallerAccountID string // who authenticated; differs only on cross-account access
	PrincipalARN    string
	Action          string
	ResourceARN     string
	RequestID       string
}

// Minter signs capabilities. The front door holds one; nothing else should.
type Minter struct {
	keyID string
	key   ed25519.PrivateKey
	ttl   time.Duration
	now   func() time.Time
}

// NewMinter builds a minter from a seed.
func NewMinter(keyID string, seed []byte, ttl time.Duration, now func() time.Time) (*Minter, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("capability: signing key must be %d bytes, got %d",
			ed25519.SeedSize, len(seed))
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if now == nil {
		now = time.Now
	}
	return &Minter{keyID: keyID, key: ed25519.NewKeyFromSeed(seed), ttl: ttl, now: now}, nil
}

// NewMinterFromEnv reads EnvSigningKey.
//
// A missing key is an error rather than a cue to generate one. A front door that invents a
// keypair on boot mints tokens no service will accept, and the failure appears later as every
// request being rejected by the data plane — a long way from the cause.
func NewMinterFromEnv(ttl time.Duration) (*Minter, error) {
	raw := os.Getenv(EnvSigningKey)
	if raw == "" {
		return nil, fmt.Errorf("capability: %s is not set (see `make dev-keys`)", EnvSigningKey)
	}
	id, seed, err := parseKeyEntry(raw)
	if err != nil {
		return nil, err
	}
	return NewMinter(id, seed, ttl, nil)
}

// PublicKey is what services need.
func (m *Minter) PublicKey() ed25519.PublicKey { return m.key.Public().(ed25519.PublicKey) }

func (m *Minter) KeyID() string { return m.keyID }

// Mint produces a signed capability for exactly one request.
func (m *Minter) Mint(c Claims) (*capabilityv1.SignedCapability, error) {
	now := m.now()

	cap := &capabilityv1.Capability{
		AccountId:       c.AccountID,
		CallerAccountId: c.CallerAccountID,
		PrincipalArn:    c.PrincipalARN,
		Action:          c.Action,
		ResourceArn:     c.ResourceARN,
		RequestId:       c.RequestID,
		IssuedAtUnixMs:  now.UnixMilli(),
		ExpiresAtUnixMs: now.Add(m.ttl).UnixMilli(),
	}
	if cap.CallerAccountId == "" {
		cap.CallerAccountId = cap.AccountId
	}

	// Deterministic marshalling is requested, but the signature still covers the produced bytes
	// rather than relying on it: Deterministic is a best effort within one implementation, not a
	// canonical form across them.
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(cap)
	if err != nil {
		return nil, fmt.Errorf("capability: marshal: %w", err)
	}

	return &capabilityv1.SignedCapability{
		CapabilityBytes: encoded,
		Signature:       ed25519.Sign(m.key, encoded),
		KeyId:           m.keyID,
	}, nil
}

// Verifier checks capabilities offline. A service holds one, built from public keys only.
type Verifier struct {
	keys map[string]ed25519.PublicKey
	now  func() time.Time

	// Skew tolerates a small clock difference between the front door and the service. Without
	// it, a service whose clock is a second behind rejects every token for its first second of
	// validity, which looks like an intermittent authorization bug.
	Skew time.Duration
}

func NewVerifier(keys map[string]ed25519.PublicKey, now func() time.Time) *Verifier {
	if now == nil {
		now = time.Now
	}
	return &Verifier{keys: keys, now: now, Skew: time.Second}
}

// NewVerifierFromEnv reads EnvPublicKeys.
func NewVerifierFromEnv() (*Verifier, error) {
	raw := os.Getenv(EnvPublicKeys)
	if raw == "" {
		return nil, fmt.Errorf("capability: %s is not set", EnvPublicKeys)
	}

	keys := map[string]ed25519.PublicKey{}
	for _, entry := range strings.Split(raw, ",") {
		id, material, err := parseKeyEntry(strings.TrimSpace(entry))
		if err != nil {
			return nil, err
		}
		if len(material) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("capability: public key %q is %d bytes, want %d",
				id, len(material), ed25519.PublicKeySize)
		}
		keys[id] = ed25519.PublicKey(material)
	}
	return NewVerifier(keys, nil), nil
}

// Verify checks the signature and the expiry, and returns what the token asserts.
//
// It does NOT check that the token matches the request being served. See the package comment:
// that omission is the subject of BREAK.md E4 and is deliberate for exactly one milestone.
func (v *Verifier) Verify(token *capabilityv1.SignedCapability) (*capabilityv1.Capability, error) {
	if token == nil || len(token.GetCapabilityBytes()) == 0 || len(token.GetSignature()) == 0 {
		return nil, ErrMalformed
	}

	key, ok := v.keys[token.GetKeyId()]
	if !ok {
		return nil, fmt.Errorf("%w: %q — it must stay configured until every token it signed has "+
			"expired", ErrNoSuchKey, token.GetKeyId())
	}

	// Signature first, over the bytes as received, before anything parses them. Parsing
	// attacker-controlled bytes before authenticating them is how a parser bug becomes a
	// vulnerability.
	if !ed25519.Verify(key, token.GetCapabilityBytes(), token.GetSignature()) {
		return nil, ErrBadSignature
	}

	cap := &capabilityv1.Capability{}
	if err := proto.Unmarshal(token.GetCapabilityBytes(), cap); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	if v.now().Add(-v.Skew).UnixMilli() > cap.GetExpiresAtUnixMs() {
		return nil, fmt.Errorf("%w: expired at %d", ErrExpired, cap.GetExpiresAtUnixMs())
	}

	return cap, nil
}

// GenerateKey makes a signing seed. For `make dev-keys` and tests.
func GenerateKey() (seed []byte, public ed25519.PublicKey, err error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	return priv.Seed(), pub, nil
}

func parseKeyEntry(entry string) (id string, material []byte, err error) {
	id, encoded, ok := strings.Cut(entry, ":")
	if !ok || id == "" {
		return "", nil, fmt.Errorf("capability: %q is not id:base64key", entry)
	}
	material, err = base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", nil, fmt.Errorf("capability: key %q: %w", id, err)
	}
	return id, material, nil
}

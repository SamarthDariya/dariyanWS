// Package secrets encrypts access key secrets at rest (DESIGN.md decision 10).
//
// Not hashing. Verifying a request signature means recomputing an HMAC, which needs the secret
// itself back, so the store must be reversible. The claim this buys is weaker than a password
// store's and is worth stating plainly: a database dump alone does not yield signing keys; a dump
// plus the master key does.
//
// A real KMS-alike — key hierarchy, rotation policy, audit trail — is a service in its own right
// and is not being smuggled in here. What this package does provide is the seam for one: every
// ciphertext records which master key produced it, so keys can be rotated with an overlap window
// rather than a flag day.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// EnvVar holds the keyring: comma-separated "id:base64key" entries, the first being the one new
// ciphertexts are written with. Every key listed stays available for decryption.
//
//	DARIYA_MASTER_KEYS=k2:<base64 32 bytes>,k1:<base64 32 bytes>
const EnvVar = "DARIYA_MASTER_KEYS"

// KeySize is AES-256.
const KeySize = 32

// Keyring holds the master keys. Safe for concurrent use; never mutated after construction.
type Keyring struct {
	keys    map[string]cipher.AEAD
	primary string
}

// NewKeyring builds a keyring from id -> raw key bytes. The primary id must be present.
func NewKeyring(keys map[string][]byte, primary string) (*Keyring, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("secrets: no master keys")
	}
	if _, ok := keys[primary]; !ok {
		return nil, fmt.Errorf("secrets: primary key %q is not in the keyring", primary)
	}

	kr := &Keyring{keys: make(map[string]cipher.AEAD, len(keys)), primary: primary}
	for id, raw := range keys {
		if len(raw) != KeySize {
			return nil, fmt.Errorf("secrets: key %q is %d bytes, want %d", id, len(raw), KeySize)
		}
		block, err := aes.NewCipher(raw)
		if err != nil {
			return nil, fmt.Errorf("secrets: key %q: %w", id, err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("secrets: key %q: %w", id, err)
		}
		kr.keys[id] = aead
	}
	return kr, nil
}

// NewKeyringFromEnv reads EnvVar.
//
// It is an error for the variable to be missing rather than a cue to generate a key. A process that
// invents its own master key on boot cannot decrypt anything it wrote last time, and the failure
// surfaces later as "all credentials are invalid" rather than here as "you did not configure a key".
func NewKeyringFromEnv() (*Keyring, error) {
	raw := os.Getenv(EnvVar)
	if raw == "" {
		return nil, fmt.Errorf("secrets: %s is not set (see `make dev-keys`)", EnvVar)
	}

	keys := map[string][]byte{}
	primary := ""
	for _, entry := range strings.Split(raw, ",") {
		id, b64, ok := strings.Cut(strings.TrimSpace(entry), ":")
		if !ok || id == "" {
			return nil, fmt.Errorf("secrets: %s entry %q is not id:base64key", EnvVar, entry)
		}
		key, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("secrets: %s entry %q: %w", EnvVar, id, err)
		}
		keys[id] = key
		if primary == "" {
			primary = id
		}
	}
	return NewKeyring(keys, primary)
}

// Sealed is a ciphertext together with everything needed to open it later.
type Sealed struct {
	Ciphertext []byte
	Nonce      []byte
	KeyID      string
}

// Seal encrypts with the primary key.
//
// `aad` is bound into the ciphertext without being stored: the access key id is passed here, so a
// ciphertext lifted out of one row and pasted into another fails to decrypt. Without it, swapping
// two rows' ciphertext columns silently swaps two customers' secrets.
func (k *Keyring) Seal(plaintext []byte, aad string) (Sealed, error) {
	aead := k.keys[k.primary]

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Sealed{}, fmt.Errorf("secrets: nonce: %w", err)
	}

	return Sealed{
		Ciphertext: aead.Seal(nil, nonce, plaintext, []byte(aad)),
		Nonce:      nonce,
		KeyID:      k.primary,
	}, nil
}

// Open decrypts. It fails if the key id is unknown, the nonce is wrong, the ciphertext was
// tampered with, or the aad does not match what was sealed.
func (k *Keyring) Open(s Sealed, aad string) ([]byte, error) {
	aead, ok := k.keys[s.KeyID]
	if !ok {
		return nil, fmt.Errorf("secrets: unknown master key %q — it must stay in %s until every "+
			"row it encrypted has been rewritten", s.KeyID, EnvVar)
	}
	out, err := aead.Open(nil, s.Nonce, s.Ciphertext, []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("secrets: decrypt: %w", err)
	}
	return out, nil
}

// PrimaryKeyID reports which key new ciphertexts are written with.
func (k *Keyring) PrimaryKeyID() string { return k.primary }

// GenerateKey makes a fresh master key. For `make dev-keys` and tests only.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

package secrets

import (
	"bytes"
	"testing"
)

// testKeyring returns the keyring and the raw key bytes, so a test can build a second keyring
// containing the same key — which is what rotation is.
func testKeyring(t *testing.T, ids ...string) (*Keyring, map[string][]byte) {
	t.Helper()
	keys := map[string][]byte{}
	for _, id := range ids {
		keys[id] = mustKey(t)
	}
	kr, err := NewKeyring(keys, ids[0])
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return kr, keys
}

func TestSealOpen(t *testing.T) {
	kr, _ := testKeyring(t, "k1")
	secret := []byte("s3cret-signing-material")

	sealed, err := kr.Seal(secret, "DARIYAKEYAAAA")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(sealed.Ciphertext, secret) {
		t.Fatal("plaintext is visible in the ciphertext")
	}

	got, err := kr.Open(sealed, "DARIYAKEYAAAA")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Errorf("got %q, want %q", got, secret)
	}
}

// The aad binding is what stops a ciphertext being lifted from one row into another. Without it,
// swapping two rows' ciphertext columns silently swaps two customers' secrets.
func TestOpenRejectsWrongAAD(t *testing.T) {
	kr, _ := testKeyring(t, "k1")
	sealed, err := kr.Seal([]byte("secret"), "DARIYAKEYAAAA")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := kr.Open(sealed, "DARIYAKEYBBBB"); err == nil {
		t.Fatal("ciphertext opened under a different access key id")
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	kr, _ := testKeyring(t, "k1")
	sealed, err := kr.Seal([]byte("secret"), "id")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	sealed.Ciphertext[0] ^= 0xff
	if _, err := kr.Open(sealed, "id"); err == nil {
		t.Fatal("tampered ciphertext opened")
	}
}

// Rotation: new writes use the primary, old ciphertexts keep opening under their recorded key.
func TestRotationKeepsOldCiphertextsReadable(t *testing.T) {
	old, oldKeys := testKeyring(t, "k1")
	sealed, err := old.Seal([]byte("written-under-k1"), "id")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	rotated, err := NewKeyring(map[string][]byte{
		"k1": oldKeys["k1"],
		"k2": mustKey(t),
	}, "k2")
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	if rotated.PrimaryKeyID() != "k2" {
		t.Errorf("primary = %s", rotated.PrimaryKeyID())
	}

	got, err := rotated.Open(sealed, "id")
	if err != nil {
		t.Fatalf("old ciphertext unreadable after rotation: %v", err)
	}
	if string(got) != "written-under-k1" {
		t.Errorf("got %q", got)
	}
}

func TestUnknownKeyIDIsAClearError(t *testing.T) {
	kr, _ := testKeyring(t, "k1")
	_, err := kr.Open(Sealed{Ciphertext: []byte("x"), Nonce: make([]byte, 12), KeyID: "gone"}, "id")
	if err == nil {
		t.Fatal("unknown key id accepted")
	}
}

// helpers -------------------------------------------------------------------

func mustKey(t *testing.T) []byte {
	t.Helper()
	k, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return k
}

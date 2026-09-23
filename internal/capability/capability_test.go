package capability

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	capabilityv1 "dariyanws/gen/dariya/capability/v1"
)

var testNow = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

func testClaims() Claims {
	return Claims{
		AccountID:    "000000000001",
		PrincipalARN: "arn:dariya:iam:hind-1:000000000001:user/root",
		Action:       "func:Invoke",
		ResourceARN:  "arn:dariya:func:hind-1:000000000001:function/a",
		RequestID:    "abc123",
	}
}

func testPair(t *testing.T) (*Minter, *Verifier) {
	t.Helper()

	seed, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	clock := func() time.Time { return testNow }

	m, err := NewMinter("k1", seed, DefaultTTL, clock)
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	return m, NewVerifier(map[string]ed25519.PublicKey{"k1": pub}, clock)
}

func TestMintVerifyRoundTrip(t *testing.T) {
	m, v := testPair(t)

	token, err := m.Mint(testClaims())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	got, err := v.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.GetAction() != "func:Invoke" ||
		got.GetResourceArn() != "arn:dariya:func:hind-1:000000000001:function/a" ||
		got.GetPrincipalArn() != "arn:dariya:iam:hind-1:000000000001:user/root" ||
		got.GetRequestId() != "abc123" {
		t.Errorf("claims did not round trip: %+v", got)
	}
	// caller_account_id defaults to the resource owner, so same-account access does not have to
	// set two fields that always agree.
	if got.GetCallerAccountId() != "000000000001" {
		t.Errorf("caller_account_id = %q", got.GetCallerAccountId())
	}
}

// The service holds only a public key. If a private key were needed to verify, every service
// repo would hold material that can mint tokens — which is the whole point of using Ed25519 here
// rather than another HMAC.
func TestVerifierNeedsOnlyThePublicKey(t *testing.T) {
	seed, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	m, err := NewMinter("k1", seed, DefaultTTL, func() time.Time { return testNow })
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}

	token, err := m.Mint(testClaims())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	v := NewVerifier(map[string]ed25519.PublicKey{"k1": pub}, func() time.Time { return testNow })
	if _, err := v.Verify(token); err != nil {
		t.Errorf("Verify with only a public key: %v", err)
	}
}

func TestTamperedCapabilityIsRejected(t *testing.T) {
	m, v := testPair(t)

	token, err := m.Mint(testClaims())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// Re-sign nothing; just rewrite the claim. This is the attack the signature exists to stop:
	// a service that trusted the bytes would now believe the caller may touch function/b.
	forged := &capabilityv1.Capability{}
	if err := proto.Unmarshal(token.GetCapabilityBytes(), forged); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	forged.ResourceArn = "arn:dariya:func:hind-1:000000000001:function/b"
	rewritten, err := proto.Marshal(forged)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	token.CapabilityBytes = rewritten

	if _, err := v.Verify(token); !errors.Is(err, ErrBadSignature) {
		t.Errorf("err = %v, want ErrBadSignature", err)
	}
}

func TestSignatureTamperingIsRejected(t *testing.T) {
	m, v := testPair(t)
	token, _ := m.Mint(testClaims())

	token.Signature[0] ^= 0xff
	if _, err := v.Verify(token); !errors.Is(err, ErrBadSignature) {
		t.Errorf("err = %v, want ErrBadSignature", err)
	}
}

// A token signed by a different front door must not verify. Otherwise anyone who can run the
// binary can mint capabilities for any account.
func TestForeignKeyIsRejected(t *testing.T) {
	_, v := testPair(t)

	otherSeed, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	other, err := NewMinter("k1", otherSeed, DefaultTTL, func() time.Time { return testNow })
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}

	token, _ := other.Mint(testClaims())
	if _, err := v.Verify(token); !errors.Is(err, ErrBadSignature) {
		t.Errorf("err = %v, want ErrBadSignature", err)
	}
}

func TestUnknownKeyID(t *testing.T) {
	m, v := testPair(t)
	token, _ := m.Mint(testClaims())
	token.KeyId = "rotated-away"

	if _, err := v.Verify(token); !errors.Is(err, ErrNoSuchKey) {
		t.Errorf("err = %v, want ErrNoSuchKey", err)
	}
}

// The TTL is the revocation bound decision 6 accepts. A token outliving it must stop working, or
// the bound is not a bound.
func TestExpiry(t *testing.T) {
	seed, pub, _ := GenerateKey()

	now := testNow
	clock := func() time.Time { return now }

	m, err := NewMinter("k1", seed, 30*time.Second, clock)
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	v := NewVerifier(map[string]ed25519.PublicKey{"k1": pub}, clock)

	token, _ := m.Mint(testClaims())

	now = testNow.Add(29 * time.Second)
	if _, err := v.Verify(token); err != nil {
		t.Fatalf("rejected inside the TTL: %v", err)
	}

	now = testNow.Add(35 * time.Second)
	if _, err := v.Verify(token); !errors.Is(err, ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}
}

// A service whose clock is a second behind must not reject every token for its first second of
// validity — that presents as an intermittent authorization bug with no pattern to it.
func TestClockSkewTolerance(t *testing.T) {
	seed, pub, _ := GenerateKey()

	minterNow := testNow
	m, _ := NewMinter("k1", seed, 30*time.Second, func() time.Time { return minterNow })

	// The service is half a second ahead, so the token looks marginally expired at the boundary.
	serviceNow := testNow.Add(30*time.Second + 500*time.Millisecond)
	v := NewVerifier(map[string]ed25519.PublicKey{"k1": pub}, func() time.Time { return serviceNow })

	token, _ := m.Mint(testClaims())
	if _, err := v.Verify(token); err != nil {
		t.Errorf("a half-second clock difference rejected a valid token: %v", err)
	}
}

func TestMalformedTokens(t *testing.T) {
	_, v := testPair(t)

	for name, token := range map[string]*capabilityv1.SignedCapability{
		"nil":          nil,
		"no bytes":     {Signature: []byte("x"), KeyId: "k1"},
		"no signature": {CapabilityBytes: []byte("x"), KeyId: "k1"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Verify(token); !errors.Is(err, ErrMalformed) {
				t.Errorf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

// The bytes are signed and carried verbatim rather than re-encoded, because protobuf output is
// not canonical across implementations. This pins the property the C++ verifier depends on.
func TestSignatureCoversTheTransmittedBytesVerbatim(t *testing.T) {
	m, v := testPair(t)
	token, _ := m.Mint(testClaims())

	parsed := &capabilityv1.Capability{}
	if err := proto.Unmarshal(token.GetCapabilityBytes(), parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// A verifier that re-encoded and checked the signature against THAT would be relying on
	// re-encoding being byte-identical. Even where it happens to be today, the token carries the
	// original bytes so it never has to be.
	reencoded, err := proto.Marshal(parsed)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := v.Verify(&capabilityv1.SignedCapability{
		CapabilityBytes: reencoded,
		Signature:       token.GetSignature(),
		KeyId:           token.GetKeyId(),
	}); err != nil {
		// Not a failure of this implementation — a demonstration that the property is not free.
		t.Logf("re-encoding produced different bytes (%v); this is exactly why the signature "+
			"covers the transmitted bytes", err)
	}

	// What must hold unconditionally: the token as transmitted verifies.
	if _, err := v.Verify(token); err != nil {
		t.Errorf("the transmitted token did not verify: %v", err)
	}
}

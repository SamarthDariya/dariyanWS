package control

import (
	"context"
	"strings"
	"testing"

	controlv1 "dariyanws/gen/dariya/control/v1"
	"dariyanws/internal/apierr"
)

func createTestAccount(t *testing.T, s *AccountsServer) string {
	t.Helper()
	resp, err := s.CreateAccount(context.Background(), &controlv1.CreateAccountRequest{Name: "t"})
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	return resp.GetAccount().GetAccountId()
}

func TestCreateAccessKey(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	acct := createTestAccount(t, s)

	resp, err := s.CreateAccessKey(ctx, &controlv1.CreateAccessKeyRequest{AccountId: acct})
	if err != nil {
		t.Fatalf("CreateAccessKey: %v", err)
	}
	key := resp.GetAccessKey()

	if !strings.HasPrefix(key.GetAccessKeyId(), accessKeyPrefix) {
		t.Errorf("access key id %q lacks the %s prefix that makes a leak greppable",
			key.GetAccessKeyId(), accessKeyPrefix)
	}
	if key.GetSecretAccessKey() == "" {
		t.Fatal("create did not return a secret")
	}
	if key.GetPrincipalArn() != "arn:dariya:iam:hind-1:"+acct+":user/root" {
		t.Errorf("default principal = %q", key.GetPrincipalArn())
	}

	// The secret must round-trip through encryption. This is the whole point of decision 10: a
	// hash would have made this impossible and signature verification along with it.
	got, err := s.ResolveSigningKey(ctx, key.GetAccessKeyId())
	if err != nil {
		t.Fatalf("ResolveSigningKey: %v", err)
	}
	if string(got.Secret) != key.GetSecretAccessKey() {
		t.Error("resolved secret does not match the one handed to the caller")
	}
	if got.AccountID != acct || got.PrincipalARN != key.GetPrincipalArn() {
		t.Errorf("resolved %+v, want account %s", got, acct)
	}
}

// The secret is shown once. A list must never leak it, and the field is left empty by construction
// rather than cleared afterwards, because a clear that gets forgotten is a credential dump.
func TestListAccessKeysNeverReturnsSecrets(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	acct := createTestAccount(t, s)

	for i := 0; i < 3; i++ {
		if _, err := s.CreateAccessKey(ctx, &controlv1.CreateAccessKeyRequest{AccountId: acct}); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}

	resp, err := s.ListAccessKeys(ctx, &controlv1.ListAccessKeysRequest{AccountId: acct})
	if err != nil {
		t.Fatalf("ListAccessKeys: %v", err)
	}
	if len(resp.GetAccessKeys()) != 3 {
		t.Fatalf("got %d keys, want 3", len(resp.GetAccessKeys()))
	}
	for _, k := range resp.GetAccessKeys() {
		if k.GetSecretAccessKey() != "" {
			t.Errorf("key %s leaked its secret in a list", k.GetAccessKeyId())
		}
	}
}

// Tenant isolation, at the one call that could breach it: account A must not be able to mint a
// credential that authenticates as a principal in account B.
func TestCreateAccessKeyRejectsForeignPrincipal(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	a := createTestAccount(t, s)
	b := createTestAccount(t, s)

	_, err := s.CreateAccessKey(ctx, &controlv1.CreateAccessKeyRequest{
		AccountId:    a,
		PrincipalArn: "arn:dariya:iam:hind-1:" + b + ":user/root",
	})
	if err == nil {
		t.Fatal("minted a credential for another account's principal")
	}
	if got := apierr.From(err).Code; got != apierr.CodeValidation {
		t.Errorf("code = %s, want %s", got, apierr.CodeValidation)
	}
}

func TestCreateAccessKeyRejectsUnknownAccount(t *testing.T) {
	s := newTestServer(t)
	_, err := s.CreateAccessKey(context.Background(),
		&controlv1.CreateAccessKeyRequest{AccountId: "000000000042"})
	if got := apierr.From(err).Code; got != apierr.CodeNotFound {
		t.Errorf("code = %s, want %s", got, apierr.CodeNotFound)
	}
}

// A replayed client_token cannot hand back the secret again — it was shown once and only the
// ciphertext survives. Returning a decrypted copy would turn "shown once" into "shown to anyone who
// replays the token", so this is a conflict rather than an idempotent replay.
func TestCreateAccessKeyReplayIsAConflict(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	acct := createTestAccount(t, s)

	req := &controlv1.CreateAccessKeyRequest{AccountId: acct, ClientToken: "tok-key-1"}
	if _, err := s.CreateAccessKey(ctx, req); err != nil {
		t.Fatalf("first: %v", err)
	}
	_, err := s.CreateAccessKey(ctx, req)
	if err == nil {
		t.Fatal("replay succeeded, and would have had to invent a secret to do it")
	}
	if got := apierr.From(err).Code; got != apierr.CodeIdempotencyMis {
		t.Errorf("code = %s, want %s", got, apierr.CodeIdempotencyMis)
	}

	// The rolled-back attempt must not have left a key behind.
	list, err := s.ListAccessKeys(ctx, &controlv1.ListAccessKeysRequest{AccountId: acct})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if n := len(list.GetAccessKeys()); n != 1 {
		t.Errorf("account has %d keys after a replayed create, want 1", n)
	}
}

// Deletion must be immediate: the signing path finds no row, so there is no state column it could
// forget to check.
func TestDeleteAccessKeyRevokesImmediately(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	acct := createTestAccount(t, s)

	created, err := s.CreateAccessKey(ctx, &controlv1.CreateAccessKeyRequest{AccountId: acct})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	id := created.GetAccessKey().GetAccessKeyId()

	if _, err := s.DeleteAccessKey(ctx, &controlv1.DeleteAccessKeyRequest{AccessKeyId: id}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.ResolveSigningKey(ctx, id); err == nil {
		t.Fatal("a deleted key still resolves to signing material")
	}

	// Deleting twice is a NotFound, not a silent success: a caller retrying a revocation deserves
	// to know the state it is in.
	_, err = s.DeleteAccessKey(ctx, &controlv1.DeleteAccessKeyRequest{AccessKeyId: id})
	if got := apierr.From(err).Code; got != apierr.CodeNotFound {
		t.Errorf("code = %s, want %s", got, apierr.CodeNotFound)
	}
}

// Two keys must never share a secret, and the ids must differ. A seeded or reused RNG here would be
// catastrophic and silent.
func TestAccessKeysAreDistinct(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	acct := createTestAccount(t, s)

	ids, secretsSeen := map[string]bool{}, map[string]bool{}
	for i := 0; i < 20; i++ {
		resp, err := s.CreateAccessKey(ctx, &controlv1.CreateAccessKeyRequest{AccountId: acct})
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		k := resp.GetAccessKey()
		if ids[k.GetAccessKeyId()] {
			t.Fatalf("duplicate access key id %s", k.GetAccessKeyId())
		}
		if secretsSeen[k.GetSecretAccessKey()] {
			t.Fatal("duplicate secret")
		}
		ids[k.GetAccessKeyId()] = true
		secretsSeen[k.GetSecretAccessKey()] = true
	}
}

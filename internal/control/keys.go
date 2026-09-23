package control

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	commonv1 "dariyanws/gen/dariya/common/v1"
	controlv1 "dariyanws/gen/dariya/control/v1"
	"dariyanws/internal/apierr"
	"dariyanws/internal/arn"
	"dariyanws/internal/page"
	"dariyanws/internal/secrets"
)

const (
	// accessKeyPrefix makes a key id obvious on sight in a log, a ticket or a git diff, which is
	// most of what makes a leaked credential findable.
	accessKeyPrefix = "DARIYAKEY"

	// accessKeyIDChars is base32's alphabet minus nothing: no 0/O or 1/I to confuse when a key id
	// is read aloud or retyped from a screenshot.
	accessKeyIDChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	accessKeyIDLen   = 16

	// secretBytes is the entropy behind the signing secret. 30 bytes encodes to 40 base64 chars,
	// matching the shape people expect from a cloud secret key.
	secretBytes = 30
)

// CreateAccessKey mints a long-lived credential for a principal in an account.
//
// The secret is returned exactly once, here, and is never retrievable again through any API. What
// is stored is the ciphertext (DESIGN.md decision 10) — reversible on purpose, because verifying a
// signature means recomputing an HMAC and that needs the secret back.
func (s *AccountsServer) CreateAccessKey(ctx context.Context, req *controlv1.CreateAccessKeyRequest) (*controlv1.CreateAccessKeyResponse, error) {
	if err := arn.ValidateAccountID(req.GetAccountId()); err != nil {
		return nil, apierr.Validation("account_id must be 12 digits")
	}
	// Existence is checked before anything is minted, so a typo'd account id cannot leave an
	// orphaned credential that authenticates as a tenant who does not exist.
	if _, err := s.getAccount(ctx, req.GetAccountId()); err != nil {
		return nil, err
	}

	principalARN, err := s.resolvePrincipalARN(req.GetAccountId(), req.GetPrincipalArn())
	if err != nil {
		return nil, err
	}

	keyID, err := newAccessKeyID()
	if err != nil {
		return nil, apierr.Internal(err, "could not allocate an access key id")
	}
	secret, err := newSecret()
	if err != nil {
		return nil, apierr.Internal(err, "could not generate a secret")
	}

	// The access key id is bound into the ciphertext as additional data, so a ciphertext moved
	// between rows stops decrypting instead of silently authenticating the wrong principal.
	sealed, err := s.keyring.Seal([]byte(secret), keyID)
	if err != nil {
		return nil, apierr.Internal(err, "could not encrypt the secret")
	}

	nowMS := s.now().UnixMilli()

	tx, err := s.store.Pool().Begin(ctx)
	if err != nil {
		return nil, apierr.Internal(err, "could not begin transaction")
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`INSERT INTO access_keys
		   (access_key_id, account_id, principal_arn, secret_ciphertext, secret_nonce,
		    master_key_id, state, created_at_ms)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		keyID, req.GetAccountId(), principalARN,
		sealed.Ciphertext, sealed.Nonce, sealed.KeyID,
		stateName(commonv1.ResourceState_RESOURCE_STATE_ACTIVE), nowMS); err != nil {
		return nil, apierr.Internal(err, "could not store the access key")
	}

	if token := req.GetClientToken(); token != "" {
		tag, err := tx.Exec(ctx,
			`INSERT INTO idempotency (operation, client_token, result_id, created_at_ms)
			 VALUES ('CreateAccessKey', $1, $2, $3) ON CONFLICT DO NOTHING`,
			token, keyID, nowMS)
		if err != nil {
			return nil, apierr.Internal(err, "could not record idempotency token")
		}
		if tag.RowsAffected() == 0 {
			// A retry. The original secret is gone — it was returned once and only the ciphertext
			// survives, and handing back a decrypted copy here would quietly turn "shown once"
			// into "shown to anyone who replays the token". So this is a conflict, not a replay.
			_ = tx.Rollback(ctx)
			return nil, &apierr.Error{
				Code: apierr.CodeIdempotencyMis,
				Message: "this client_token already created an access key; its secret was returned " +
					"once and cannot be returned again — create a new key",
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, apierr.Internal(err, "could not commit the access key")
	}

	return &controlv1.CreateAccessKeyResponse{AccessKey: &controlv1.AccessKey{
		AccessKeyId:     keyID,
		AccountId:       req.GetAccountId(),
		PrincipalArn:    principalARN,
		State:           commonv1.ResourceState_RESOURCE_STATE_ACTIVE,
		CreatedAtUnixMs: nowMS,
		SecretAccessKey: secret, // the only time this field is ever populated
	}}, nil
}

// ListAccessKeys never returns a secret. The field stays empty by construction rather than by being
// cleared afterwards, because a clear that is forgotten is a credential dump.
func (s *AccountsServer) ListAccessKeys(ctx context.Context, req *controlv1.ListAccessKeysRequest) (*controlv1.ListAccessKeysResponse, error) {
	if err := arn.ValidateAccountID(req.GetAccountId()); err != nil {
		return nil, apierr.Validation("account_id must be 12 digits")
	}
	limit, err := page.Limit(req.GetPage().GetMaxResults())
	if err != nil {
		return nil, err
	}
	after, err := page.Decode(req.GetPage().GetNextToken())
	if err != nil {
		return nil, err
	}

	rows, err := s.store.Pool().Query(ctx,
		`SELECT access_key_id, account_id, principal_arn, state, created_at_ms
		   FROM access_keys
		  WHERE account_id = $1 AND access_key_id > $2
		  ORDER BY access_key_id
		  LIMIT $3`, req.GetAccountId(), after, limit+1)
	if err != nil {
		return nil, apierr.Internal(err, "could not list access keys")
	}
	defer rows.Close()

	resp := &controlv1.ListAccessKeysResponse{Page: &commonv1.PageResponse{}}
	for rows.Next() {
		var k controlv1.AccessKey
		var state string
		if err := rows.Scan(&k.AccessKeyId, &k.AccountId, &k.PrincipalArn, &state, &k.CreatedAtUnixMs); err != nil {
			return nil, apierr.Internal(err, "could not scan access key")
		}
		k.State = parseState(state)
		resp.AccessKeys = append(resp.AccessKeys, &k)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.Internal(err, "could not read access keys")
	}

	if len(resp.AccessKeys) > limit {
		resp.AccessKeys = resp.AccessKeys[:limit]
		resp.Page.NextToken = page.Encode(resp.AccessKeys[limit-1].AccessKeyId)
	}
	return resp, nil
}

// DeleteAccessKey removes a credential outright rather than marking it inactive.
//
// Revocation of a long-lived key has to be immediate, and a state column that the signing path
// might forget to check is how a "revoked" key keeps working. The signing path looks the row up by
// primary key; no row means no credential.
func (s *AccountsServer) DeleteAccessKey(ctx context.Context, req *controlv1.DeleteAccessKeyRequest) (*controlv1.DeleteAccessKeyResponse, error) {
	if req.GetAccessKeyId() == "" {
		return nil, apierr.Validation("access_key_id is required")
	}
	tag, err := s.store.Pool().Exec(ctx,
		`DELETE FROM access_keys WHERE access_key_id = $1`, req.GetAccessKeyId())
	if err != nil {
		return nil, apierr.Internal(err, "could not delete the access key")
	}
	if tag.RowsAffected() == 0 {
		return nil, apierr.NotFound("no access key %s", req.GetAccessKeyId())
	}

	// Fired after the row is gone, never before: a cache dropped ahead of a delete that then
	// failed would leave the entry to be re-populated from the row that still exists.
	if s.onKeyDeleted != nil {
		s.onKeyDeleted(req.GetAccessKeyId())
	}
	return &controlv1.DeleteAccessKeyResponse{}, nil
}

// SigningKey is what the front door needs to verify a signature: who the caller is, and the secret
// to recompute their HMAC with.
type SigningKey struct {
	AccessKeyID  string
	AccountID    string
	PrincipalARN string
	Secret       []byte
}

// ResolveSigningKey is the hot-path lookup, called once per signed request at M2.
//
// It returns a NotFound for an unknown key id and a decryption failure as an internal error, and
// the caller must render both to the client as the same opaque InvalidSignature: telling an
// attacker whether an access key id exists turns credential stuffing into enumeration.
func (s *AccountsServer) ResolveSigningKey(ctx context.Context, accessKeyID string) (*SigningKey, error) {
	var (
		sealed       secrets.Sealed
		accountID    string
		principalARN string
	)
	err := s.store.Pool().QueryRow(ctx,
		`SELECT account_id, principal_arn, secret_ciphertext, secret_nonce, master_key_id
		   FROM access_keys WHERE access_key_id = $1`, accessKeyID).
		Scan(&accountID, &principalARN, &sealed.Ciphertext, &sealed.Nonce, &sealed.KeyID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apierr.NotFound("no access key %s", accessKeyID)
	}
	if err != nil {
		return nil, apierr.Internal(err, "could not read the access key")
	}

	secret, err := s.keyring.Open(sealed, accessKeyID)
	if err != nil {
		return nil, apierr.Internal(err, "could not decrypt the access key secret")
	}

	return &SigningKey{
		AccessKeyID:  accessKeyID,
		AccountID:    accountID,
		PrincipalARN: principalARN,
		Secret:       secret,
	}, nil
}

// resolvePrincipalARN defaults an empty principal to the account's root user and otherwise checks
// that the caller is not minting a credential that claims to belong to somebody else's account.
func (s *AccountsServer) resolvePrincipalARN(accountID, requested string) (string, error) {
	if requested == "" {
		return fmt.Sprintf("arn:dariya:iam:%s:%s:user/root", s.region, accountID), nil
	}

	a, err := arn.Parse(requested)
	if err != nil {
		return "", apierr.Validation("principal_arn is not a valid ARN: %v", err)
	}
	if a.Service != "iam" {
		return "", apierr.Validation("principal_arn must be an iam ARN, got service %q", a.Service)
	}
	// The check that makes account_id a boundary rather than a label.
	if a.Account != accountID {
		return "", apierr.Validation("principal_arn belongs to account %s, not %s", a.Account, accountID)
	}
	if a.Type != "user" && a.Type != "role" {
		return "", apierr.Validation("principal_arn must name a user or a role, got %q", a.Type)
	}
	return requested, nil
}

func newAccessKeyID() (string, error) {
	out := make([]byte, accessKeyIDLen)
	buf := make([]byte, accessKeyIDLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i, b := range buf {
		// len(accessKeyIDChars) is 32, a power of two, so masking is unbiased.
		out[i] = accessKeyIDChars[b&31]
	}
	return accessKeyPrefix + string(out), nil
}

func newSecret() (string, error) {
	buf := make([]byte, secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

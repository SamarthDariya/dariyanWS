// Package control implements the control plane for the only resources dariyanWS owns: accounts and
// the access keys that authenticate into them (DESIGN.md decision 1).
package control

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	commonv1 "dariyanws/gen/dariya/common/v1"
	controlv1 "dariyanws/gen/dariya/control/v1"
	"dariyanws/internal/apierr"
	"dariyanws/internal/arn"
	"dariyanws/internal/page"
	"dariyanws/internal/store"
)

// pgUniqueViolation is the SQLSTATE for a duplicate key. Compared as a code rather than by matching
// the error string, which is locale- and version-dependent.
const pgUniqueViolation = "23505"

// accountIDAttempts bounds the retry loop for a random account id collision.
//
// With a 12-digit space and a realistically small number of accounts, a collision is close to
// impossible; the loop exists because "close to impossible" is not "cannot", and an unbounded
// retry on a genuine bug is an infinite loop in a request handler.
const accountIDAttempts = 5

// Clock is injected so tests do not depend on wall time.
type Clock func() time.Time

// AccountsServer implements controlv1.AccountsServiceServer.
type AccountsServer struct {
	controlv1.UnimplementedAccountsServiceServer

	store *store.Store
	now   Clock

	// region is stamped into the principal ARNs this service mints. Pinned today (DESIGN.md
	// decision 4), a field rather than a constant so a second region is configuration.
	region string
}

func NewAccountsServer(st *store.Store, region string, now Clock) *AccountsServer {
	if now == nil {
		now = time.Now
	}
	return &AccountsServer{store: st, now: now, region: region}
}

// CreateAccount allocates a tenant.
//
// Idempotent on client_token: a client that times out and retries must not end up owning two
// accounts. The idempotency row and the account row are written in one transaction, so the retry
// either finds a complete pair or finds nothing at all.
func (s *AccountsServer) CreateAccount(ctx context.Context, req *controlv1.CreateAccountRequest) (*controlv1.CreateAccountResponse, error) {
	if err := validateName(req.GetName()); err != nil {
		return nil, err
	}

	nowMS := s.now().UnixMilli()

	for attempt := 0; attempt < accountIDAttempts; attempt++ {
		id, err := newAccountID()
		if err != nil {
			return nil, apierr.Internal(err, "could not allocate an account id")
		}

		acct, err := s.tryCreateAccount(ctx, id, req.GetName(), req.GetClientToken(), nowMS)
		switch {
		case err == nil:
			// Either the account just created, or — if client_token had been used before — the
			// account the first call created. Both are a successful CreateAccount.
			return &controlv1.CreateAccountResponse{Account: acct}, nil
		case isUniqueViolation(err):
			continue // account id collision, draw again
		default:
			return nil, err
		}
	}
	return nil, apierr.Internal(nil, "could not allocate an unused account id in %d attempts", accountIDAttempts)
}

// tryCreateAccount does one attempt.
//
// It returns a raw unique-violation error when the account id collides, so the caller can draw
// again; every other failure is already an *apierr.Error.
func (s *AccountsServer) tryCreateAccount(ctx context.Context, id, name, clientToken string, nowMS int64) (*controlv1.Account, error) {
	tx, err := s.store.Pool().Begin(ctx)
	if err != nil {
		return nil, apierr.Internal(err, "could not begin transaction")
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful Commit

	if _, err := tx.Exec(ctx,
		`INSERT INTO accounts (account_id, name, state, created_at_ms) VALUES ($1, $2, $3, $4)`,
		id, name, stateName(commonv1.ResourceState_RESOURCE_STATE_ACTIVE), nowMS); err != nil {
		return nil, err // may be a unique violation; caller decides
	}

	if clientToken != "" {
		tag, err := tx.Exec(ctx,
			`INSERT INTO idempotency (operation, client_token, result_id, created_at_ms)
			 VALUES ('CreateAccount', $1, $2, $3) ON CONFLICT DO NOTHING`,
			clientToken, id, nowMS)
		if err != nil {
			return nil, apierr.Internal(err, "could not record idempotency token")
		}
		if tag.RowsAffected() == 0 {
			// Someone used this token already. Roll back the account just inserted and return
			// theirs. The rollback is what makes the retry safe: the second account never existed.
			_ = tx.Rollback(ctx)

			var priorID string
			if err := s.store.Pool().QueryRow(ctx,
				`SELECT result_id FROM idempotency WHERE operation = 'CreateAccount' AND client_token = $1`,
				clientToken).Scan(&priorID); err != nil {
				return nil, apierr.Internal(err, "could not read idempotency token")
			}
			prior, err := s.getAccount(ctx, priorID)
			if err != nil {
				return nil, err
			}
			return prior, nil
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, apierr.Internal(err, "could not commit account")
	}

	return &controlv1.Account{
		AccountId:       id,
		Name:            name,
		State:           commonv1.ResourceState_RESOURCE_STATE_ACTIVE,
		CreatedAtUnixMs: nowMS,
	}, nil
}

func (s *AccountsServer) GetAccount(ctx context.Context, req *controlv1.GetAccountRequest) (*controlv1.GetAccountResponse, error) {
	if err := arn.ValidateAccountID(req.GetAccountId()); err != nil {
		return nil, apierr.Validation("account_id must be 12 digits")
	}
	acct, err := s.getAccount(ctx, req.GetAccountId())
	if err != nil {
		return nil, err
	}
	return &controlv1.GetAccountResponse{Account: acct}, nil
}

// ListAccounts is an operator view across tenants, not a tenant-facing call. It is listed here
// because the front door will never route it; it is reachable only to an operator principal.
func (s *AccountsServer) ListAccounts(ctx context.Context, req *controlv1.ListAccountsRequest) (*controlv1.ListAccountsResponse, error) {
	limit, err := page.Limit(req.GetPage().GetMaxResults())
	if err != nil {
		return nil, err
	}
	after, err := page.Decode(req.GetPage().GetNextToken())
	if err != nil {
		return nil, err
	}

	// One row more than asked for: if it comes back, there is a next page. Counting rows is cheaper
	// and more honest than a second COUNT query that can disagree with the page under concurrency.
	rows, err := s.store.Pool().Query(ctx,
		`SELECT account_id, name, state, created_at_ms
		   FROM accounts
		  WHERE account_id > $1
		  ORDER BY account_id
		  LIMIT $2`, after, limit+1)
	if err != nil {
		return nil, apierr.Internal(err, "could not list accounts")
	}
	defer rows.Close()

	resp := &controlv1.ListAccountsResponse{Page: &commonv1.PageResponse{}}
	for rows.Next() {
		var a controlv1.Account
		var state string
		if err := rows.Scan(&a.AccountId, &a.Name, &state, &a.CreatedAtUnixMs); err != nil {
			return nil, apierr.Internal(err, "could not scan account")
		}
		a.State = parseState(state)
		resp.Accounts = append(resp.Accounts, &a)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.Internal(err, "could not read accounts")
	}

	if len(resp.Accounts) > limit {
		resp.Accounts = resp.Accounts[:limit]
		resp.Page.NextToken = page.Encode(resp.Accounts[limit-1].AccountId)
	}
	return resp, nil
}

func (s *AccountsServer) getAccount(ctx context.Context, id string) (*controlv1.Account, error) {
	var a controlv1.Account
	var state string
	err := s.store.Pool().QueryRow(ctx,
		`SELECT account_id, name, state, created_at_ms FROM accounts WHERE account_id = $1`, id).
		Scan(&a.AccountId, &a.Name, &state, &a.CreatedAtUnixMs)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apierr.NotFound("no account %s", id)
	}
	if err != nil {
		return nil, apierr.Internal(err, "could not read account")
	}
	a.State = parseState(state)
	return &a, nil
}

// newAccountID draws twelve random decimal digits.
//
// Random rather than sequential on purpose: a sequential id tells every customer how many tenants
// exist and makes another tenant's id guessable, which matters because account ids appear in ARNs
// that get shared in support threads and resource policies.
func newAccountID() (string, error) {
	const digits = "0123456789"
	out := make([]byte, arn.AccountIDLen)
	for i := range out {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", err
		}
		out[i] = digits[n.Int64()]
	}
	return string(out), nil
}

func validateName(name string) error {
	switch {
	case name == "":
		return apierr.Validation("name is required")
	case len(name) > 64:
		return apierr.Validation("name must be at most 64 characters, got %d", len(name))
	default:
		return nil
	}
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation
}

func stateName(s commonv1.ResourceState) string { return s.String() }

func parseState(s string) commonv1.ResourceState {
	if v, ok := commonv1.ResourceState_value[s]; ok {
		return commonv1.ResourceState(v)
	}
	return commonv1.ResourceState_RESOURCE_STATE_UNSPECIFIED
}

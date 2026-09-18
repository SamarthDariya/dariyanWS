package control

import (
	"context"
	"testing"
	"time"

	commonv1 "dariyanws/gen/dariya/common/v1"
	controlv1 "dariyanws/gen/dariya/control/v1"
	"dariyanws/internal/apierr"
	"dariyanws/internal/arn"
	"dariyanws/internal/secrets"
	"dariyanws/internal/store"
)

const testRegion = "hind-1"

// fixedClock keeps created_at deterministic so tests assert on it rather than around it.
func fixedClock(ms int64) Clock {
	return func() time.Time { return time.UnixMilli(ms) }
}

// newTestServer gives each test an empty accounts table. Tests in this package do not run in
// parallel, so truncation is safe and is cheaper than namespacing every row.
func newTestServer(t *testing.T) *AccountsServer {
	t.Helper()
	st := store.OpenTest(t)
	if _, err := st.Pool().Exec(context.Background(),
		`TRUNCATE access_keys, accounts, idempotency`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return NewAccountsServer(st, testKeyring(t), testRegion, fixedClock(1_700_000_000_000))
}

func TestCreateAccount(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()

	resp, err := s.CreateAccount(ctx, &controlv1.CreateAccountRequest{Name: "samarth-dev"})
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	got := resp.GetAccount()

	if err := arn.ValidateAccountID(got.GetAccountId()); err != nil {
		t.Errorf("allocated a malformed account id %q: %v", got.GetAccountId(), err)
	}
	if got.GetName() != "samarth-dev" {
		t.Errorf("name = %q", got.GetName())
	}
	if got.GetState() != commonv1.ResourceState_RESOURCE_STATE_ACTIVE {
		t.Errorf("state = %v, want ACTIVE", got.GetState())
	}
	if got.GetCreatedAtUnixMs() != 1_700_000_000_000 {
		t.Errorf("created_at = %d", got.GetCreatedAtUnixMs())
	}

	// The response must match what a later read returns — a create that reports fields it did not
	// persist is the kind of bug that only shows up in the console a week later.
	read, err := s.GetAccount(ctx, &controlv1.GetAccountRequest{AccountId: got.GetAccountId()})
	if err != nil {
		t.Fatalf("GetAccount: %v", err)
	}
	if read.GetAccount().GetName() != got.GetName() ||
		read.GetAccount().GetCreatedAtUnixMs() != got.GetCreatedAtUnixMs() {
		t.Errorf("read back %+v, created %+v", read.GetAccount(), got)
	}
}

// The reason client_token exists: a client that times out and retries must not end up owning two
// tenants.
func TestCreateAccountIsIdempotent(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()

	req := &controlv1.CreateAccountRequest{Name: "retried", ClientToken: "tok-1"}
	first, err := s.CreateAccount(ctx, req)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := s.CreateAccount(ctx, req)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}

	if first.GetAccount().GetAccountId() != second.GetAccount().GetAccountId() {
		t.Fatalf("retry created a second account: %s then %s",
			first.GetAccount().GetAccountId(), second.GetAccount().GetAccountId())
	}

	// And the rolled-back attempt must have left nothing behind.
	list, err := s.ListAccounts(ctx, &controlv1.ListAccountsRequest{})
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if n := len(list.GetAccounts()); n != 1 {
		t.Errorf("accounts table has %d rows after an idempotent retry, want 1", n)
	}
}

func TestCreateAccountValidation(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()

	for _, name := range []string{"", string(make([]byte, 65))} {
		_, err := s.CreateAccount(ctx, &controlv1.CreateAccountRequest{Name: name})
		if err == nil {
			t.Fatalf("name %q accepted", name)
		}
		if got := apierr.From(err).Code; got != apierr.CodeValidation {
			t.Errorf("code = %s, want %s", got, apierr.CodeValidation)
		}
	}
}

func TestGetAccountNotFound(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()

	_, err := s.GetAccount(ctx, &controlv1.GetAccountRequest{AccountId: "000000000042"})
	if got := apierr.From(err).Code; got != apierr.CodeNotFound {
		t.Errorf("code = %s, want %s", got, apierr.CodeNotFound)
	}

	// A malformed id is a validation error, not a not-found: the caller made a different mistake
	// and telling them "no such account" sends them looking in the wrong place.
	_, err = s.GetAccount(ctx, &controlv1.GetAccountRequest{AccountId: "42"})
	if got := apierr.From(err).Code; got != apierr.CodeValidation {
		t.Errorf("code = %s, want %s", got, apierr.CodeValidation)
	}
}

func TestListAccountsPaginates(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()

	const total = 7
	created := map[string]bool{}
	for i := 0; i < total; i++ {
		resp, err := s.CreateAccount(ctx, &controlv1.CreateAccountRequest{Name: "acct"})
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		created[resp.GetAccount().GetAccountId()] = true
	}

	seen := map[string]bool{}
	token := ""
	for pages := 0; ; pages++ {
		if pages > total {
			t.Fatal("pagination did not terminate")
		}
		resp, err := s.ListAccounts(ctx, &controlv1.ListAccountsRequest{
			Page: &commonv1.PageRequest{MaxResults: 3, NextToken: token},
		})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if n := len(resp.GetAccounts()); n > 3 {
			t.Fatalf("page has %d accounts, over max_results", n)
		}
		for _, a := range resp.GetAccounts() {
			if seen[a.GetAccountId()] {
				t.Errorf("account %s returned on two pages", a.GetAccountId())
			}
			seen[a.GetAccountId()] = true
		}
		token = resp.GetPage().GetNextToken()
		if token == "" {
			break
		}
	}

	if len(seen) != total {
		t.Errorf("saw %d accounts across all pages, want %d", len(seen), total)
	}
	for id := range created {
		if !seen[id] {
			t.Errorf("account %s never appeared in a page", id)
		}
	}
}

// testKeyring gives each test a fresh master key. Rows do not survive between tests (the table is
// truncated), so there is nothing for a previous key to have encrypted.
func testKeyring(t *testing.T) *secrets.Keyring {
	t.Helper()
	key, err := secrets.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	kr, err := secrets.NewKeyring(map[string][]byte{"test": key}, "test")
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return kr
}

package store

import (
	"context"
	"testing"
)

func TestMigrateIsIdempotent(t *testing.T) {
	st := OpenTest(t) // already migrated once
	ctx := context.Background()

	// Running again must be a no-op, not an error. Every boot of the front door calls Migrate.
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}

	// Counted against the embedded set rather than a literal: a literal here means every new
	// migration breaks a test that has nothing to say about it.
	names, err := migrationNames()
	if err != nil {
		t.Fatalf("migrationNames: %v", err)
	}

	var n int
	if err := st.Pool().QueryRow(ctx,
		`SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if n != len(names) {
		t.Errorf("schema_migrations has %d rows, want %d", n, len(names))
	}
}

func TestSchemaShape(t *testing.T) {
	st := OpenTest(t)
	ctx := context.Background()

	for _, table := range []string{"accounts", "access_keys", "idempotency"} {
		var exists bool
		if err := st.Pool().QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables
			                WHERE table_schema = 'public' AND table_name = $1)`,
			table).Scan(&exists); err != nil {
			t.Fatalf("check %s: %v", table, err)
		}
		if !exists {
			t.Errorf("table %s missing", table)
		}
	}
}

// The account id is a tenant boundary before it is a column. The database enforces its shape so
// that a bug in one code path cannot write a row every other code path will mis-scope.
func TestAccountIDConstraint(t *testing.T) {
	st := OpenTest(t)
	ctx := context.Background()

	for _, bad := range []string{"1", "00000000000x", "0000000000012"} {
		_, err := st.Pool().Exec(ctx,
			`INSERT INTO accounts (account_id, name, state, created_at_ms) VALUES ($1,'t','ACTIVE',0)`,
			bad)
		if err == nil {
			// Clean up the row that should not exist, so the failure does not cascade.
			_, _ = st.Pool().Exec(ctx, `DELETE FROM accounts WHERE account_id = $1`, bad)
			t.Errorf("account_id %q was accepted, want rejected", bad)
		}
	}
}

// An access key must not be able to reference an account that does not exist. Without this, a key
// deleted-account pair becomes a credential authenticating as nobody.
func TestAccessKeyRequiresAccount(t *testing.T) {
	st := OpenTest(t)
	ctx := context.Background()

	_, err := st.Pool().Exec(ctx,
		`INSERT INTO access_keys
		   (access_key_id, account_id, principal_arn, secret_ciphertext, secret_nonce,
		    master_key_id, state, created_at_ms)
		 VALUES ('DARIYAKEYTEST','999999999999','arn:dariya:iam:hind-1:999999999999:user/x',
		         '\x00','\x00','k1','ACTIVE',0)`)
	if err == nil {
		_, _ = st.Pool().Exec(ctx, `DELETE FROM access_keys WHERE access_key_id = 'DARIYAKEYTEST'`)
		t.Fatal("access key for a nonexistent account was accepted, want foreign key violation")
	}
}

package store

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

// DefaultTestDSN points at the Postgres that `make region-up` boots. Port 55432, not 5432, because
// a local Postgres on the default port is common and the collision is confusing to debug.
const DefaultTestDSN = "postgres://dariya:dariya@localhost:55432/dariyanws?sslmode=disable"

// OpenTest connects to the local region's Postgres and applies migrations.
//
// It SKIPS rather than fails when nothing is listening, so `go test ./...` works on a machine with
// no Docker running. It does NOT skip on any other error: a database that is present but rejects
// the schema is a real failure, and swallowing that is how a broken migration reaches a commit.
func OpenTest(t *testing.T) *Store {
	t.Helper()

	dsn := os.Getenv("DARIYA_TEST_DSN")
	if dsn == "" {
		dsn = DefaultTestDSN
	}

	ctx := context.Background()
	st, err := Open(ctx, dsn)
	if err != nil {
		t.Skipf("no Postgres at %s (%v) — run `make region-up` to include integration tests", dsn, err)
	}
	t.Cleanup(st.Close)

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return st
}

// TruncateAll empties every table except the migration bookkeeping.
//
// Discovered from the catalogue rather than listed, because a hand-written list has to be edited
// in every test file each time a table is added — which is exactly how adding migration 0002
// broke six tests in a package that has nothing to do with policies. CASCADE is required now that
// tables reference each other, and is safe here because the statement covers every table anyway.
func TruncateAll(t *testing.T, st *Store) {
	t.Helper()
	ctx := context.Background()

	rows, err := st.Pool().Query(ctx,
		`SELECT tablename FROM pg_tables
		  WHERE schemaname = 'public' AND tablename <> 'schema_migrations'`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan table name: %v", err)
		}
		tables = append(tables, `"`+name+`"`)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("list tables: %v", err)
	}
	if len(tables) == 0 {
		return
	}

	if _, err := st.Pool().Exec(ctx,
		fmt.Sprintf("TRUNCATE %s CASCADE", strings.Join(tables, ", "))); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

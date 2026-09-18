package store

import (
	"context"
	"os"
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

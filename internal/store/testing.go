package store

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// DefaultTestDSN points at the Postgres that `make region-up` boots. Port 55432, not 5432, because
// a local Postgres on the default port is common and the collision is confusing to debug.
const DefaultTestDSN = "postgres://dariya:dariya@localhost:55432/dariyanws?sslmode=disable"

// OpenTest connects to the local region's Postgres and applies migrations, in a schema of this
// test binary's own.
//
// The schema isolation is not tidiness. `go test ./...` runs packages in parallel against one
// database, so before this, internal/iam truncating tables would delete accounts that
// internal/control was midway through using — which it did, as a flake that only appeared once
// there were enough packages to collide. Sharing a database between parallel test binaries is a
// race with a slow trigger.
//
// It SKIPS rather than fails when nothing is listening, so `go test ./...` works on a machine
// with no Docker running. It does NOT skip on any other error: a database that is present but
// rejects the schema is a real failure, and swallowing that is how a broken migration reaches a
// commit.
func OpenTest(t *testing.T) *Store {
	t.Helper()

	dsn := os.Getenv("DARIYA_TEST_DSN")
	if dsn == "" {
		dsn = DefaultTestDSN
	}
	ctx := context.Background()

	// First connection creates the schema; it has to happen outside the pool that will be
	// configured to use it, because a search_path pointing at a schema that does not exist yet
	// makes every subsequent statement fail in a confusing way.
	bootstrap, err := Open(ctx, dsn)
	if err != nil {
		t.Skipf("no Postgres at %s (%v) — run `make region-up` to include integration tests", dsn, err)
	}
	schema := testSchemaName()
	_, err = bootstrap.Pool().Exec(ctx, `CREATE SCHEMA IF NOT EXISTS `+quoteIdent(schema))
	bootstrap.Close()
	if err != nil {
		t.Fatalf("create schema %s: %v", schema, err)
	}

	st, err := Open(ctx, withSearchPath(dsn, schema))
	if err != nil {
		t.Fatalf("connect to schema %s: %v", schema, err)
	}
	t.Cleanup(st.Close)

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return st
}

// testSchemaName derives a name from the test binary, so each package gets its own and two runs
// of the same package reuse one rather than leaking schemas.
func testSchemaName() string {
	base := filepath.Base(os.Args[0]) // e.g. "control.test", or a temp name under `go test`
	base = strings.TrimSuffix(base, ".test")

	var b strings.Builder
	b.WriteString("test_")
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func withSearchPath(dsn, schema string) string {
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "search_path=" + url.QueryEscape(schema)
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

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
		  WHERE schemaname = current_schema() AND tablename <> 'schema_migrations'`)
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

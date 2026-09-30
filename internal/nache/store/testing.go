package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// OpenTest opens a database of its own for one test package, empty, and skips when the region's
// Postgres is not up. A database per package rather than per test: `go test ./...` runs packages
// in parallel, and the control plane's tests learned at M3 what sharing one does.
func OpenTest(t *testing.T, pkg string) *Store {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dsn := strings.Replace(DefaultDSN, "/nache?", "/nache_test_"+pkg+"?", 1)
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Skipf("no Postgres for nache (%v) — `make region-up`", err)
	}
	if _, err := s.pool.Exec(ctx, `TRUNCATE clusters`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

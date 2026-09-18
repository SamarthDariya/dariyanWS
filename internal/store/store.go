// Package store is the Postgres access layer for the two things dariyanWS owns: accounts and the
// credentials that prove membership of one.
//
// Migrations are embedded and applied at startup rather than by a separate tool. The region boots
// with one command (DESIGN.md Part III), and a schema step that has to be remembered separately is
// a step that gets forgotten in exactly the demo where it matters.
package store

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Store owns a connection pool. It is safe for concurrent use.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects and verifies the connection before returning, so a bad DSN fails at startup rather
// than at the first request.
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: parse dsn: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}

	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

// Pool exposes the underlying pool to the packages in this repo that hold queries. Deliberately not
// an interface: a repository abstraction over one database that will never be swapped is ceremony,
// and the thing worth isolating here is the SQL, which lives next to the code that owns each table.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Migrate applies every embedded migration that has not run yet, in filename order.
//
// Each migration runs inside its own transaction together with the row that records it, so a
// migration that fails halfway leaves neither the change nor the bookkeeping. Postgres has
// transactional DDL, which is what makes this three lines instead of a tool.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			name       TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}

	names, err := migrationNames()
	if err != nil {
		return err
	}

	for _, name := range names {
		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("store: read %s: %w", name, err)
		}

		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("store: begin %s: %w", name, err)
		}

		// ON CONFLICT DO NOTHING plus a zero rowcount is the "already applied" check. Doing it as
		// an insert rather than a prior SELECT means two processes migrating at once cannot both
		// decide the migration is pending — the second one blocks on the row lock and then sees
		// the conflict.
		tag, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations (name) VALUES ($1) ON CONFLICT DO NOTHING`, name)
		if err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("store: record %s: %w", name, err)
		}
		if tag.RowsAffected() == 0 {
			_ = tx.Rollback(ctx)
			continue // already applied
		}

		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("store: apply %s: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("store: commit %s: %w", name, err)
		}
	}
	return nil
}

func migrationNames() ([]string, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("store: read migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	// Filename order is apply order, which is why migrations are numbered.
	sort.Strings(names)
	return names, nil
}

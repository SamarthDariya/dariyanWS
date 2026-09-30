// Package store is nache's record of which cache clusters exist — the desired state the
// reconciler converges towards (DESIGN.md decision 13g).
//
// # Where a cluster's account comes from
//
// Decision 13i left one rule that trust in nache depends on: the account a node is attached to
// must be the account that asked for the cluster, and nothing else. A rule like that is kept by
// making it the only thing the types allow. Cluster's account is unexported, so no code outside
// this package can build a Cluster naming an arbitrary account; the only way one comes into
// existence is Create, which takes the verified capability itself rather than an account string;
// and every other Cluster is read back from rows Create wrote. The reconciler attaches a node to
// cluster.Account(), and has no other account in reach to attach it to.
package store

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	capabilityv1 "dariyanws/gen/dariya/capability/v1"
)

//go:embed schema.sql
var schema string

// DefaultDSN is the region's Postgres, database nache.
const DefaultDSN = "postgres://dariya:dariya@localhost:55432/nache?sslmode=disable"

// State is a cluster's lifecycle, as stored.
type State string

const (
	Creating State = "creating"
	Active   State = "active"
	Deleting State = "deleting"
)

var (
	ErrNotFound = errors.New("store: no such cluster")

	// ErrDeleting is a Create for a name whose previous cluster is still being torn down. The
	// name is not free until its node is gone, or the new cluster would inherit the old node.
	ErrDeleting = errors.New("store: a cluster with this name is being deleted")
)

// Node is one node as last observed, stored as JSON.
type Node struct {
	ID         string    `json:"id"`
	Status     string    `json:"status"`
	ObservedAt time.Time `json:"observed_at"`
}

// Cluster is one row.
type Cluster struct {
	account   string
	Name      string
	State     State
	Nodes     []Node
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Account is whose cluster this is. See the package comment for why it has no setter.
func (c *Cluster) Account() string { return c.account }

type Store struct {
	pool *pgxpool.Pool
}

// Open connects to nache's database, creating it first if the server does not have it yet.
func Open(ctx context.Context, dsn string) (*Store, error) {
	if err := ensureDatabase(ctx, dsn); err != nil {
		return nil, err
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("nache store: connect: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("nache store: ping: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("nache store: schema: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

// ensureDatabase creates the DSN's database through the server's maintenance database. The
// region's Postgres volume predates nache, so an init script would never run for it.
func ensureDatabase(ctx context.Context, dsn string) error {
	u, err := url.Parse(dsn)
	if err != nil {
		return fmt.Errorf("nache store: dsn: %w", err)
	}
	name := strings.TrimPrefix(u.Path, "/")
	if name == "" || strings.ContainsAny(name, `"; `) {
		return fmt.Errorf("nache store: dsn names no usable database: %q", name)
	}
	admin := *u
	admin.Path = "/postgres"

	conn, err := pgx.Connect(ctx, admin.String())
	if err != nil {
		return fmt.Errorf("nache store: connect to create database %s: %w", name, err)
	}
	defer conn.Close(ctx)

	_, err = conn.Exec(ctx, `CREATE DATABASE "`+name+`"`)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (pgErr.Code == "42P04" || pgErr.Code == "23505") {
		return nil // already exists; 23505 is two creates racing on the catalog
	}
	return err
}

// Create records a cluster for the capability's account, or returns the one already recorded.
//
// It takes the capability, not an account id, so the account is the one the front door
// authorized and servicekit verified — the same value, by construction, in every row.
func (s *Store) Create(ctx context.Context, cap *capabilityv1.Capability, name string) (*Cluster, bool, error) {
	account := cap.GetAccountId()
	if account == "" {
		return nil, false, errors.New("nache store: a capability with no account")
	}

	tag, err := s.pool.Exec(ctx,
		`INSERT INTO clusters (account_id, name, state) VALUES ($1, $2, 'creating')
		 ON CONFLICT (account_id, name) DO NOTHING`, account, name)
	if err != nil {
		return nil, false, err
	}
	c, err := s.get(ctx, account, name)
	if err != nil {
		return nil, false, err
	}
	created := tag.RowsAffected() == 1
	if !created && c.State == Deleting {
		return nil, false, ErrDeleting
	}
	return c, created, nil
}

// Get returns the caller's cluster by name.
func (s *Store) Get(ctx context.Context, cap *capabilityv1.Capability, name string) (*Cluster, error) {
	return s.get(ctx, cap.GetAccountId(), name)
}

// Count is how many clusters the capability's account has, for the quota.
func (s *Store) Count(ctx context.Context, cap *capabilityv1.Capability) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM clusters WHERE account_id = $1`,
		cap.GetAccountId()).Scan(&n)
	return n, err
}

// List returns the caller's clusters, by name.
func (s *Store) List(ctx context.Context, cap *capabilityv1.Capability) ([]*Cluster, error) {
	return s.query(ctx, `WHERE account_id = $1 ORDER BY name`, cap.GetAccountId())
}

// MarkDeleting moves a cluster to deleting. It never moves one back: deletion is one-way, and a
// reconciler pass that read the row a moment earlier cannot resurrect it (see SetObserved).
func (s *Store) MarkDeleting(ctx context.Context, cap *capabilityv1.Capability, name string) (*Cluster, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE clusters SET state = 'deleting', updated_at = now()
		 WHERE account_id = $1 AND name = $2`, cap.GetAccountId(), name)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.get(ctx, cap.GetAccountId(), name)
}

// All returns every cluster in every account. It is the reconciler's view, and the only call
// here that crosses accounts — which is why it takes no capability: the reconciler acts for
// nache, and nache serves every account.
func (s *Store) All(ctx context.Context) ([]*Cluster, error) {
	return s.query(ctx, `ORDER BY account_id, name`)
}

// SetObserved records what the reconciler saw, and promotes creating → active when asked to.
//
// Conditional on the state not being deleting. The reconciler reads a row, talks to chala for a
// while, and writes back; a DeleteCacheCluster landing in between must win, or a cluster the
// customer deleted would be written back to active by a pass that started before the delete.
func (s *Store) SetObserved(ctx context.Context, c *Cluster, nodes []Node, active bool) error {
	raw, err := json.Marshal(nodes)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`UPDATE clusters
		    SET nodes = $3,
		        state = CASE WHEN $4 THEN 'active' ELSE state END,
		        updated_at = now()
		  WHERE account_id = $1 AND name = $2 AND state <> 'deleting'`,
		c.account, c.Name, raw, active)
	return err
}

// Forget removes a deleting cluster's row, once its node is gone. Only a deleting one: a row in
// any other state is a cluster somebody wants.
func (s *Store) Forget(ctx context.Context, c *Cluster) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM clusters WHERE account_id = $1 AND name = $2 AND state = 'deleting'`,
		c.account, c.Name)
	return err
}

func (s *Store) get(ctx context.Context, account, name string) (*Cluster, error) {
	rows, err := s.query(ctx, `WHERE account_id = $1 AND name = $2`, account, name)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	return rows[0], nil
}

func (s *Store) query(ctx context.Context, where string, args ...any) ([]*Cluster, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT account_id, name, state, nodes, created_at, updated_at FROM clusters `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Cluster
	for rows.Next() {
		var (
			c   Cluster
			raw []byte
		)
		if err := rows.Scan(&c.account, &c.Name, &c.State, &raw, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &c.Nodes); err != nil {
			return nil, fmt.Errorf("nache store: nodes of %s/%s: %w", c.account, c.Name, err)
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

// Package ttlcache is the caching policy this system uses in front of the control-plane store.
//
// It exists because E2 (BREAK.md) measured a single Postgres lookup at 96.4% of everything the
// front door adds to a request, and because the same shape then appeared a second time for policy
// lookups at M3.3. The semantics below are subtle in security-relevant ways — which errors get
// cached, what happens when the cache is full, what a concurrent miss does — and two hand-written
// copies of them would eventually disagree. One implementation, two instantiations.
//
// # The rules, and the reasoning behind each
//
//   - **Negative results are cached.** Without it, an unauthenticated caller spraying unknown
//     identifiers reaches the database once per request, and the front door becomes a pump aimed
//     at its own control plane. Negatives get a shorter TTL, because a stale "no" is far less
//     dangerous than a stale "yes" and because someone who just created a thing should not wait.
//
//   - **Failures are never cached.** Only a caller-supplied predicate says which errors are
//     definitive. Caching a timeout turns a blip into an outage of the cache's own length.
//
//   - **Concurrent misses collapse into one load.** A cold cache under load would otherwise issue
//     one query per in-flight request — the stampede arriving in the exact moment the database is
//     least able to absorb it.
//
//   - **A full cache refuses to insert rather than evicting.** Since negative caching lets an
//     untrusted caller choose the keys, eviction would let sprayed keys push real entries out and
//     turn the cache into a cache-miss generator. Refusing degrades to the uncached path, which
//     is slow and correct.
//
// # What every user of this package accepts
//
// **A change made elsewhere takes up to the TTL to be seen here.** For credentials that means a
// revoked key keeps working; for policies it means a revoked permission keeps applying. Callers
// that can detect the change locally should call Invalidate, which makes it immediate on that
// process — but the TTL is the guarantee, and Invalidate is an optimisation on top of it.
package ttlcache

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
)

// Defaults. TTL matches the capability token lifetime in DESIGN.md decision 6 on purpose, so the
// whole system has one answer to "how long after a change can the old answer still be used?".
const (
	DefaultTTL         = 30 * time.Second
	DefaultNegativeTTL = 5 * time.Second
	DefaultMaxEntries  = 10_000
)

// Options configure a Cache. Zero values take the defaults.
type Options struct {
	TTL         time.Duration
	NegativeTTL time.Duration
	MaxEntries  int
	Now         func() time.Time

	// IsNegative reports whether an error is a definitive "no such thing" worth caching, as
	// opposed to a transient failure that must not be. Nil means no error is ever cached, which
	// is the safe default for a caller that has not thought about it.
	IsNegative func(error) bool
}

// Loader produces the value for a key on a miss.
type Loader[V any] func(ctx context.Context, key string) (V, error)

// Cache is safe for concurrent use.
type Cache[V any] struct {
	load Loader[V]

	ttl         time.Duration
	negativeTTL time.Duration
	maxEntries  int
	now         func() time.Time
	isNegative  func(error) bool

	group singleflight.Group

	mu      sync.RWMutex
	entries map[string]entry[V]

	hits      atomic.Uint64
	misses    atomic.Uint64
	negatives atomic.Uint64
	expired   atomic.Uint64
	refusals  atomic.Uint64
}

type entry[V any] struct {
	value     V
	err       error
	expiresAt time.Time
}

func New[V any](load Loader[V], opts Options) *Cache[V] {
	if opts.TTL <= 0 {
		opts.TTL = DefaultTTL
	}
	if opts.NegativeTTL <= 0 {
		opts.NegativeTTL = DefaultNegativeTTL
	}
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = DefaultMaxEntries
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.IsNegative == nil {
		opts.IsNegative = func(error) bool { return false }
	}

	return &Cache[V]{
		load:        load,
		ttl:         opts.TTL,
		negativeTTL: opts.NegativeTTL,
		maxEntries:  opts.MaxEntries,
		now:         opts.Now,
		isNegative:  opts.IsNegative,
		entries:     make(map[string]entry[V]),
	}
}

// Get answers from cache when it can, and otherwise loads exactly once per key.
func (c *Cache[V]) Get(ctx context.Context, key string) (V, error) {
	if e, ok := c.lookup(key); ok {
		c.hits.Add(1)
		return e.value, e.err
	}
	c.misses.Add(1)

	result, err, _ := c.group.Do(key, func() (any, error) {
		value, err := c.load(ctx, key)

		switch {
		case err == nil:
			c.store(key, entry[V]{value: value, expiresAt: c.now().Add(c.ttl)})
		case c.isNegative(err):
			c.negatives.Add(1)
			c.store(key, entry[V]{err: err, expiresAt: c.now().Add(c.negativeTTL)})
		}
		return value, err
	})

	if err != nil {
		var zero V
		return zero, err
	}
	value, _ := result.(V)
	return value, nil
}

func (c *Cache[V]) lookup(key string) (entry[V], bool) {
	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok || !c.now().Before(e.expiresAt) {
		return entry[V]{}, false
	}
	return e, true
}

func (c *Cache[V]) store(key string, e entry[V]) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.maxEntries {
		c.sweepExpiredLocked()
	}
	if len(c.entries) >= c.maxEntries {
		c.refusals.Add(1)
		return
	}
	c.entries[key] = e
}

func (c *Cache[V]) sweepExpiredLocked() {
	now := c.now()
	for key, e := range c.entries {
		if !now.Before(e.expiresAt) {
			delete(c.entries, key)
			c.expired.Add(1)
		}
	}
}

// Invalidate drops one key. It makes a change immediate on the process that made it; the TTL
// remains the guarantee for every other process.
func (c *Cache[V]) Invalidate(key string) {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

// Stats is a snapshot, for logs and for benchmarks.
type Stats struct {
	Hits      uint64
	Misses    uint64
	Negatives uint64
	Expired   uint64
	Refusals  uint64
	Entries   int
}

func (c *Cache[V]) Stats() Stats {
	c.mu.RLock()
	entries := len(c.entries)
	c.mu.RUnlock()

	return Stats{
		Hits:      c.hits.Load(),
		Misses:    c.misses.Load(),
		Negatives: c.negatives.Load(),
		Expired:   c.expired.Load(),
		Refusals:  c.refusals.Load(),
		Entries:   entries,
	}
}

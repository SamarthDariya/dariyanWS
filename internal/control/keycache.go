package control

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"dariyanws/internal/apierr"
)

// CachingResolver caches access-key lookups in front of Postgres.
//
// E2 (BREAK.md) measured the lookup at 165µs and **96.4% of everything the front door adds** to a
// request, with the pool becoming the concurrency ceiling: throughput peaked at 8 connections —
// exactly the pool size — and then went backwards. This is the fix that measurement chose. It was
// deliberately not built before the number existed, because a cache added on suspicion is a cache
// whose value nobody can state.
//
// # What it costs
//
// **A revoked credential keeps working for up to the TTL.** That is a real weakening, not a
// refactor, and the test that asserted immediate revocation had to be rewritten to assert a
// bounded window instead. It is the same trade decision 6 already accepted for capability tokens,
// bounded the same way and, deliberately, by the same duration — so the system has one revocation
// story ("up to 30 seconds") rather than two.
//
// # Negative caching is not optional here
//
// Without it, an attacker spraying unknown access key ids reaches Postgres once per request and
// the front door becomes a pump aimed at its own control plane. Misses are therefore cached too,
// for a shorter window, because a negative answer becoming stale is far less dangerous than a
// positive one — and a caller who has just created a credential should not wait 30s for it.
type CachingResolver struct {
	inner KeyResolver

	ttl         time.Duration
	negativeTTL time.Duration
	maxEntries  int

	now   func() time.Time
	group singleflight.Group

	mu      sync.RWMutex
	entries map[string]cacheEntry

	hits      atomic.Uint64
	misses    atomic.Uint64
	negatives atomic.Uint64
	evictions atomic.Uint64
	refusals  atomic.Uint64
}

type cacheEntry struct {
	key       *SigningKey
	err       error // set for a cached negative
	expiresAt time.Time
}

// KeyResolver is what CachingResolver wraps. *AccountsServer satisfies it.
type KeyResolver interface {
	ResolveSigningKey(ctx context.Context, accessKeyID string) (*SigningKey, error)
}

// Defaults.
//
// DefaultTTL matches the capability token lifetime in decision 6 on purpose: one number to reason
// about when asking "how long after a revocation can this still be used?".
const (
	DefaultTTL         = 30 * time.Second
	DefaultNegativeTTL = 5 * time.Second
	DefaultMaxEntries  = 10_000
)

// CacheOptions configure a CachingResolver. Zero values take the defaults.
type CacheOptions struct {
	TTL         time.Duration
	NegativeTTL time.Duration

	// MaxEntries bounds memory. It matters because negative caching means an unauthenticated
	// caller chooses the keys: without a cap, spraying random access key ids is a memory leak
	// with extra steps.
	MaxEntries int

	Now func() time.Time
}

func NewCachingResolver(inner KeyResolver, opts CacheOptions) *CachingResolver {
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
	return &CachingResolver{
		inner:       inner,
		ttl:         opts.TTL,
		negativeTTL: opts.NegativeTTL,
		maxEntries:  opts.MaxEntries,
		now:         opts.Now,
		entries:     make(map[string]cacheEntry),
	}
}

// ResolveSigningKey answers from cache when it can.
func (c *CachingResolver) ResolveSigningKey(ctx context.Context, accessKeyID string) (*SigningKey, error) {
	if entry, ok := c.lookup(accessKeyID); ok {
		c.hits.Add(1)
		return entry.key, entry.err
	}
	c.misses.Add(1)

	// One query per key id, however many requests are waiting on it. Without this, a cold start
	// under load sends one query per in-flight request — which is precisely the stampede the
	// cache exists to prevent, arriving in the one moment the database is least able to take it.
	result, err, _ := c.group.Do(accessKeyID, func() (any, error) {
		key, err := c.inner.ResolveSigningKey(ctx, accessKeyID)

		switch {
		case err == nil:
			c.store(accessKeyID, cacheEntry{key: key, expiresAt: c.now().Add(c.ttl)})

		case isNotFound(err):
			// Only a definitive "no such key" is cached. A timeout or a connection failure must
			// not be: caching an outage turns a blip into an outage of its own length.
			c.negatives.Add(1)
			c.store(accessKeyID, cacheEntry{err: err, expiresAt: c.now().Add(c.negativeTTL)})
		}
		return key, err
	})

	if err != nil {
		return nil, err
	}
	key, _ := result.(*SigningKey)
	return key, nil
}

func (c *CachingResolver) lookup(accessKeyID string) (cacheEntry, bool) {
	c.mu.RLock()
	entry, ok := c.entries[accessKeyID]
	c.mu.RUnlock()

	if !ok || !c.now().Before(entry.expiresAt) {
		return cacheEntry{}, false
	}
	return entry, true
}

func (c *CachingResolver) store(accessKeyID string, entry cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.maxEntries {
		c.sweepExpiredLocked()
	}
	if len(c.entries) >= c.maxEntries {
		// Full of live entries. Refusing to cache degrades to the uncached behaviour, which is
		// slow but correct; evicting someone else's live entry to make room would let an attacker
		// spraying key ids push real credentials out and turn a cache into a cache-miss generator.
		c.refusals.Add(1)
		return
	}
	c.entries[accessKeyID] = entry
}

func (c *CachingResolver) sweepExpiredLocked() {
	now := c.now()
	for id, entry := range c.entries {
		if !now.Before(entry.expiresAt) {
			delete(c.entries, id)
			c.evictions.Add(1)
		}
	}
}

// Invalidate drops an entry. DeleteAccessKey calls it, which makes revocation immediate on the
// process that served the delete — the TTL is the bound for *other* front doors, not for this one.
// With one front door today it means revocation is in fact immediate; the TTL is what the story
// degrades to when there are several.
func (c *CachingResolver) Invalidate(accessKeyID string) {
	c.mu.Lock()
	delete(c.entries, accessKeyID)
	c.mu.Unlock()
}

// CacheStats is a snapshot, for logs and for E2b.
type CacheStats struct {
	Hits      uint64
	Misses    uint64
	Negatives uint64
	Evictions uint64
	Refusals  uint64
	Entries   int
}

func (c *CachingResolver) Stats() CacheStats {
	c.mu.RLock()
	entries := len(c.entries)
	c.mu.RUnlock()

	return CacheStats{
		Hits:      c.hits.Load(),
		Misses:    c.misses.Load(),
		Negatives: c.negatives.Load(),
		Evictions: c.evictions.Load(),
		Refusals:  c.refusals.Load(),
		Entries:   entries,
	}
}

func isNotFound(err error) bool {
	var e *apierr.Error
	return errors.As(err, &e) && e.Code == apierr.CodeNotFound
}

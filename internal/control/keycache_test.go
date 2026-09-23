package control

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dariyanws/internal/apierr"
)

// countingResolver stands in for Postgres and counts how often it was actually consulted, which
// is the only thing a cache test is really about.
type countingResolver struct {
	calls atomic.Int64
	key   *SigningKey
	err   error
	delay time.Duration
}

func (c *countingResolver) ResolveSigningKey(context.Context, string) (*SigningKey, error) {
	c.calls.Add(1)
	if c.delay > 0 {
		time.Sleep(c.delay)
	}
	return c.key, c.err
}

func testKey() *SigningKey {
	return &SigningKey{
		AccessKeyID:  "DARIYAKEYAAAA",
		AccountID:    "000000000001",
		PrincipalARN: "arn:dariya:iam:hind-1:000000000001:user/root",
		Secret:       []byte("secret"),
	}
}

func TestCacheServesRepeatLookupsWithoutTheDatabase(t *testing.T) {
	inner := &countingResolver{key: testKey()}
	c := NewCachingResolver(inner, CacheOptions{})

	for i := 0; i < 100; i++ {
		key, err := c.ResolveSigningKey(context.Background(), "DARIYAKEYAAAA")
		if err != nil {
			t.Fatalf("lookup %d: %v", i, err)
		}
		if key.AccountID != "000000000001" {
			t.Fatalf("wrong key: %+v", key)
		}
	}

	if got := inner.calls.Load(); got != 1 {
		t.Errorf("database consulted %d times for 100 lookups, want 1", got)
	}
	if s := c.Stats(); s.Hits != 99 || s.Misses != 1 {
		t.Errorf("stats = %+v", s)
	}
}

func TestCacheExpires(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	inner := &countingResolver{key: testKey()}
	c := NewCachingResolver(inner, CacheOptions{TTL: 30 * time.Second, Now: clock})

	ctx := context.Background()
	mustResolve(t, c, ctx)
	now = now.Add(29 * time.Second)
	mustResolve(t, c, ctx)
	if got := inner.calls.Load(); got != 1 {
		t.Fatalf("database consulted %d times inside the TTL, want 1", got)
	}

	now = now.Add(2 * time.Second) // past 30s
	mustResolve(t, c, ctx)
	if got := inner.calls.Load(); got != 2 {
		t.Errorf("database consulted %d times after expiry, want 2", got)
	}
}

// The cost of the cache, asserted rather than only documented: a revoked credential keeps working
// until the entry expires, unless something invalidates it.
func TestRevocationIsBoundedByTheTTL(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	inner := &countingResolver{key: testKey()}
	c := NewCachingResolver(inner, CacheOptions{TTL: 30 * time.Second, Now: clock})
	ctx := context.Background()

	mustResolve(t, c, ctx)

	// The row is deleted, but nothing invalidated the cache — another front door's delete.
	inner.key = nil
	inner.err = apierr.NotFound("no access key")

	if _, err := c.ResolveSigningKey(ctx, "DARIYAKEYAAAA"); err != nil {
		t.Fatal("expected the revoked credential to still work inside the TTL; that is the " +
			"accepted cost, and if it has stopped being true the comment in keycache.go is wrong")
	}

	now = now.Add(31 * time.Second)
	if _, err := c.ResolveSigningKey(ctx, "DARIYAKEYAAAA"); err == nil {
		t.Error("a revoked credential still resolved after the TTL")
	}
}

// Invalidate is what keeps revocation immediate on the process that served the delete.
func TestInvalidateIsImmediate(t *testing.T) {
	inner := &countingResolver{key: testKey()}
	c := NewCachingResolver(inner, CacheOptions{})
	ctx := context.Background()

	mustResolve(t, c, ctx)
	inner.key = nil
	inner.err = apierr.NotFound("no access key")

	c.Invalidate("DARIYAKEYAAAA")

	if _, err := c.ResolveSigningKey(ctx, "DARIYAKEYAAAA"); err == nil {
		t.Error("an invalidated credential still resolved")
	}
}

// Without negative caching, spraying unknown key ids reaches Postgres once per request and the
// front door becomes a pump aimed at its own control plane.
func TestUnknownKeysAreCachedToo(t *testing.T) {
	inner := &countingResolver{err: apierr.NotFound("no access key")}
	c := NewCachingResolver(inner, CacheOptions{})
	ctx := context.Background()

	for i := 0; i < 50; i++ {
		if _, err := c.ResolveSigningKey(ctx, "DARIYAKEYNOPE"); err == nil {
			t.Fatal("an unknown key resolved")
		}
	}
	if got := inner.calls.Load(); got != 1 {
		t.Errorf("database consulted %d times for 50 unknown-key lookups, want 1", got)
	}
}

// Caching an outage would turn a blip into an outage of the cache's own length.
func TestTransientFailuresAreNotCached(t *testing.T) {
	inner := &countingResolver{err: apierr.Internal(errors.New("connection refused"), "db down")}
	c := NewCachingResolver(inner, CacheOptions{})
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if _, err := c.ResolveSigningKey(ctx, "DARIYAKEYAAAA"); err == nil {
			t.Fatal("a failing lookup succeeded")
		}
	}
	if got := inner.calls.Load(); got != 5 {
		t.Errorf("database consulted %d times through an outage, want 5 — a cached outage "+
			"outlives the outage", got)
	}
}

// A cold cache under load must send one query, not one per in-flight request — the stampede
// arrives in the exact moment the database is least able to take it.
func TestConcurrentMissesCollapseToOneQuery(t *testing.T) {
	inner := &countingResolver{key: testKey(), delay: 50 * time.Millisecond}
	c := NewCachingResolver(inner, CacheOptions{})

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.ResolveSigningKey(context.Background(), "DARIYAKEYAAAA"); err != nil {
				t.Errorf("lookup: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := inner.calls.Load(); got != 1 {
		t.Errorf("64 concurrent misses produced %d queries, want 1", got)
	}
}

// Negative caching means an unauthenticated caller chooses the keys, so the map must be bounded
// or spraying random ids is a memory leak with extra steps.
func TestCacheIsBounded(t *testing.T) {
	inner := &countingResolver{key: testKey()}
	c := NewCachingResolver(inner, CacheOptions{MaxEntries: 10})
	ctx := context.Background()

	for i := 0; i < 200; i++ {
		if _, err := c.ResolveSigningKey(ctx, "DARIYAKEY"+string(rune('A'+i%200))+string(rune(i))); err != nil {
			t.Fatalf("lookup %d: %v", i, err)
		}
	}

	if s := c.Stats(); s.Entries > 10 {
		t.Errorf("cache holds %d entries, cap is 10", s.Entries)
	}
	// Refusing to cache when full is the chosen behaviour: it degrades to the uncached path
	// rather than letting sprayed ids evict real credentials.
	if s := c.Stats(); s.Refusals == 0 {
		t.Error("a full cache never refused an insert, so something else made room")
	}
}

func mustResolve(t *testing.T, c *CachingResolver, ctx context.Context) {
	t.Helper()
	if _, err := c.ResolveSigningKey(ctx, "DARIYAKEYAAAA"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
}

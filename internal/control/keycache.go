package control

import (
	"context"
	"errors"
	"time"

	"dariyanws/internal/apierr"
	"dariyanws/internal/ttlcache"
)

// CachingResolver caches access-key lookups in front of Postgres.
//
// E2 (BREAK.md) measured the uncached lookup at 165µs and **96.4% of everything the front door
// adds** to a request, with the pool becoming the concurrency ceiling: throughput peaked at 8
// connections — exactly the pool size — and then went backwards. E2b measured this cache at 6.2×
// and, more importantly, turned a falling curve flat. It was deliberately not built before that
// number existed, because a cache added on suspicion is a cache whose value nobody can state.
//
// The caching semantics live in internal/ttlcache; what is decided here is which errors count as
// definitive. Only a NotFound does: an unknown access key id really is a stable answer, while a
// timeout or a refused connection is a condition that must not be remembered.
//
// **What it costs:** a revoked credential keeps working for up to the TTL. That is a real
// weakening, not a refactor, and TestRevocationIsBoundedByTheTTL asserts it directly so it cannot
// hide behind the invalidation hook that makes revocation immediate on one process. It is the
// same trade decision 6 already accepted for capability tokens, bounded by the same duration so
// there is one number to reason about rather than two.
type CachingResolver struct {
	cache *ttlcache.Cache[*SigningKey]
}

// KeyResolver is what CachingResolver wraps. *AccountsServer satisfies it.
type KeyResolver interface {
	ResolveSigningKey(ctx context.Context, accessKeyID string) (*SigningKey, error)
}

// CacheOptions configure a CachingResolver. Zero values take the ttlcache defaults.
type CacheOptions struct {
	TTL         time.Duration
	NegativeTTL time.Duration
	MaxEntries  int
	Now         func() time.Time
}

func NewCachingResolver(inner KeyResolver, opts CacheOptions) *CachingResolver {
	return &CachingResolver{
		cache: ttlcache.New(inner.ResolveSigningKey, ttlcache.Options{
			TTL:         opts.TTL,
			NegativeTTL: opts.NegativeTTL,
			MaxEntries:  opts.MaxEntries,
			Now:         opts.Now,
			IsNegative:  isNotFound,
		}),
	}
}

func (c *CachingResolver) ResolveSigningKey(ctx context.Context, accessKeyID string) (*SigningKey, error) {
	return c.cache.Get(ctx, accessKeyID)
}

// Invalidate drops an entry. DeleteAccessKey calls it, which keeps revocation immediate on the
// process that served the delete — the TTL is the bound for any other front door.
func (c *CachingResolver) Invalidate(accessKeyID string) { c.cache.Invalidate(accessKeyID) }

// Stats is a snapshot, for logs and for E2b.
func (c *CachingResolver) Stats() ttlcache.Stats { return c.cache.Stats() }

func isNotFound(err error) bool {
	var e *apierr.Error
	return errors.As(err, &e) && e.Code == apierr.CodeNotFound
}

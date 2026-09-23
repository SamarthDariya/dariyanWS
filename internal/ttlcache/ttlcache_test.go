package ttlcache

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The credential cache's tests in internal/control exercise these rules through a real wrapper.
// What is tested here is what is generic and therefore not covered there: a non-pointer value
// type, and the default that applies to a caller who has not thought about which errors are
// definitive.

var errTransient = errors.New("connection refused")
var errNoSuchThing = errors.New("no such thing")

func TestCachesByValue(t *testing.T) {
	var calls atomic.Int64
	c := New(func(context.Context, string) (int, error) {
		calls.Add(1)
		return 42, nil
	}, Options{})

	for i := 0; i < 10; i++ {
		got, err := c.Get(context.Background(), "k")
		if err != nil || got != 42 {
			t.Fatalf("Get = %v, %v", got, err)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("loaded %d times, want 1", calls.Load())
	}
}

// A caller who does not supply IsNegative gets no error caching at all. Between defaulting to
// "cache every error" and "cache none", only one of them can silently turn an outage into a
// longer outage.
func TestNoErrorsCachedByDefault(t *testing.T) {
	var calls atomic.Int64
	c := New(func(context.Context, string) (string, error) {
		calls.Add(1)
		return "", errNoSuchThing
	}, Options{})

	for i := 0; i < 5; i++ {
		if _, err := c.Get(context.Background(), "k"); err == nil {
			t.Fatal("expected an error")
		}
	}
	if calls.Load() != 5 {
		t.Errorf("loaded %d times, want 5 — no error should be cached by default", calls.Load())
	}
}

func TestOnlyDefinitiveErrorsAreCached(t *testing.T) {
	var calls atomic.Int64
	var returned error

	c := New(func(context.Context, string) (string, error) {
		calls.Add(1)
		return "", returned
	}, Options{IsNegative: func(err error) bool { return errors.Is(err, errNoSuchThing) }})

	ctx := context.Background()

	returned = errNoSuchThing
	for i := 0; i < 5; i++ {
		_, _ = c.Get(ctx, "definitive")
	}
	if calls.Load() != 1 {
		t.Errorf("a definitive error was loaded %d times, want 1", calls.Load())
	}

	calls.Store(0)
	returned = errTransient
	for i := 0; i < 5; i++ {
		_, _ = c.Get(ctx, "transient")
	}
	if calls.Load() != 5 {
		t.Errorf("a transient error was loaded %d times, want 5 — a cached outage outlives the "+
			"outage", calls.Load())
	}
}

func TestExpiry(t *testing.T) {
	now := time.Now()
	var calls atomic.Int64

	c := New(func(context.Context, string) (int, error) {
		calls.Add(1)
		return 1, nil
	}, Options{TTL: time.Minute, Now: func() time.Time { return now }})

	ctx := context.Background()
	_, _ = c.Get(ctx, "k")
	now = now.Add(59 * time.Second)
	_, _ = c.Get(ctx, "k")
	if calls.Load() != 1 {
		t.Fatalf("loaded %d times inside the TTL", calls.Load())
	}

	now = now.Add(2 * time.Second)
	_, _ = c.Get(ctx, "k")
	if calls.Load() != 2 {
		t.Errorf("loaded %d times after expiry, want 2", calls.Load())
	}
}

func TestConcurrentMissesCollapse(t *testing.T) {
	var calls atomic.Int64
	c := New(func(context.Context, string) (int, error) {
		calls.Add(1)
		time.Sleep(30 * time.Millisecond)
		return 7, nil
	}, Options{})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Get(context.Background(), "k"); err != nil {
				t.Errorf("Get: %v", err)
			}
		}()
	}
	wg.Wait()

	if calls.Load() != 1 {
		t.Errorf("50 concurrent misses produced %d loads, want 1", calls.Load())
	}
}

func TestBoundedAndRefusesRatherThanEvicts(t *testing.T) {
	c := New(func(_ context.Context, key string) (string, error) {
		return key, nil
	}, Options{MaxEntries: 8})

	ctx := context.Background()
	for i := 0; i < 100; i++ {
		if _, err := c.Get(ctx, string(rune('a'+i%26))+string(rune(i))); err != nil {
			t.Fatalf("Get: %v", err)
		}
	}

	s := c.Stats()
	if s.Entries > 8 {
		t.Errorf("cache holds %d entries, cap is 8", s.Entries)
	}
	if s.Refusals == 0 {
		t.Error("a full cache never refused an insert, so something evicted a live entry")
	}
}

func TestInvalidate(t *testing.T) {
	var calls atomic.Int64
	c := New(func(context.Context, string) (int, error) {
		calls.Add(1)
		return 1, nil
	}, Options{})

	ctx := context.Background()
	_, _ = c.Get(ctx, "k")
	c.Invalidate("k")
	_, _ = c.Get(ctx, "k")

	if calls.Load() != 2 {
		t.Errorf("loaded %d times across an invalidation, want 2", calls.Load())
	}
}

// Package tiered composes two cache.Cache[T] backends — a low-latency L1
// (typically in-process) and a distributed L2 (typically Redis) — into a
// single cache.Cache[T], with an optional invalidation.Bus so a Delete on one
// node evicts L1 on every other node sharing the same L2.
//
// This was promoted out of authz/cache/tiered.go as part of the auth/authz
// restructure: the composition itself is not authz-specific, and the root
// module's cache.Cache[T] is generic and typed, unlike the old byte-oriented,
// authz-only CacheProvider it replaces.
//
// Miss semantics follow cache.Cache[T] exactly: a miss at both tiers is
// (zero T, false, nil), never an error. This is a deliberate behavior change
// from the old authz/cache, where a miss and a real backend failure were both
// reported as an error (ErrCacheMiss vs. any other error), which let callers
// silently conflate "nothing cached yet" with "the cache is broken."
package tiered

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/JinishBhardwaj/shared-go/cache"
	"github.com/JinishBhardwaj/shared-go/cache/invalidation"
)

// Config configures a two-tier L1+L2 cache.Cache[T].
type Config[T any] struct {
	// L1 is the low-latency, typically process-local cache.
	L1 cache.Cache[T]

	// L2 is the distributed cache (e.g. Redis-backed).
	L2 cache.Cache[T]

	// Bus receives invalidation broadcasts so a Delete on one node evicts
	// L1 on every other node. If nil and L2 implements invalidation.Bus,
	// L2 is used as the bus. If nil and L2 does not implement it either,
	// Delete only affects the local process's L1 and L2.
	Bus invalidation.Bus

	// L1TTL bounds how long a value may live in L1 before it must be
	// re-fetched from L2, even if Set's own expiration was longer.
	// Defaults to 60s.
	L1TTL time.Duration
}

// Store implements cache.Cache[T] as an L1-then-L2 composite: Get checks L1
// first, falls back to L2 on an L1 miss (or a non-fatal L1 error — see Get),
// and populates L1 on an L2 hit. Delete evicts both tiers locally and, if a
// Bus is configured, broadcasts the key so other nodes evict their own L1.
type Store[T any] struct {
	l1    cache.Cache[T]
	l2    cache.Cache[T]
	bus   invalidation.Bus
	l1TTL time.Duration

	cancelListen context.CancelFunc
	wg           sync.WaitGroup
	disposeOnce  sync.Once
}

var _ cache.Cache[string] = (*Store[string])(nil)

// New constructs a Store[T]. If cfg.Bus is set (or cfg.L2 implements
// invalidation.Bus), New starts a background listener that evicts L1 on
// every invalidation received; that listener is what Dispose stops.
func New[T any](cfg Config[T]) (*Store[T], error) {
	if cfg.L1 == nil {
		return nil, errors.New("tiered: L1 cache cannot be nil")
	}
	if cfg.L2 == nil {
		return nil, errors.New("tiered: L2 cache cannot be nil")
	}
	if cfg.L1TTL <= 0 {
		cfg.L1TTL = 60 * time.Second
	}

	bus := cfg.Bus
	if bus == nil {
		if b, ok := cfg.L2.(invalidation.Bus); ok {
			bus = b
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &Store[T]{
		l1:           cfg.L1,
		l2:           cfg.L2,
		bus:          bus,
		l1TTL:        cfg.L1TTL,
		cancelListen: cancel,
	}

	if s.bus != nil {
		if err := s.startInvalidationListener(ctx); err != nil {
			cancel()
			return nil, err
		}
	}

	return s, nil
}

func (s *Store[T]) startInvalidationListener(ctx context.Context) error {
	ch, err := s.bus.Subscribe(ctx)
	if err != nil {
		return err
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case key, ok := <-ch:
				if !ok {
					return
				}
				_ = s.l1.Delete(ctx, key)
			}
		}
	}()

	return nil
}

// Get checks L1 first (sub-microsecond for an in-process L1). On an L1 miss
// — or a non-fatal L1-specific error, since a brief L1 hiccup should not fail
// a read that L2 can still answer — it checks L2 and, on an L2 hit,
// populates L1 with L1TTL. A miss at both tiers is (zero T, false, nil); a
// real error from L2 is returned as an error, never silently reported as a
// miss.
func (s *Store[T]) Get(ctx context.Context, key string) (T, bool, error) {
	if val, found, err := s.l1.Get(ctx, key); err == nil && found {
		return val, true, nil
	}

	val, found, err := s.l2.Get(ctx, key)
	if err != nil {
		var zero T
		return zero, false, err
	}
	if !found {
		return val, false, nil
	}

	_ = s.l1.Set(ctx, key, val, s.l1TTL)
	return val, true, nil
}

// Set stores in both L1 (bounded by L1TTL) and L2.
func (s *Store[T]) Set(ctx context.Context, key string, value T, expiration time.Duration) error {
	l1TTL := s.l1TTL
	if expiration > 0 && expiration < l1TTL {
		l1TTL = expiration
	}

	_ = s.l1.Set(ctx, key, value, l1TTL)
	return s.l2.Set(ctx, key, value, expiration)
}

// Delete removes key from both tiers and, if a Bus is configured,
// broadcasts the invalidation so other nodes evict their L1 too.
func (s *Store[T]) Delete(ctx context.Context, key string) error {
	_ = s.l1.Delete(ctx, key)
	if err := s.l2.Delete(ctx, key); err != nil {
		return err
	}
	if s.bus != nil {
		return s.bus.Publish(ctx, key)
	}
	return nil
}

// Dispose stops the invalidation listener (if any) and disposes both tiers.
// Safe to call more than once.
func (s *Store[T]) Dispose() {
	s.disposeOnce.Do(func() {
		if s.cancelListen != nil {
			s.cancelListen()
		}
		s.wg.Wait()
		s.l1.Dispose()
		s.l2.Dispose()
	})
}

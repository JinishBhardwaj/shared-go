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
	"sync/atomic"
	"time"

	"github.com/JinishBhardwaj/shared-go/cache"
	"github.com/JinishBhardwaj/shared-go/cache/invalidation"
	"github.com/sony/gobreaker/v2"
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

	// L2Timeout bounds each individual L2 call (Get/Set/Delete) with a
	// context deadline, so a slow or unreachable L2 backend (typically
	// Redis) cannot stall every request that falls through from an L1
	// miss. Defaults to 50ms, per the gap analysis's explicit figure for
	// repo/Redis calls. Applied in addition to (never in place of)
	// whatever deadline the caller's own ctx already carries.
	L2Timeout time.Duration

	// ReconnectMinBackoff / ReconnectMaxBackoff bound the exponential
	// backoff used to resubscribe to Bus after the invalidation listener's
	// channel closes for a reason other than ctx cancellation (e.g. a
	// dropped Redis pubsub connection). Default to 200ms / 30s.
	ReconnectMinBackoff time.Duration
	ReconnectMaxBackoff time.Duration
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

	// l2Timeout and l2Breaker guard every L2 call (Tier 3 "deadlines +
	// breakers" for the Redis leg). Not exposed as public fields -- only
	// the time.Duration knob (Config.L2Timeout) is public; the breaker
	// itself uses fixed library defaults, same "don't leak the breaker
	// library into the public API" reasoning used in auth/authz.
	l2Timeout time.Duration
	l2Breaker *gobreaker.CircuitBreaker[l2Result[T]]

	// minBackoff/maxBackoff bound the invalidation listener's resubscribe
	// backoff (Tier 3 revocation-listener supervision). listenerHealthy is
	// the liveness gauge: true once a subscribe has succeeded, false for
	// the duration of an outage/reconnect loop, and vacuously true if no
	// Bus is configured at all (nothing to be unhealthy about -- see New).
	minBackoff      time.Duration
	maxBackoff      time.Duration
	listenerHealthy atomic.Bool

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
	if cfg.L2Timeout <= 0 {
		cfg.L2Timeout = 50 * time.Millisecond
	}
	if cfg.ReconnectMinBackoff <= 0 {
		cfg.ReconnectMinBackoff = 200 * time.Millisecond
	}
	if cfg.ReconnectMaxBackoff <= 0 {
		cfg.ReconnectMaxBackoff = 30 * time.Second
	}
	if cfg.ReconnectMaxBackoff < cfg.ReconnectMinBackoff {
		cfg.ReconnectMaxBackoff = cfg.ReconnectMinBackoff
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
		l2Timeout:    cfg.L2Timeout,
		l2Breaker:    gobreaker.NewCircuitBreaker[l2Result[T]](gobreaker.Settings{Name: "tiered-l2"}),
		minBackoff:   cfg.ReconnectMinBackoff,
		maxBackoff:   cfg.ReconnectMaxBackoff,
		cancelListen: cancel,
	}
	// Vacuously healthy until proven otherwise: if no Bus is configured at
	// all, there is no listener to ever report unhealthy, so this stays
	// true forever (see ListenerHealthy's doc comment).
	s.listenerHealthy.Store(true)

	if s.bus != nil {
		if err := s.startInvalidationListener(ctx); err != nil {
			cancel()
			return nil, err
		}
	}

	return s, nil
}

// ListenerHealthy reports whether the background invalidation-listener
// goroutine currently believes it has a live subscription to Bus. It is
// vacuously true if no Bus was configured (nothing to be unhealthy about).
// It goes false for the duration of a dropped-connection/resubscribe
// backoff loop (Tier 3 revocation-listener supervision) and recovers to
// true once a resubscribe succeeds. Intended for a liveness/health-check
// gauge, not for gating request handling.
func (s *Store[T]) ListenerHealthy() bool {
	return s.listenerHealthy.Load()
}

func (s *Store[T]) startInvalidationListener(ctx context.Context) error {
	ch, err := s.bus.Subscribe(ctx)
	if err != nil {
		return err
	}
	s.listenerHealthy.Store(true)

	s.wg.Add(1)
	go s.runInvalidationListener(ctx, ch)

	return nil
}

// runInvalidationListener consumes invalidation keys from ch until ctx is
// done, evicting each one from L1. Tier 3 revocation-listener supervision:
// previously, a channel close for ANY reason (a dropped Bus connection, not
// just our own ctx cancellation) permanently and silently stopped
// revocation delivery -- "the worst failure mode in the library" per the
// gap analysis, since a principal revoked after that point would never
// have their stale L1 entry evicted. Now, a close that is NOT explained by
// ctx being done triggers an exponential-backoff resubscribe loop instead
// of returning, and s.listenerHealthy tracks whether a subscription is
// currently believed live.
func (s *Store[T]) runInvalidationListener(ctx context.Context, ch <-chan string) {
	defer s.wg.Done()

	for {
		select {
		case <-ctx.Done():
			s.listenerHealthy.Store(false)
			return
		case key, ok := <-ch:
			if !ok {
				if ctx.Err() != nil {
					// Ordinary shutdown: the channel closed because ctx
					// was canceled (e.g. Dispose), not because the
					// connection dropped. Exit cleanly, no reconnect
					// noise.
					s.listenerHealthy.Store(false)
					return
				}

				s.listenerHealthy.Store(false)
				newCh, resubErr := s.resubscribeWithBackoff(ctx)
				if resubErr != nil {
					// ctx was canceled while we were waiting/retrying.
					return
				}
				ch = newCh
				s.listenerHealthy.Store(true)
				continue
			}
			_ = s.l1.Delete(ctx, key)
		}
	}
}

// resubscribeWithBackoff retries s.bus.Subscribe with exponential backoff
// (bounded by s.minBackoff/s.maxBackoff, doubling on each failed attempt)
// until it succeeds or ctx is done.
func (s *Store[T]) resubscribeWithBackoff(ctx context.Context) (<-chan string, error) {
	backoff := s.minBackoff
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}

		ch, err := s.bus.Subscribe(ctx)
		if err == nil {
			return ch, nil
		}

		backoff *= 2
		if backoff > s.maxBackoff {
			backoff = s.maxBackoff
		}
	}
}

// l2Result wraps an L2 Get's (value, found) pair so all three L2
// operations (Get/Set/Delete) can share one generic breaker instance --
// gobreaker.CircuitBreaker[T]'s Execute needs a single result type, and
// Set/Delete simply ignore the zero-valued result they return.
type l2Result[T any] struct {
	Val   T
	Found bool
}

// l2Get wraps s.l2.Get with a per-call context deadline (l2Timeout) and the
// circuit breaker (Tier 3 "deadlines + breakers" for the Redis leg). A
// deadline-exceeded or breaker-open error surfaces exactly like any other
// L2 error already did -- never as a miss, never specially handled.
func (s *Store[T]) l2Get(ctx context.Context, key string) (T, bool, error) {
	cctx, cancel := context.WithTimeout(ctx, s.l2Timeout)
	defer cancel()

	res, err := s.l2Breaker.Execute(func() (l2Result[T], error) {
		val, found, err := s.l2.Get(cctx, key)
		return l2Result[T]{Val: val, Found: found}, err
	})
	if err != nil {
		var zero T
		return zero, false, err
	}
	return res.Val, res.Found, nil
}

// l2Set wraps s.l2.Set the same way as l2Get.
func (s *Store[T]) l2Set(ctx context.Context, key string, value T, expiration time.Duration) error {
	cctx, cancel := context.WithTimeout(ctx, s.l2Timeout)
	defer cancel()

	_, err := s.l2Breaker.Execute(func() (l2Result[T], error) {
		return l2Result[T]{}, s.l2.Set(cctx, key, value, expiration)
	})
	return err
}

// l2Delete wraps s.l2.Delete the same way as l2Get.
func (s *Store[T]) l2Delete(ctx context.Context, key string) error {
	cctx, cancel := context.WithTimeout(ctx, s.l2Timeout)
	defer cancel()

	_, err := s.l2Breaker.Execute(func() (l2Result[T], error) {
		return l2Result[T]{}, s.l2.Delete(cctx, key)
	})
	return err
}

// Get checks L1 first (sub-microsecond for an in-process L1). On an L1 miss
// — or a non-fatal L1-specific error, since a brief L1 hiccup should not fail
// a read that L2 can still answer — it checks L2 (via l2Get, deadline- and
// breaker-guarded) and, on an L2 hit, populates L1 with L1TTL. A miss at
// both tiers is (zero T, false, nil); a real error from L2 (including a
// deadline exceeded or an open breaker) is returned as an error, never
// silently reported as a miss.
func (s *Store[T]) Get(ctx context.Context, key string) (T, bool, error) {
	if val, found, err := s.l1.Get(ctx, key); err == nil && found {
		return val, true, nil
	}

	val, found, err := s.l2Get(ctx, key)
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

// Set stores in both L1 (bounded by L1TTL) and L2 (via l2Set, deadline- and
// breaker-guarded).
func (s *Store[T]) Set(ctx context.Context, key string, value T, expiration time.Duration) error {
	l1TTL := s.l1TTL
	if expiration > 0 && expiration < l1TTL {
		l1TTL = expiration
	}

	_ = s.l1.Set(ctx, key, value, l1TTL)
	return s.l2Set(ctx, key, value, expiration)
}

// Delete removes key from both tiers (L2 via l2Delete, deadline- and
// breaker-guarded) and, if a Bus is configured, broadcasts the invalidation
// so other nodes evict their L1 too.
func (s *Store[T]) Delete(ctx context.Context, key string) error {
	_ = s.l1.Delete(ctx, key)
	if err := s.l2Delete(ctx, key); err != nil {
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

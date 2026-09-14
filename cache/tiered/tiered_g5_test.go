package tiered

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JinishBhardwaj/shared-go/cache"
	"github.com/JinishBhardwaj/shared-go/cache/invalidation"
	"github.com/JinishBhardwaj/shared-go/cache/memory"
)

// blockingCache is a cache.Cache[string] whose Get blocks until either ctx
// is done or the test unblocks it, used to prove Store.Get's L2 deadline
// (Config.L2Timeout) actually bounds a slow L2 call instead of hanging
// forever or silently reporting a false miss.
type blockingCache struct {
	calls int32
}

func (b *blockingCache) Set(context.Context, string, string, time.Duration) error { return nil }
func (b *blockingCache) Get(ctx context.Context, _ string) (string, bool, error) {
	atomic.AddInt32(&b.calls, 1)
	<-ctx.Done()
	return "", false, ctx.Err()
}
func (b *blockingCache) Delete(context.Context, string) error { return nil }
func (b *blockingCache) Dispose()                             {}

var _ cache.Cache[string] = (*blockingCache)(nil)

// TestStore_L2Deadline_BoundsASlowL2Call is the Tier 3 deadline regression
// test: an L2 that never responds must not hang Store.Get forever, and must
// not be silently reported as a plain miss -- it must surface as an error,
// bounded by Config.L2Timeout, not by however long the test would otherwise
// wait.
func TestStore_L2Deadline_BoundsASlowL2Call(t *testing.T) {
	ctx := context.Background()
	l1 := memory.New[string](0)
	defer l1.Dispose()
	l2 := &blockingCache{}

	s, err := New(Config[string]{L1: l1, L2: l2, L2Timeout: 30 * time.Millisecond})
	if err != nil {
		t.Fatalf("failed to construct tiered store: %v", err)
	}
	defer s.Dispose()

	start := time.Now()
	_, found, err := s.Get(ctx, "any-key")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected the deadline-exceeded L2 call to surface as an error, got found=%v err=nil", found)
	}
	if found {
		t.Fatalf("expected found=false alongside the error")
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("Get took %v -- the L2Timeout deadline does not appear to be bounding the call", elapsed)
	}
}

// alwaysFailCache is a cache.Cache[string] whose Get always fails, used to
// trip the L2 circuit breaker and prove it actually opens (fails fast
// without reaching the backend) rather than retrying forever.
type alwaysFailCache struct {
	calls int32
}

var errAlwaysFail = errors.New("l2: simulated persistent failure")

func (a *alwaysFailCache) Set(context.Context, string, string, time.Duration) error { return nil }
func (a *alwaysFailCache) Get(context.Context, string) (string, bool, error) {
	atomic.AddInt32(&a.calls, 1)
	return "", false, errAlwaysFail
}
func (a *alwaysFailCache) Delete(context.Context, string) error { return nil }
func (a *alwaysFailCache) Dispose()                             {}

var _ cache.Cache[string] = (*alwaysFailCache)(nil)

// TestStore_L2Breaker_OpensAfterRepeatedFailures proves the L2 breaker
// actually trips: after enough consecutive failures, further Get calls fail
// fast without incrementing the backend's own call count any further,
// instead of hammering an already-down backend indefinitely.
func TestStore_L2Breaker_OpensAfterRepeatedFailures(t *testing.T) {
	ctx := context.Background()
	l1 := memory.New[string](0)
	defer l1.Dispose()
	l2 := &alwaysFailCache{}

	s, err := New(Config[string]{L1: l1, L2: l2, L2Timeout: time.Second})
	if err != nil {
		t.Fatalf("failed to construct tiered store: %v", err)
	}
	defer s.Dispose()

	// Drive enough failures to trip the breaker (gobreaker's default
	// ReadyToTrip fires after more than 5 consecutive failures).
	for i := 0; i < 10; i++ {
		if _, _, err := s.Get(ctx, "k"); err == nil {
			t.Fatalf("call %d: expected an error from the always-failing L2", i)
		}
	}

	callsAtTrip := atomic.LoadInt32(&l2.calls)

	// A few more calls: if the breaker is open, these should fail without
	// reaching the backend at all, so the backend's call count should not
	// keep climbing 1:1 with every subsequent Get.
	for i := 0; i < 5; i++ {
		if _, _, err := s.Get(ctx, "k"); err == nil {
			t.Fatalf("post-trip call %d: expected an error (breaker open or backend failure)", i)
		}
	}

	callsAfter := atomic.LoadInt32(&l2.calls)
	if callsAfter > callsAtTrip {
		t.Fatalf("expected the breaker to be open and short-circuit further backend calls, but backend calls grew from %d to %d", callsAtTrip, callsAfter)
	}
}

// fakeBus is a minimal invalidation.Bus whose Subscribe hands out channels
// the test can close directly (simulating a dropped pubsub connection, NOT
// a ctx.Done()-driven shutdown), used to exercise Tier 3 revocation-listener
// supervision (backoff reconnect + liveness gauge) in cache/tiered.
type fakeBus struct {
	mu             sync.Mutex
	subscribeCalls int
	// current is the channel most recently handed out by Subscribe -- the
	// one the listener goroutine is (or should be) actively reading.
	// Publish only ever targets this one, so once the test closes it out
	// from under the listener and the listener resubscribes, Publish
	// automatically starts targeting the NEW channel instead -- exactly
	// mirroring how a real pubsub reconnect replaces the old subscription.
	current chan string
	nextErr error
}

func (b *fakeBus) Publish(_ context.Context, key string) error {
	b.mu.Lock()
	ch := b.current
	b.mu.Unlock()

	if ch != nil {
		select {
		case ch <- key:
		default:
		}
	}
	return nil
}

func (b *fakeBus) Subscribe(_ context.Context) (<-chan string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subscribeCalls++
	if b.nextErr != nil {
		err := b.nextErr
		b.nextErr = nil
		return nil, err
	}
	ch := make(chan string, 10)
	b.current = ch
	return ch, nil
}

func (b *fakeBus) callCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.subscribeCalls
}

func (b *fakeBus) latestChan() chan string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.current
}

var _ invalidation.Bus = (*fakeBus)(nil)

func waitUntil(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("condition not met within %v", timeout)
	}
}

// TestStore_RevocationListener_ReconnectsAfterDroppedChannel is the Tier 3
// revocation-listener-supervision regression test. Today's (pre-fix) code
// permanently and silently exits the listener goroutine the moment its
// invalidation channel closes for ANY reason -- including a dropped
// connection unrelated to ctx cancellation, not just Dispose. This proves:
// (a) ListenerHealthy() goes false the moment the channel drops, (b) the
// listener actually calls Subscribe again (not just parking forever), and
// (c) once resubscribed, revocation delivery genuinely resumes -- a
// published key after reconnect still evicts L1. (c) is the fail-closed
// proof: without it, a principal revoked after a connection drop would keep
// a stale "allowed" entry in L1 forever.
func TestStore_RevocationListener_ReconnectsAfterDroppedChannel(t *testing.T) {
	ctx := context.Background()
	l1 := memory.New[string](0)
	defer l1.Dispose()
	l2 := memory.New[string](0)
	defer l2.Dispose()
	bus := &fakeBus{}

	s, err := New(Config[string]{
		L1:                  l1,
		L2:                  l2,
		Bus:                 bus,
		ReconnectMinBackoff: 5 * time.Millisecond,
		ReconnectMaxBackoff: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to construct tiered store: %v", err)
	}
	defer s.Dispose()

	if !s.ListenerHealthy() {
		t.Fatalf("expected the listener to be healthy immediately after a successful initial subscribe")
	}
	if got := bus.callCount(); got != 1 {
		t.Fatalf("expected exactly 1 initial Subscribe call, got %d", got)
	}

	// Prime L1 with a value so we can later prove eviction still works.
	if err := l1.Set(ctx, "perm:revoked-user", "stale-allow", time.Minute); err != nil {
		t.Fatalf("priming L1: %v", err)
	}

	// Simulate a dropped connection: close the channel the listener is
	// currently reading from, WITHOUT canceling ctx.
	close(bus.latestChan())

	waitUntil(t, time.Second, func() bool { return !s.ListenerHealthy() })
	waitUntil(t, time.Second, func() bool { return bus.callCount() >= 2 })
	waitUntil(t, time.Second, func() bool { return s.ListenerHealthy() })

	// Publish on the NEW subscription and confirm revocation delivery
	// actually resumed, not just that the goroutine is still alive.
	if err := bus.Publish(ctx, "perm:revoked-user"); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	waitUntil(t, time.Second, func() bool {
		_, found, _ := l1.Get(ctx, "perm:revoked-user")
		return !found
	})
}

// TestStore_ListenerHealthy_TrueWhenNoBusConfigured confirms the vacuous
// "nothing to be unhealthy about" case documented on ListenerHealthy.
func TestStore_ListenerHealthy_TrueWhenNoBusConfigured(t *testing.T) {
	l1 := memory.New[string](0)
	defer l1.Dispose()
	l2 := memory.New[string](0)
	defer l2.Dispose()

	s, err := New(Config[string]{L1: l1, L2: l2})
	if err != nil {
		t.Fatalf("failed to construct tiered store: %v", err)
	}
	defer s.Dispose()

	if !s.ListenerHealthy() {
		t.Fatalf("expected ListenerHealthy()==true when no Bus is configured")
	}
}

// TestStore_ListenerHealthy_FalseAfterDispose confirms clean shutdown (via
// Dispose/ctx cancellation) is reported as not-healthy without triggering a
// reconnect attempt.
func TestStore_ListenerHealthy_FalseAfterDispose(t *testing.T) {
	l1 := memory.New[string](0)
	defer l1.Dispose()
	l2 := memory.New[string](0)
	defer l2.Dispose()
	bus := &fakeBus{}

	s, err := New(Config[string]{L1: l1, L2: l2, Bus: bus})
	if err != nil {
		t.Fatalf("failed to construct tiered store: %v", err)
	}

	if !s.ListenerHealthy() {
		t.Fatalf("expected healthy before Dispose")
	}
	s.Dispose()
	waitUntil(t, time.Second, func() bool { return !s.ListenerHealthy() })

	if got := bus.callCount(); got != 1 {
		t.Fatalf("expected no reconnect attempt on ordinary shutdown, got %d Subscribe calls", got)
	}
}

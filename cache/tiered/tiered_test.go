package tiered

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JinishBhardwaj/shared-go/cache"
	"github.com/JinishBhardwaj/shared-go/cache/invalidation"
	"github.com/JinishBhardwaj/shared-go/cache/memory"
)

func TestNew_RequiresL1AndL2(t *testing.T) {
	l1 := memory.New[string](0)
	defer l1.Dispose()
	l2 := memory.New[string](0)
	defer l2.Dispose()

	if _, err := New(Config[string]{L1: nil, L2: l2}); err == nil {
		t.Fatalf("expected error when L1 is nil")
	}
	if _, err := New(Config[string]{L1: l1, L2: nil}); err == nil {
		t.Fatalf("expected error when L2 is nil")
	}
}

func TestStore_GetMissAtBothTiersIsNeverAnError(t *testing.T) {
	ctx := context.Background()
	l1 := memory.New[string](0)
	defer l1.Dispose()
	l2 := memory.New[string](0)
	defer l2.Dispose()

	s, err := New(Config[string]{L1: l1, L2: l2})
	if err != nil {
		t.Fatalf("failed to construct tiered store: %v", err)
	}
	defer s.Dispose()

	val, found, err := s.Get(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("a miss must not be an error, got %v", err)
	}
	if found {
		t.Fatalf("expected found=false on a miss")
	}
	if val != "" {
		t.Fatalf("expected zero value on a miss, got %q", val)
	}
}

func TestStore_L2HitPopulatesL1(t *testing.T) {
	ctx := context.Background()
	l1 := memory.New[string](0)
	defer l1.Dispose()
	l2 := memory.New[string](0)
	defer l2.Dispose()

	s, err := New(Config[string]{L1: l1, L2: l2, L1TTL: 10 * time.Second})
	if err != nil {
		t.Fatalf("failed to construct tiered store: %v", err)
	}
	defer s.Dispose()

	// Prime L2 only, simulating a value already granted/stored by another
	// node.
	if err := l2.Set(ctx, "perm:user_1", "editor", 10*time.Minute); err != nil {
		t.Fatalf("failed priming L2: %v", err)
	}

	if _, found, _ := l1.Get(ctx, "perm:user_1"); found {
		t.Fatalf("expected L1 to be empty before the tiered Get")
	}

	val, found, err := s.Get(ctx, "perm:user_1")
	if err != nil || !found || val != "editor" {
		t.Fatalf("expected hit via L2 fallthrough, got val=%q found=%v err=%v", val, found, err)
	}

	if val, found, _ := l1.Get(ctx, "perm:user_1"); !found || val != "editor" {
		t.Fatalf("expected L1 to be populated after the tiered Get, got val=%q found=%v", val, found)
	}
}

func TestStore_DeletePropagatesInstantlyToOtherNodesViaBus(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	bus := invalidation.NewInProcessBus()

	// Node A: its own L1, sharing L2 and the bus with node B.
	l2 := memory.New[string](0)
	defer l2.Dispose()

	l1A := memory.New[string](0)
	defer l1A.Dispose()
	nodeA, err := New(Config[string]{L1: l1A, L2: l2, Bus: bus, L1TTL: 10 * time.Second})
	if err != nil {
		t.Fatalf("failed constructing node A: %v", err)
	}
	defer nodeA.Dispose()

	l1B := memory.New[string](0)
	defer l1B.Dispose()
	nodeB, err := New(Config[string]{L1: l1B, L2: l2, Bus: bus, L1TTL: 10 * time.Second})
	if err != nil {
		t.Fatalf("failed constructing node B: %v", err)
	}
	defer nodeB.Dispose()

	// Both nodes read the value, populating their own L1.
	if err := nodeA.Set(ctx, "perm:user_9", "viewer", 10*time.Minute); err != nil {
		t.Fatalf("set failed: %v", err)
	}
	if _, found, _ := nodeB.Get(ctx, "perm:user_9"); !found {
		t.Fatalf("expected node B to see the value via L2")
	}
	waitForL1(t, l1B, "perm:user_9", true)

	// Node A deletes (e.g. a permission revocation) -- node B's L1 must be
	// evicted instantly via the bus, not merely on its own next TTL expiry.
	if err := nodeA.Delete(ctx, "perm:user_9"); err != nil {
		t.Fatalf("delete failed: %v", err)
	}

	waitForL1(t, l1B, "perm:user_9", false)

	if _, found, _ := l2.Get(ctx, "perm:user_9"); found {
		t.Fatalf("expected L2 to be evicted after delete")
	}
}

func waitForL1(t *testing.T, l1 cache.Cache[string], key string, wantFound bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, found, _ := l1.Get(context.Background(), key)
		if found == wantFound {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for L1 found=%v for key %q", wantFound, key)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestStore_GetSurfacesRealL2Errors(t *testing.T) {
	ctx := context.Background()
	l1 := memory.New[string](0)
	defer l1.Dispose()

	s, err := New(Config[string]{L1: l1, L2: &erroringCache{}})
	if err != nil {
		t.Fatalf("failed to construct tiered store: %v", err)
	}
	defer s.Dispose()

	_, found, err := s.Get(ctx, "any-key")
	if err == nil {
		t.Fatalf("expected a real L2 error to be surfaced, not swallowed as a miss")
	}
	if found {
		t.Fatalf("expected found=false alongside the error")
	}
}

// erroringCache is a minimal cache.Cache[string] whose Get always fails,
// used to prove tiered.Store does not conflate a real backend failure with a
// plain miss.
type erroringCache struct{}

var errBackend = errors.New("backend unavailable")

func (e *erroringCache) Set(context.Context, string, string, time.Duration) error { return nil }
func (e *erroringCache) Get(context.Context, string) (string, bool, error) {
	return "", false, errBackend
}
func (e *erroringCache) Delete(context.Context, string) error { return nil }
func (e *erroringCache) Dispose()                             {}

var _ cache.Cache[string] = (*erroringCache)(nil)

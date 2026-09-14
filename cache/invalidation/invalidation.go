// Package invalidation defines the Observer-pattern contract for broadcasting
// and receiving cache-key invalidation events, so that a write or revocation
// observed on one node is reflected promptly on every other node sharing the
// same distributed (L2) cache.
//
// This was promoted out of authz/cache (where it was called InvalidationBus)
// as part of the auth/authz restructure: it is not authz-specific, and
// cache/tiered composes any cache.Cache[T] backend with a Bus to get instant
// cross-node eviction on top of a plain L1+L2 read-through cache.
package invalidation

import (
	"context"
	"sync"
)

// Bus publishes and subscribes to cache-key invalidation events.
type Bus interface {
	// Publish broadcasts that key should be invalidated everywhere.
	Publish(ctx context.Context, key string) error

	// Subscribe returns a channel delivering keys invalidated by any
	// publisher. The channel is closed once ctx is done.
	Subscribe(ctx context.Context) (<-chan string, error)
}

// InProcessBus is a Bus implementation for single-process deployments (and
// tests): Publish fans a key out to every channel returned by a prior
// Subscribe call, all within the same process. It does nothing for other
// processes — a distributed deployment needs a Bus backed by a shared
// broker (e.g. Redis Pub/Sub).
type InProcessBus struct {
	mu          sync.Mutex
	subscribers map[chan string]struct{}
}

var _ Bus = (*InProcessBus)(nil)

// NewInProcessBus constructs a ready-to-use InProcessBus.
func NewInProcessBus() *InProcessBus {
	return &InProcessBus{subscribers: make(map[chan string]struct{})}
}

// Publish fans key out to every currently-subscribed channel. A slow or full
// subscriber does not block or lose the event for others; a non-blocking send
// is used, mirroring at-most-once, best-effort delivery.
func (b *InProcessBus) Publish(_ context.Context, key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subscribers {
		select {
		case ch <- key:
		default:
		}
	}
	return nil
}

// Subscribe registers a new channel that receives every key published after
// this call. The returned channel is closed and unregistered when ctx is
// done.
func (b *InProcessBus) Subscribe(ctx context.Context) (<-chan string, error) {
	ch := make(chan string, 100)

	b.mu.Lock()
	b.subscribers[ch] = struct{}{}
	b.mu.Unlock()

	go func() {
		<-ctx.Done()
		b.mu.Lock()
		if _, exists := b.subscribers[ch]; exists {
			delete(b.subscribers, ch)
			close(ch)
		}
		b.mu.Unlock()
	}()

	return ch, nil
}

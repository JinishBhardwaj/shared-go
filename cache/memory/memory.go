// Package memory implements cache.Cache[T] as an in-process store backed by
// github.com/patrickmn/go-cache.
package memory

import (
	"context"
	"sync"
	"time"

	gocache "github.com/patrickmn/go-cache"

	"github.com/JinishBhardwaj/shared-go/cache"
)

// Store is an in-process, concurrency-safe implementation of cache.Cache[T].
//
// go-cache's own background janitor cannot be stopped deterministically once
// started (it only stops when the returned *gocache.Cache is garbage
// collected), so Store never enables it. Instead, if a positive
// cleanupInterval is supplied to New, Store runs its own ticker goroutine
// that periodically evicts expired entries; that goroutine is what Dispose
// stops.
type Store[T any] struct {
	underlying *gocache.Cache

	stopOnce sync.Once
	stopCh   chan struct{}
}

var _ cache.Cache[string] = (*Store[string])(nil)

// New constructs a Store[T]. If cleanupInterval > 0, a background goroutine
// periodically purges expired entries from memory at that interval; pass 0
// (or a negative value) to disable background purging, in which case
// expired entries are only removed lazily, on Get or Delete. Dispose stops
// the background goroutine (if any) and drops all entries.
func New[T any](cleanupInterval time.Duration) *Store[T] {
	s := &Store[T]{
		// gocache.NoExpiration as the default is inert here: every call this
		// package makes to the underlying cache passes an explicit
		// per-entry duration, so the underlying "default expiration" is
		// never consulted.
		underlying: gocache.New(gocache.NoExpiration, 0),
	}

	if cleanupInterval > 0 {
		s.stopCh = make(chan struct{})
		go s.runJanitor(cleanupInterval)
	}

	return s
}

func (s *Store[T]) runJanitor(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.underlying.DeleteExpired()
		case <-s.stopCh:
			return
		}
	}
}

// Set stores value under key. If expiration <= 0, the value never expires.
func (s *Store[T]) Set(_ context.Context, key string, value T, expiration time.Duration) error {
	d := expiration
	if d <= 0 {
		d = gocache.NoExpiration
	}
	s.underlying.Set(key, value, d)
	return nil
}

// Get retrieves the value stored under key. A missing or expired key
// returns (zero T, false, nil); it is never reported as an error.
func (s *Store[T]) Get(_ context.Context, key string) (T, bool, error) {
	var zero T

	raw, found := s.underlying.Get(key)
	if !found {
		return zero, false, nil
	}

	value, ok := raw.(T)
	if !ok {
		// Should not happen in practice since only Set (typed T) ever
		// populates this cache, but guard against a mismatched entry rather
		// than panicking.
		return zero, false, nil
	}

	return value, true, nil
}

// Delete removes key from the cache. Deleting a missing key is not an error.
func (s *Store[T]) Delete(_ context.Context, key string) error {
	s.underlying.Delete(key)
	return nil
}

// Dispose stops the background purge goroutine (if one was started) and
// drops all entries. It is safe to call more than once.
func (s *Store[T]) Dispose() {
	s.stopOnce.Do(func() {
		if s.stopCh != nil {
			close(s.stopCh)
		}
		s.underlying.Flush()
	})
}

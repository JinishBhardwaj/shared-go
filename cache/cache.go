// Package cache defines a generic, backend-agnostic caching abstraction.
//
// It is a generification of an earlier, non-generic ICacheManager
// (Set(..., value interface{}, ...) error / Get(...) (interface{}, error) /
// Dispose()). Two changes are deliberate:
//
//   - Generic T instead of interface{}: callers get a strongly typed value
//     back with no type assertion required on the hot path.
//   - Get returns (T, bool, error) instead of (interface{}, error): with a
//     generic T, the zero value of T cannot be used to signal a cache miss,
//     because T may legitimately be bool, int, or a struct whose zero value
//     is a meaningful, storable value. The bool is the found/miss signal.
//     A miss is NOT an error and implementations must never report it as
//     one (they must return (zero T, false, nil)).
//
// Delete was added to the interface because it is the invalidation hook a
// future cache-invalidation subscriber will call.
//
// Implementations of this interface live in sibling packages (e.g.
// cache/memory, cache/rediscache) and must all honor the same semantics:
//
//   - expiration <= 0 means the value never expires.
//   - Get on a missing or expired key returns (zero T, false, nil); never
//     an error.
//   - Delete on a missing key returns nil; never an error.
//   - Set overwrites any existing value for the key.
//   - All methods must be safe for concurrent use.
//   - Dispose releases backend resources and must be safe to call more
//     than once.
package cache

import (
	"context"
	"time"
)

// Cache is a generic key/value cache abstraction over a pluggable backend.
type Cache[T any] interface {
	// Set stores value under key. If expiration <= 0, the value never
	// expires. Set overwrites any existing value for key.
	Set(ctx context.Context, key string, value T, expiration time.Duration) error

	// Get retrieves the value stored under key. The bool return indicates
	// whether the key was found and not expired: (zero T, false, nil) is
	// returned on a miss, never an error. A non-nil error indicates a real
	// failure (e.g. a deserialization error), not a miss.
	Get(ctx context.Context, key string) (T, bool, error)

	// Delete removes key from the cache. Deleting a missing key is not an
	// error and returns nil.
	Delete(ctx context.Context, key string) error

	// Dispose releases any resources held by the backend (background
	// goroutines, network connections it owns, etc). It is safe to call
	// more than once.
	Dispose()
}

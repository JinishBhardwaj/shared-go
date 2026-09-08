package cache

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrCacheMiss indicates that a key was not found or has expired.
	ErrCacheMiss = errors.New("cache: key not found")

	// ErrInvalidKey indicates that an empty or invalid cache key was provided.
	ErrInvalidKey = errors.New("cache: key cannot be empty")
)

// CacheProvider defines the contract for caching permission bundles, policies, and tokens.
// Conforms to the Strategy Pattern and Interface Segregation Principle.
type CacheProvider interface {
	// Get retrieves cached bytes for a key. Returns ErrCacheMiss if not found or expired.
	Get(ctx context.Context, key string) ([]byte, error)

	// Set stores a key-value pair with a time-to-live duration.
	// If ttl <= 0, the item does not expire automatically.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error

	// Delete immediately removes a key from the cache.
	Delete(ctx context.Context, key string) error

	// Close releases any underlying connections or resources.
	Close() error
}

// InvalidationBus defines the contract for publishing and subscribing to revocation events.
// Used to achieve instant revocation across distributed API instances.
type InvalidationBus interface {
	// PublishRevocation broadcasts a revocation signal for a specific principal or key ID.
	PublishRevocation(ctx context.Context, principalID string) error

	// SubscribeRevocations returns a read-only channel delivering revoked principal IDs.
	SubscribeRevocations(ctx context.Context) (<-chan string, error)
}

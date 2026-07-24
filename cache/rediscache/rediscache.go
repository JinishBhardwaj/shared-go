// Package rediscache implements cache.Cache[T] over
// github.com/redis/go-redis/v9.
//
// T is serialized with encoding/json for storage and deserialized with
// encoding/json on read. T must therefore be JSON-round-trippable. This is
// exactly why some values can never be cached through this package -- a
// compiled program object, a channel, a func, or anything else that cannot
// survive a json.Marshal/json.Unmarshal round trip cannot be stored here.
// A json.Unmarshal failure on Get is a real error and is returned as such;
// it is never swallowed into a cache miss.
package rediscache

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/JinishBhardwaj/shared-go/cache"
)

// Store is a Redis-backed implementation of cache.Cache[T].
type Store[T any] struct {
	client *redis.Client
	owned  bool

	closeOnce sync.Once
}

var _ cache.Cache[string] = (*Store[string])(nil)

// New constructs a Store[T] using the supplied *redis.Client.
//
// Ownership: the caller retains ownership of client. Dispose will NOT close
// it. Use this constructor when the caller already manages the client's
// lifecycle (e.g. a shared client used elsewhere in the application).
func New[T any](client *redis.Client) *Store[T] {
	return &Store[T]{client: client, owned: false}
}

// NewFromOptions constructs a Store[T], creating its own *redis.Client from
// opts.
//
// Ownership: this package creates and owns the client. Dispose WILL close
// it. Do not share opts.Addr's client elsewhere expecting it to outlive
// Dispose.
func NewFromOptions[T any](opts *redis.Options) *Store[T] {
	return &Store[T]{client: redis.NewClient(opts), owned: true}
}

// Set stores value under key. If expiration <= 0, the value never expires.
func (s *Store[T]) Set(ctx context.Context, key string, value T, expiration time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	d := expiration
	if d <= 0 {
		d = 0 // go-redis treats a 0 TTL as "never expires".
	}

	return s.client.Set(ctx, key, data, d).Err()
}

// Get retrieves the value stored under key. A missing or expired key
// returns (zero T, false, nil); it is never reported as an error. A
// json.Unmarshal failure IS a real error and is returned as such.
func (s *Store[T]) Get(ctx context.Context, key string) (T, bool, error) {
	var zero T

	data, err := s.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return zero, false, nil
	}
	if err != nil {
		return zero, false, err
	}

	var value T
	if err := json.Unmarshal(data, &value); err != nil {
		return zero, false, err
	}

	return value, true, nil
}

// Delete removes key from the cache. Deleting a missing key is not an error.
func (s *Store[T]) Delete(ctx context.Context, key string) error {
	return s.client.Del(ctx, key).Err()
}

// Dispose closes the underlying *redis.Client, but only if this package
// created it (see New vs. NewFromOptions). It is safe to call more than
// once.
func (s *Store[T]) Dispose() {
	s.closeOnce.Do(func() {
		if s.owned {
			_ = s.client.Close()
		}
	})
}

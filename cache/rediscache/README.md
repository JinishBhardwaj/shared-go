# cache/rediscache

Redis-backed implementation of [`cache.Cache[T]`](..), via
[`redis/go-redis/v9`](https://github.com/redis/go-redis).

```go
func New[T any](client *redis.Client) *Store[T]
func NewFromOptions[T any](opts *redis.Options) *Store[T]
```

Values are marshalled to/from Redis; `T` must be JSON-serializable.

## Usage

```go
store := rediscache.NewFromOptions[Policy](&redis.Options{Addr: "localhost:6379"})
defer store.Dispose()

_ = store.Set(ctx, "policy:123", policy, time.Minute)
p, found, err := store.Get(ctx, "policy:123")
```

Use this when cached values must be shared across instances; use
[`cache/memory`](../memory) for single-instance/local-dev caching.

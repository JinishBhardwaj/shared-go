# cache

Generic, backend-agnostic key/value cache abstraction.

```go
type Cache[T any] interface {
	Set(ctx context.Context, key string, value T, expiration time.Duration) error
	Get(ctx context.Context, key string) (T, bool, error)
	Delete(ctx context.Context, key string) error
	Dispose()
}
```

- `T` is a real, strongly-typed value — no `interface{}` and no type assertion
  on the hot path. This is a generification of an earlier, non-generic
  `ICacheManager` (`Set(..., value interface{}, ...) error` /
  `Get(...) (interface{}, error)`).
- `Get` returns `(T, bool, error)` instead of `(interface{}, error)`: with a
  generic `T`, the zero value can't be used to signal a miss (`T` may
  legitimately be `bool`, `int`, or a struct whose zero value is meaningful
  and storable). The `bool` is the found/miss signal; a miss is never
  reported as an error.

## Implementations

| Package | Backend |
|---|---|
| [`cache/memory`](memory) | In-process, via `patrickmn/go-cache` |
| [`cache/rediscache`](rediscache) | Redis, via `redis/go-redis/v9` |

Both implement `Cache[T]` and must honor the same semantics:

- `expiration <= 0` means the value never expires.
- `Get` on a missing or expired key returns `(zero T, false, nil)`; never an
  error.
- `Delete` on a missing key returns `nil`; never an error.
- `Set` overwrites any existing value for the key.
- All methods are safe for concurrent use.
- `Dispose` releases backend resources and is safe to call more than once.

## Usage

```go
store := memory.New[Policy](5 * time.Minute)
defer store.Dispose()

_ = store.Set(ctx, "policy:123", policy, time.Minute)

if p, found, err := store.Get(ctx, "policy:123"); err != nil {
	// real failure (e.g. deserialization), not a miss
} else if found {
	// use p
}
```

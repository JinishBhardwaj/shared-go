# cache/memory

In-process implementation of [`cache.Cache[T]`](..), backed by
[`patrickmn/go-cache`](https://github.com/patrickmn/go-cache).

```go
func New[T any](cleanupInterval time.Duration) *Store[T]
```

`cleanupInterval` controls how often a background janitor sweeps expired
entries. `Dispose` stops that janitor and is safe to call more than once.

## Usage

```go
store := memory.New[Session](10 * time.Minute)
defer store.Dispose()

_ = store.Set(ctx, "sess:abc", session, 30*time.Minute)
sess, found, err := store.Get(ctx, "sess:abc")
```

Use this for single-instance caching or local dev; use
[`cache/rediscache`](../rediscache) when cached values must be shared across
instances.

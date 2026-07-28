# health/redis

Redis health check for [`health.Checker`](..), backed by
[`redis/go-redis`](https://github.com/redis/go-redis).

```go
func Check(client *redis.Client, tags ...string) health.Check
```

Probes the client with `PING` and reports `Healthy`, `Degraded` (latency
> 100ms), or `Unhealthy`; `tags` are attached to the resulting `Entry` so
consumers can filter checks by tag (e.g. `ready` vs `live`).

## Usage

```go
checker := health.NewChecker()
checker.Register("redis", redis.Check(client, "cache", "ready"))
```

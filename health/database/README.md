# health/database

Postgres health check for [`health.Checker`](..), backed by
[`jackc/pgxpool`](https://github.com/jackc/pgx).

```go
func Check(pool *pgxpool.Pool, tags ...string) health.Check
```

Probes the pool (connectivity + a trivial query) and reports `Healthy` or
`Unhealthy` accordingly; `tags` are attached to the resulting `Entry` so
consumers can filter checks by tag (e.g. `ready` vs `live`).

## Usage

```go
checker := health.NewChecker()
checker.Register("postgres", database.Check(pool, "db", "ready"))
```

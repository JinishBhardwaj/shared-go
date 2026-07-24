# health

Transport-agnostic health-check aggregation, response shape matching the
ASP.NET Core HealthChecks-UI format.

This package has no knowledge of HTTP or any web framework: register checks
on a `Checker`, call `Run` to get a `Response`, and let the consuming
application decide how to expose it (e.g. a gin `/health` route) and what
status code to emit.

```go
type Check func(ctx context.Context) Entry

checker := health.NewChecker()
checker.Register("postgres", database.Check(pool, "db", "ready"))

resp := checker.Run(ctx) // runs all registered checks concurrently
```

`Response.Status` is the worst of any entry
(`Unhealthy` > `Degraded` > `Healthy`); with no registered checks it reports
`Healthy` with an empty entries map. Each `Entry.Duration` and
`Response.TotalDuration` are formatted via `FormatDuration` in the .NET
`TimeSpan` format (`hh:mm:ss.fffffff`) the HealthChecks-UI expects.

## Concrete checks

| Package | Checks |
|---|---|
| [`health/database`](database) | Postgres, via a `pgxpool.Pool` |

Additional checks (message bus, generic services) live in their own sibling
packages so this core module stays dependency-free.

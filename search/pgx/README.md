# search/pgx

PostgreSQL execution adapter for the driver-agnostic [`search`](../) core. Runs a
compiled search query against pgx: assembles the final SELECT, fetches the page
and total count **in parallel**, wires the core `Counter` to real exact /
planner-estimate queries, and applies the empty-first-page correction.


## Design

This module depends on **neither** `repo` nor `repo/pgx`. It works against a
narrow `Querier` interface (Select / Count / QueryRow) whose method set matches
`repo/pgx.BaseReader` exactly — so a caller already holding a `*repo/pgx.BaseReader`
passes it straight in (Go interfaces are structural), while others use the
built-in pool querier. Three layers:

- `search` (core) — **builds** the SQL (`CompiledQuery`)
- a `Querier` (`repo/pgx.BaseReader` or the built-in) — **executes** + scans
- `search/pgx` — **orchestrates** compile → parallel count+data → paged result

## Usage

```go
// Built-in pool querier:
s := searchpgx.NewFromPool(pool)

// …or reuse an existing repo/pgx.BaseReader (structural match, no import coupling):
s := searchpgx.New(baseReader)

var rows []RegistryRow
vm, err := s.Search(ctx, cfg, req,
    searchpgx.Table{Columns: "r.*", From: "registry r"},
    &rows,
    search.WithTenant(tenantID), // optional
)
if err != nil {
    switch {
    case search.IsValidationError(err):   // → 400 / 422
    case searchpgx.IsQueryTimeout(err):    // → 408
    default:                               // → 500
    }
    return
}
// rows is the page; vm is the pagination envelope (TotalCount, TotalPages, IsEstimatedCount…)
```

`Table.Columns` and `Table.From` are trusted, code-supplied SQL — never request
input. All filter/sort values are bound as `$N` parameters by the core; column
identifiers come only from the resource's `FieldConfig` whitelist.

## Counting

`Search` drives the resource's `Counter` (default `AdaptiveCounter`) with two
real queries:

- exact: `SELECT COUNT(*) FROM <from> [WHERE …]`
- estimate: `EXPLAIN (FORMAT JSON) SELECT 1 FROM <from> [WHERE …]` → `search.ParseExplainEstimate`

On an adaptive timeout the planner estimate is returned (`IsEstimatedCount=true`);
an empty first page is corrected to an exact `0` regardless of the estimate.

## Timeouts

`IsQueryTimeout(err)` reports a context deadline/cancellation or PostgreSQL
`SQLSTATE 57014` (query cancelled) — map it to HTTP 408. This pgconn-coupled
concern is intentionally kept out of the driver-agnostic core.

## Testing

Logic is covered by fast, DB-free tests (fake `Querier` for orchestration +
empty-page correction, pure SQL-assembly assertions, timeout classification).
Real-database validation belongs at the consuming service's integration layer —
this library deliberately avoids a testcontainers/docker dependency.

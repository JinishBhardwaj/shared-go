# Search

Driver-agnostic, reusable server-side search for list endpoints: a generic
request contract, a per-resource field validator, and a compiler that turns a
search request into parameterised SQL (`WHERE` / `ORDER BY` / `LIMIT-OFFSET`)
plus its bound arguments.

The core imports **no** database driver, ORM, or transport — no GORM, no pgx,
no protobuf. It emits a `CompiledQuery`; a thin adapter (`search/pgx`,
`search/gorm`) executes it. Counting is expressed against injected `CountFunc`
closures, so the package depends only on abstractions (Dependency Inversion).


## Status

Core scaffolded and unit-tested. Execution adapters (`search/pgx`, `search/gorm`)
are not yet implemented — see [Roadmap](#roadmap).

## Concepts

| Type             | Role                                                                               |
|------------------|------------------------------------------------------------------------------------|
| `RequestBody`    | generic search request (terms, filters, sort, pagination)                          |
| `ResourceConfig` | per-resource source of truth: fields, default sort, limits, tenant column, counter |
| `FieldConfig`    | one field's type, column, allowed operators, sort/search flags                     |
| `CompiledQuery`  | `{Where, OrderBy, Limit, Args}` — parameterised SQL fragments                      |
| `FieldResolver`  | Strategy: builds the predicate for one field                                       |
| `Counter`        | Strategy: exact vs adaptive (planner-estimate fallback) counting                   |
| `Registry`       | thread-safe name → `ResourceConfig` lookup                                         |

### Built-in resolvers

- `DirectColumnResolver` — `column <op> value` with typed coercion + cast (default; covers primary-key UUID fields via `FieldUUID`).
- `SubqueryResolver` — relationship predicate from a `%s` template (e.g. `EXISTS (...)`).
- `FieldResolverFunc` — adapt any func to a `FieldResolver`.

Domain-specific resolvers (e.g. data-managers' order-id routing between a UUID
and a short-id column) live with their domain and plug in via
`FieldConfig.Resolver` — the core stays domain-neutral.

### Operators

`eq ne gt gte lt lte like ilike not_like not_ilike in not_in is_null is_not_null between`

## Usage

```go
cfg := &search.ResourceConfig{
    Name:         "registry",
    TenantColumn: "r.tenant_id",   // optional; scope via WithTenant(...)
    MaxPageSize:  50,
    DefaultSort:  search.SortConfig{Field: "name", Direction: search.SortAsc},
    Fields: map[string]search.FieldConfig{
        "name": {Type: search.FieldString, Column: "r.name", Sortable: true, Searchable: true},
        "id":   {Type: search.FieldUUID, Column: "r.id", AllowedOperators: []string{search.OpEq, search.OpIn}},
    },
}

if err := cfg.Validate(&req); err != nil { /* → 400/422 via errors.As */ }

q, err := cfg.Compile(req, search.WithTenant(tenantID))
// q.Where, q.OrderBy, q.Limit, q.Args → hand to your driver

// SELECT ... FROM registry r [WHERE q.Where] q.OrderBy q.Limit  -- with q.Args
```

### Counting

```go
res, err := cfg.Count(ctx,
    func(ctx context.Context) (int64, error) { /* exact COUNT(*) */ },
    func(ctx context.Context) (int64, error) { /* planner estimate via EXPLAIN */ },
)
res = search.CorrectEmptyFirstPage(res, req.Pagination, len(rows))
view := search.NewPagedViewModel(req.Pagination, res.Count, res.IsEstimated, cfg.MaxPageSize)
```

Default counter is `AdaptiveCounter` (exact within a timeout, else planner
estimate). `ParseExplainEstimate` parses `EXPLAIN (FORMAT JSON)` output — EXPLAIN
a `SELECT`, not `COUNT(*)`, so `Plan Rows` reflects matching rows.

## Errors

All request-level errors implement `ValidationError` (`IsValidationError(err)`):
`InvalidFieldError`, `UnsupportedOperatorError`, `FieldNotSortableError`,
`InvalidValueTypeError` (→ 422), `PageOutOfRangeError`. `UnknownResourceError`
(from the registry) is a routing error (→ 404), intentionally not a
`ValidationError`.

## Safety

Column names come only from `FieldConfig` (a whitelist); values are always
bound through the `add()` closure as `$N` placeholders — never interpolated.
Wildcard search escapes literal `%`, `_`, `\` before translating `*`→`%`, `?`→`_`.

## Roadmap

- `search/pgx` — execute `CompiledQuery` against `pgxpool`; EXPLAIN estimate;
  parallel count+data; timeout classification (`57014` → 408).
- `search/gorm` — adapter for GORM-based data layers.

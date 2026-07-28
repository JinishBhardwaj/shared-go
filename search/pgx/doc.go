// Package pgx executes the driver-agnostic search core's CompiledQuery against a
// PostgreSQL backend using jackc/pgx.
//
// It assembles the final SELECT (caller-supplied columns + FROM, plus the core's
// WHERE / ORDER BY / LIMIT-OFFSET), runs the data fetch and the total count in
// parallel, wires the core Counter to real exact / planner-estimate queries, and
// applies the empty-first-page correction.
//
// It does NOT depend on any repo package. Instead it works against a
// narrow Querier interface (Select / Count / QueryRow) — so a caller already
// holding a compatible reader can pass it straight in (Go interfaces are
// structural), while callers without it use NewFromPool for the built-in
// scany-backed querier. This keeps the adapter independent of any repo module.
package pgx

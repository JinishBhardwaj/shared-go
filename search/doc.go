// Package search is a driver-agnostic, reusable server-side search layer for
// list endpoints: a generic request contract, a per-resource field validator,
// and a compiler that turns a search request into parameterised SQL (WHERE /
// ORDER BY / LIMIT-OFFSET) plus its bound arguments.
//
// The core imports no database driver, ORM, or transport (no GORM, no pgx, no
// protobuf). It emits a CompiledQuery{Where, OrderBy, Limit, Args}; the caller
// (or a thin adapter such as search/pgx or search/gorm) executes it. Counting is
// likewise expressed against injected CountFunc closures, so the package depends
// only on abstractions (Dependency Inversion), never on a concrete data store.
//
// Extension points are Strategy interfaces — FieldResolver for per-field
// predicate building and Counter for total-count behaviour — so new resources
// and behaviours are added without modifying the compiler (Open/Closed).
//
// Placeholder dialect: the compiler binds arguments through an injected `add`
// closure that returns the placeholder text, defaulting to PostgreSQL-style
// $1…$N. An adapter targeting a different dialect supplies its own closure.
package search

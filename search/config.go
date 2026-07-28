package search

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// FieldConfig is the single definition of one field's search behaviour.
type FieldConfig struct {
	Type             FieldType
	Column           string   // SQL column/expression, e.g. "t.name" (used by the default resolver)
	AllowedOperators []string // permitted operators; empty/nil = all
	Sortable         bool     // may appear in sort_fields / ORDER BY
	Searchable       bool     // matched (ILIKE) by free-text search_terms
	CaseInsensitive  bool     // reserved: force ILIKE for exact matches on this field
	// Resolver overrides how this field's predicate is built (Strategy). nil ⇒
	// DirectColumnResolver{Column, Type}. Use for relationship/derived filters.
	Resolver FieldResolver
}

// ResourceConfig is the single source of truth for a resource's search: its
// fields, default sort, count strategy, and limits. It owns validation, SQL
// compilation, and counting.
type ResourceConfig struct {
	Name        string
	Fields      map[string]FieldConfig
	DefaultSort SortConfig
	Counter     Counter // nil ⇒ AdaptiveCounter{}
	// TenantColumn, when non-empty, scopes every query to a tenant via
	// WithTenant(value) at Compile time. Empty ⇒ no tenant scoping (admin path).
	TenantColumn string
	// MaxPageSize caps a page for this resource (0 ⇒ DefaultMaxPageSize).
	MaxPageSize int
	// MaxBulkTerms caps the number of free-text search terms (0 ⇒ unlimited).
	MaxBulkTerms int
}

// CompiledQuery is the SQL produced from a request (placeholders $1…$N).
type CompiledQuery struct {
	Where   string // condition fragment without leading "WHERE" ("" if none)
	OrderBy string // "ORDER BY …" ("" if none)
	Limit   string // "LIMIT n OFFSET m"
	Args    []any
}

// CompileOption tunes a Compile call (e.g. tenant scoping).
type CompileOption func(*compileState)

type compileState struct {
	tenantValue string
	hasTenant   bool
}

// WithTenant scopes the compiled query to the resource's TenantColumn. It is a
// no-op if the resource has no TenantColumn configured.
func WithTenant(value string) CompileOption {
	return func(s *compileState) {
		s.tenantValue = value
		s.hasTenant = true
	}
}

// maxPageSize resolves the effective page-size cap for this resource.
func (c *ResourceConfig) maxPageSize() int {
	if c.MaxPageSize > 0 {
		return c.MaxPageSize
	}
	return DefaultMaxPageSize
}

// PageSize returns the clamped page size for a request against this resource.
func (c *ResourceConfig) PageSize(p Pagination) int { return p.SizeWithMax(c.maxPageSize()) }

// Validate rejects filters/sorts referencing unknown fields, disallowed
// operators, non-sortable fields, or too many bulk terms. Returns a
// ValidationError (→ 400).
func (c *ResourceConfig) Validate(req *RequestBody) error {
	if c.MaxBulkTerms > 0 {
		// Count only the terms Compile would actually use: blank and
		// all-wildcard terms are skipped during compilation, so they must not
		// count against the limit (keeps Validate and Compile consistent).
		effective := 0
		for _, t := range req.SearchTerms {
			if t = strings.TrimSpace(t); t == "" || IsAllWildcard(t) {
				continue
			}
			effective++
		}
		if effective > c.MaxBulkTerms {
			return &InvalidValueTypeError{
				Field:    "search_terms",
				Expected: fmt.Sprintf("at most %d terms", c.MaxBulkTerms),
				Got:      fmt.Sprintf("%d terms", effective),
			}
		}
	}
	for _, f := range req.Filters {
		if _, err := c.validateFilter(f); err != nil {
			return err
		}
	}
	for _, s := range req.SortFields {
		fc, ok := c.Fields[s.Field]
		if !ok {
			return &InvalidFieldError{Field: s.Field, Resource: c.Name}
		}
		if !fc.Sortable {
			return &FieldNotSortableError{Field: s.Field, Resource: c.Name}
		}
	}
	return nil
}

// validateFilter checks one filter's field and operator allow-list, returning
// the field config for reuse by Compile.
func (c *ResourceConfig) validateFilter(f FilterParameter) (FieldConfig, error) {
	fc, ok := c.Fields[f.Field]
	if !ok {
		return FieldConfig{}, &InvalidFieldError{Field: f.Field, Resource: c.Name}
	}
	if len(fc.AllowedOperators) == 0 {
		return fc, nil // all operators allowed
	}
	op := strings.ToLower(f.Operator)
	if !contains(fc.AllowedOperators, op) {
		return FieldConfig{}, &UnsupportedOperatorError{Field: f.Field, Operator: f.Operator}
	}
	return fc, nil
}

// Compile turns a request into parameterised SQL. It re-checks each filter's
// field and operator allow-list (so a caller that skips Validate cannot smuggle
// a disallowed operator through) before delegating predicate construction to
// the field's resolver.
func (c *ResourceConfig) Compile(req RequestBody, opts ...CompileOption) (CompiledQuery, error) {
	var st compileState
	for _, o := range opts {
		o(&st)
	}

	var args []any
	add := func(v any) string { args = append(args, v); return fmt.Sprintf("$%d", len(args)) }

	var conds []string
	if c.TenantColumn != "" && st.hasTenant {
		conds = append(conds, fmt.Sprintf("%s = %s", c.TenantColumn, add(st.tenantValue)))
	}
	if term := c.buildSearchTerms(req.SearchTerms, add); term != "" {
		conds = append(conds, term)
	}
	for _, f := range req.Filters {
		fc, err := c.validateFilter(f)
		if err != nil {
			return CompiledQuery{}, err
		}
		frag, err := c.resolver(f.Field, fc).Resolve(strings.ToLower(f.Operator), f.Value, add)
		if err != nil {
			return CompiledQuery{}, err
		}
		if frag != "" {
			conds = append(conds, frag)
		}
	}

	return CompiledQuery{
		Where:   strings.Join(conds, " AND "),
		OrderBy: c.buildOrderBy(req.SortFields),
		Limit:   fmt.Sprintf("LIMIT %d OFFSET %d", c.PageSize(req.Pagination), req.Pagination.OffsetWithMax(c.maxPageSize())),
		Args:    args,
	}, nil
}

// Count applies the resource's Counter strategy (default AdaptiveCounter).
func (c *ResourceConfig) Count(ctx context.Context, exact, estimate CountFunc) (CountResult, error) {
	counter := c.Counter
	if counter == nil {
		counter = AdaptiveCounter{}
	}
	return counter.Count(ctx, exact, estimate)
}

// resolver returns the field's resolver, defaulting to a direct column resolver.
func (c *ResourceConfig) resolver(field string, fc FieldConfig) FieldResolver {
	if fc.Resolver != nil {
		return fc.Resolver
	}
	return DirectColumnResolver{Column: fc.Column, Type: fc.Type, Field: field}
}

// buildSearchTerms ORs each term across the Searchable columns, then ORs the
// terms. Wildcards: * → %, ? → _.
func (c *ResourceConfig) buildSearchTerms(terms []string, add func(any) string) string {
	cols := c.searchColumns()
	if len(cols) == 0 {
		return ""
	}
	var termConds []string
	for _, t := range terms {
		t = strings.TrimSpace(t)
		if t == "" || IsAllWildcard(t) {
			continue
		}
		ph := add(wildcardToLike(t))
		colConds := make([]string, len(cols))
		for i, col := range cols {
			colConds[i] = fmt.Sprintf("%s ILIKE %s", col, ph)
		}
		termConds = append(termConds, "("+strings.Join(colConds, " OR ")+")")
	}
	if len(termConds) == 0 {
		return ""
	}
	return "(" + strings.Join(termConds, " OR ") + ")"
}

// searchColumns returns the searchable columns in a stable order (sorted by
// column name) so generated SQL is deterministic across runs.
func (c *ResourceConfig) searchColumns() []string {
	var cols []string
	for _, fc := range c.Fields {
		if fc.Searchable && fc.Column != "" {
			cols = append(cols, fc.Column)
		}
	}
	sort.Strings(cols)
	return cols
}

func (c *ResourceConfig) buildOrderBy(sorts []SortField) string {
	var parts []string
	for _, s := range sorts {
		fc, ok := c.Fields[s.Field]
		if !ok || !fc.Sortable {
			continue
		}
		parts = append(parts, fc.Column+" "+sqlDirection(s.Direction))
	}
	if len(parts) == 0 {
		if c.DefaultSort.Field == "" {
			return ""
		}
		if fc, ok := c.Fields[c.DefaultSort.Field]; ok {
			return "ORDER BY " + fc.Column + " " + sqlDirection(string(c.DefaultSort.Direction))
		}
		return ""
	}
	return "ORDER BY " + strings.Join(parts, ", ")
}

func sqlDirection(dir string) string {
	if strings.EqualFold(dir, "desc") {
		return "DESC"
	}
	return "ASC"
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

package search

import (
	"fmt"
	"strings"
)

// Supported operators (lower-cased), matching the search contract.
const (
	OpEq        = "eq"
	OpNe        = "ne"
	OpGt        = "gt"
	OpGte       = "gte"
	OpLt        = "lt"
	OpLte       = "lte"
	OpLike      = "like"
	OpILike     = "ilike"
	OpNotLike   = "not_like"
	OpNotILike  = "not_ilike"
	OpIn        = "in"
	OpNotIn     = "not_in"
	OpIsNull    = "is_null"
	OpIsNotNull = "is_not_null"
	OpBetween   = "between"
)

var comparisonSQL = map[string]string{
	OpEq: "=", OpNe: "<>", OpGt: ">", OpGte: ">=", OpLt: "<", OpLte: "<=",
	OpLike: "LIKE", OpILike: "ILIKE", OpNotLike: "NOT LIKE", OpNotILike: "NOT ILIKE",
}

// FieldResolver builds the SQL predicate for a filter on one field. It is the
// Strategy that lets a resource extend filtering (e.g. relationship sub-queries)
// without changing the compiler. `add(v)` binds a value and returns its "$N"
// placeholder, keeping argument numbering centralised in the compiler.
type FieldResolver interface {
	Resolve(op string, value any, add func(any) string) (string, error)
}

// FieldResolverFunc adapts a plain func to a FieldResolver — for relationship /
// derived filters (e.g. an EXISTS sub-query) that aren't a simple column.
type FieldResolverFunc func(op string, value any, add func(any) string) (string, error)

func (f FieldResolverFunc) Resolve(op string, value any, add func(any) string) (string, error) {
	return f(op, value, add)
}

// DirectColumnResolver is the default Strategy: a plain "column <op> value"
// predicate, casting the bound parameter per the field's type (e.g. ::uuid).
// Field carries the request field name only for error reporting.
type DirectColumnResolver struct {
	Column string
	Type   FieldType
	Field  string
}

func (r DirectColumnResolver) Resolve(op string, value any, add func(any) string) (string, error) {
	cast := r.Type.cast()
	ph := func(v any) string { return add(v) + cast }
	col := r.Column

	if sym, ok := comparisonSQL[op]; ok {
		v, err := coerceScalar(r.Field, r.Type, value)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s %s %s", col, sym, ph(v)), nil
	}
	switch op {
	case OpIn, OpNotIn:
		vals, err := coerceList(r.Field, r.Type, value)
		if err != nil {
			return "", err
		}
		if len(vals) == 0 {
			return "", &InvalidValueTypeError{Field: r.Field, Expected: "non-empty array", Got: "empty array"}
		}
		phs := make([]string, len(vals))
		for i, v := range vals {
			phs[i] = ph(v)
		}
		kw := "IN"
		if op == OpNotIn {
			kw = "NOT IN"
		}
		return fmt.Sprintf("%s %s (%s)", col, kw, strings.Join(phs, ", ")), nil
	case OpBetween:
		vals, err := coerceList(r.Field, r.Type, value)
		if err != nil {
			return "", err
		}
		if len(vals) != 2 {
			return "", &InvalidValueTypeError{Field: r.Field, Expected: "two-element array", Got: fmt.Sprintf("%d-element array", len(vals))}
		}
		return fmt.Sprintf("%s BETWEEN %s AND %s", col, ph(vals[0]), ph(vals[1])), nil
	case OpIsNull:
		return fmt.Sprintf("%s IS NULL", col), nil
	case OpIsNotNull:
		return fmt.Sprintf("%s IS NOT NULL", col), nil
	default:
		return "", &UnsupportedOperatorError{Field: r.Field, Operator: op}
	}
}

// SubqueryResolver builds a relationship predicate from a SQL template for
// filters that aren't a plain column (e.g. an EXISTS over a child table). The
// template must contain exactly one "%s" where the bound placeholder is
// substituted, e.g.
//
//	"EXISTS (SELECT 1 FROM tld_links l WHERE l.parent_id = t.id AND l.tld_id = %s)"
//
// Only equality-style single-value operators are supported; the value is bound
// through the compiler's add() so numbering stays centralised. Type drives the
// cast applied to the bound value.
type SubqueryResolver struct {
	Template string
	Type     FieldType
	Field    string
}

func (r SubqueryResolver) Resolve(op string, value any, add func(any) string) (string, error) {
	if strings.Count(r.Template, "%s") != 1 {
		return "", fmt.Errorf("search: SubqueryResolver template for %q must contain exactly one %%s", r.Field)
	}
	switch op {
	case OpEq:
		v, err := coerceScalar(r.Field, r.Type, value)
		if err != nil {
			return "", err
		}
		ph := add(v) + r.Type.cast()
		return fmt.Sprintf(r.Template, ph), nil
	default:
		// Only single-value equality is supported: the template carries exactly
		// one placeholder, so list operators (in/between) cannot be expressed.
		return "", &UnsupportedOperatorError{Field: r.Field, Operator: op}
	}
}

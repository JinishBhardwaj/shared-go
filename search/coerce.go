package search

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// dateLayouts are accepted, in order, for FieldDate values.
var dateLayouts = []string{time.RFC3339, "2006-01-02"}

// coerceScalar validates and normalises a single JSON-decoded value against the
// field's declared type, returning the value to bind. JSON numbers arrive as
// float64 and strings as string; this keeps the bound argument well-typed so
// the driver and the column cast agree.
func coerceScalar(field string, t FieldType, value any) (any, error) {
	if value == nil {
		return nil, &InvalidValueTypeError{Field: field, Expected: typeName(t), Got: "null"}
	}
	switch t {
	case FieldString, FieldUUID, FieldArray:
		switch v := value.(type) {
		case string:
			return v, nil
		default:
			return nil, &InvalidValueTypeError{Field: field, Expected: typeName(t), Got: goType(value)}
		}
	case FieldInt:
		switch v := value.(type) {
		case float64:
			// JSON numbers decode to float64. Reject fractional values and
			// magnitudes outside int64 rather than silently truncating (3.7→3)
			// or producing an implementation-defined cast result.
			if v != math.Trunc(v) {
				return nil, &InvalidValueTypeError{Field: field, Expected: "integer", Got: fmt.Sprintf("fractional number %v", v)}
			}
			if v < math.MinInt64 || v >= math.MaxInt64 {
				return nil, &InvalidValueTypeError{Field: field, Expected: "integer within int64 range", Got: fmt.Sprintf("%v", v)}
			}
			return int64(v), nil
		case int:
			return int64(v), nil
		case int64:
			return v, nil
		case string:
			n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return nil, &InvalidValueTypeError{Field: field, Expected: "integer", Got: fmt.Sprintf("string %q", v)}
			}
			return n, nil
		default:
			return nil, &InvalidValueTypeError{Field: field, Expected: "integer", Got: goType(value)}
		}
	case FieldBool:
		switch v := value.(type) {
		case bool:
			return v, nil
		case string:
			b, err := strconv.ParseBool(strings.TrimSpace(v))
			if err != nil {
				return nil, &InvalidValueTypeError{Field: field, Expected: "boolean", Got: fmt.Sprintf("string %q", v)}
			}
			return b, nil
		default:
			return nil, &InvalidValueTypeError{Field: field, Expected: "boolean", Got: goType(value)}
		}
	case FieldDate:
		switch v := value.(type) {
		case time.Time:
			return v, nil
		case string:
			for _, layout := range dateLayouts {
				if ts, err := time.Parse(layout, strings.TrimSpace(v)); err == nil {
					return ts, nil
				}
			}
			return nil, &InvalidValueTypeError{Field: field, Expected: "RFC3339 or YYYY-MM-DD date", Got: fmt.Sprintf("string %q", v)}
		default:
			return nil, &InvalidValueTypeError{Field: field, Expected: "date", Got: goType(value)}
		}
	default:
		return value, nil
	}
}

// coerceList normalises a JSON value used with in / not_in / between into a
// slice of bound values. Accepts a JSON array ([]any), a comma-separated string
// (for FieldArray), or a single scalar (wrapped into a one-element slice).
func coerceList(field string, t FieldType, value any) ([]any, error) {
	switch v := value.(type) {
	case []any:
		out := make([]any, len(v))
		for i, el := range v {
			cv, err := coerceScalar(field, t, el)
			if err != nil {
				return nil, err
			}
			out[i] = cv
		}
		return out, nil
	case string:
		// Comma-split convenience for array-shaped inputs.
		parts := strings.Split(v, ",")
		out := make([]any, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			cv, err := coerceScalar(field, t, p)
			if err != nil {
				return nil, err
			}
			out = append(out, cv)
		}
		return out, nil
	case nil:
		return nil, &InvalidValueTypeError{Field: field, Expected: "array", Got: "null"}
	default:
		cv, err := coerceScalar(field, t, value)
		if err != nil {
			return nil, err
		}
		return []any{cv}, nil
	}
}

func typeName(t FieldType) string {
	switch t {
	case FieldString:
		return "string"
	case FieldUUID:
		return "uuid string"
	case FieldInt:
		return "integer"
	case FieldBool:
		return "boolean"
	case FieldDate:
		return "date"
	case FieldArray:
		return "array element"
	default:
		return "value"
	}
}

func goType(v any) string { return fmt.Sprintf("%T", v) }

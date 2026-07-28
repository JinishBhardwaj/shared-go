package search

import (
	"errors"
	"fmt"
	"testing"
)

// newAdder returns a fresh $N placeholder closure and a pointer to its args,
// mirroring the compiler's argument-binding behaviour for resolver isolation.
func newAdder() (func(any) string, *[]any) {
	var args []any
	add := func(v any) string { args = append(args, v); return fmt.Sprintf("$%d", len(args)) }
	return add, &args
}

func TestDirectColumnResolver_Comparisons(t *testing.T) {
	cases := []struct {
		op   string
		want string
	}{
		{OpEq, "r.rank = $1::bigint"},
		{OpNe, "r.rank <> $1::bigint"},
		{OpGt, "r.rank > $1::bigint"},
		{OpGte, "r.rank >= $1::bigint"},
		{OpLt, "r.rank < $1::bigint"},
		{OpLte, "r.rank <= $1::bigint"},
	}
	for _, tc := range cases {
		add, args := newAdder()
		r := DirectColumnResolver{Column: "r.rank", Type: FieldInt, Field: "rank"}
		got, err := r.Resolve(tc.op, 5.0, add)
		if err != nil {
			t.Fatalf("%s: %v", tc.op, err)
		}
		if got != tc.want {
			t.Errorf("%s = %q, want %q", tc.op, got, tc.want)
		}
		if len(*args) != 1 || (*args)[0] != int64(5) {
			t.Errorf("%s args = %#v", tc.op, *args)
		}
	}
}

func TestDirectColumnResolver_LikeNoCast(t *testing.T) {
	add, _ := newAdder()
	r := DirectColumnResolver{Column: "r.name", Type: FieldString, Field: "name"}
	got, err := r.Resolve(OpILike, "ac%", add)
	if err != nil {
		t.Fatalf("ilike: %v", err)
	}
	if got != "r.name ILIKE $1" {
		t.Errorf("got %q", got)
	}
}

func TestDirectColumnResolver_InNotIn(t *testing.T) {
	add, args := newAdder()
	r := DirectColumnResolver{Column: "r.id", Type: FieldUUID, Field: "id"}
	got, err := r.Resolve(OpIn, []any{"a", "b"}, add)
	if err != nil {
		t.Fatalf("in: %v", err)
	}
	if got != "r.id IN ($1::uuid, $2::uuid)" {
		t.Errorf("got %q", got)
	}
	if len(*args) != 2 {
		t.Errorf("args = %#v", *args)
	}

	add2, _ := newAdder()
	got, _ = r.Resolve(OpNotIn, []any{"a"}, add2)
	if got != "r.id NOT IN ($1::uuid)" {
		t.Errorf("not_in got %q", got)
	}

	// empty array → error
	add3, _ := newAdder()
	if _, err := r.Resolve(OpIn, []any{}, add3); !isInvalidValueType(err) {
		t.Errorf("empty in want InvalidValueTypeError, got %v", err)
	}
}

func TestDirectColumnResolver_Between(t *testing.T) {
	add, _ := newAdder()
	r := DirectColumnResolver{Column: "r.rank", Type: FieldInt, Field: "rank"}
	got, err := r.Resolve(OpBetween, []any{1.0, 9.0}, add)
	if err != nil {
		t.Fatalf("between: %v", err)
	}
	if got != "r.rank BETWEEN $1::bigint AND $2::bigint" {
		t.Errorf("got %q", got)
	}
	// wrong arity
	add2, _ := newAdder()
	if _, err := r.Resolve(OpBetween, []any{1.0}, add2); !isInvalidValueType(err) {
		t.Errorf("between arity want InvalidValueTypeError, got %v", err)
	}
}

func TestDirectColumnResolver_NullChecks(t *testing.T) {
	add, args := newAdder()
	r := DirectColumnResolver{Column: "r.deleted_at", Type: FieldDate, Field: "deleted_at"}
	got, _ := r.Resolve(OpIsNull, nil, add)
	if got != "r.deleted_at IS NULL" {
		t.Errorf("is_null got %q", got)
	}
	got, _ = r.Resolve(OpIsNotNull, nil, add)
	if got != "r.deleted_at IS NOT NULL" {
		t.Errorf("is_not_null got %q", got)
	}
	if len(*args) != 0 {
		t.Errorf("null checks should bind no args, got %#v", *args)
	}
}

func TestDirectColumnResolver_UnsupportedOperator(t *testing.T) {
	add, _ := newAdder()
	r := DirectColumnResolver{Column: "r.name", Type: FieldString, Field: "name"}
	_, err := r.Resolve("regex", "x", add)
	var ue *UnsupportedOperatorError
	if !errors.As(err, &ue) {
		t.Fatalf("want UnsupportedOperatorError, got %v", err)
	}
}

func TestDirectColumnResolver_CoercionErrorPropagates(t *testing.T) {
	add, _ := newAdder()
	r := DirectColumnResolver{Column: "r.rank", Type: FieldInt, Field: "rank"}
	if _, err := r.Resolve(OpEq, "not-a-number", add); !isInvalidValueType(err) {
		t.Errorf("want InvalidValueTypeError, got %v", err)
	}
}

func TestFieldResolverFunc(t *testing.T) {
	add, _ := newAdder()
	var fr FieldResolver = FieldResolverFunc(func(op string, v any, add func(any) string) (string, error) {
		return "custom(" + add(v) + ")", nil
	})
	got, err := fr.Resolve(OpEq, "x", add)
	if err != nil || got != "custom($1)" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestSubqueryResolver(t *testing.T) {
	add, args := newAdder()
	r := SubqueryResolver{
		Template: "EXISTS (SELECT 1 FROM links l WHERE l.parent = t.id AND l.child = %s)",
		Type:     FieldUUID,
		Field:    "child_id",
	}
	got, err := r.Resolve(OpEq, "11111111-2222-3333-4444-555555555555", add)
	if err != nil {
		t.Fatalf("subquery: %v", err)
	}
	want := "EXISTS (SELECT 1 FROM links l WHERE l.parent = t.id AND l.child = $1::uuid)"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
	if len(*args) != 1 {
		t.Errorf("args = %#v", *args)
	}

	// unsupported operators: only single-value eq is allowed (one placeholder)
	for _, op := range []string{OpGt, OpIn, OpBetween} {
		add2, _ := newAdder()
		if _, err := r.Resolve(op, "x", add2); err == nil {
			t.Errorf("%s should be unsupported by SubqueryResolver", op)
		}
	}

	// bad template (no %s)
	add3, _ := newAdder()
	bad := SubqueryResolver{Template: "EXISTS (...)", Type: FieldUUID, Field: "x"}
	if _, err := bad.Resolve(OpEq, "11111111-2222-3333-4444-555555555555", add3); err == nil {
		t.Error("template lacking a placeholder should error")
	}
}

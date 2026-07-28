package search

import (
	"errors"
	"testing"
	"time"
)

func TestCoerceScalar_String(t *testing.T) {
	got, err := coerceScalar("name", FieldString, "acme")
	if err != nil || got != "acme" {
		t.Fatalf("got %#v, err %v", got, err)
	}
	if _, err := coerceScalar("name", FieldString, 42.0); !isInvalidValueType(err) {
		t.Errorf("non-string should be InvalidValueTypeError, got %v", err)
	}
	if _, err := coerceScalar("name", FieldString, nil); !isInvalidValueType(err) {
		t.Errorf("nil should be InvalidValueTypeError, got %v", err)
	}
}

func TestCoerceScalar_Int(t *testing.T) {
	cases := []struct {
		in   any
		want int64
	}{
		{float64(7), 7}, // JSON numbers decode to float64
		{int(7), 7},
		{int64(7), 7},
		{"7", 7},
		{" 7 ", 7},
	}
	for _, tc := range cases {
		got, err := coerceScalar("rank", FieldInt, tc.in)
		if err != nil {
			t.Fatalf("coerceScalar(%#v): %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("coerceScalar(%#v) = %#v, want int64(%d)", tc.in, got, tc.want)
		}
	}
	for _, bad := range []any{"nope", true, nil, []any{1}, 3.7, 1e19, -1e19} {
		if _, err := coerceScalar("rank", FieldInt, bad); !isInvalidValueType(err) {
			t.Errorf("coerceScalar(%#v) want InvalidValueTypeError, got %v", bad, err)
		}
	}
	// integral float64 still accepted (JSON numbers always decode to float64)
	if got, err := coerceScalar("rank", FieldInt, float64(1<<40)); err != nil || got != int64(1<<40) {
		t.Errorf("integral float64 got %#v err %v", got, err)
	}
}

func TestCoerceScalar_Bool(t *testing.T) {
	for _, in := range []any{true, "true", "false", "1", "0"} {
		if _, err := coerceScalar("active", FieldBool, in); err != nil {
			t.Errorf("coerceScalar(%#v): %v", in, err)
		}
	}
	if got, _ := coerceScalar("active", FieldBool, "true"); got != true {
		t.Errorf(`"true" -> %#v`, got)
	}
	for _, bad := range []any{"maybe", 1.0, nil} {
		if _, err := coerceScalar("active", FieldBool, bad); !isInvalidValueType(err) {
			t.Errorf("coerceScalar(%#v) want InvalidValueTypeError, got %v", bad, err)
		}
	}
}

func TestCoerceScalar_Date(t *testing.T) {
	rfc, err := coerceScalar("created_at", FieldDate, "2024-03-02T15:04:05Z")
	if err != nil {
		t.Fatalf("RFC3339: %v", err)
	}
	if _, ok := rfc.(time.Time); !ok {
		t.Errorf("RFC3339 not time.Time: %#v", rfc)
	}
	dateOnly, err := coerceScalar("created_at", FieldDate, "2024-03-02")
	if err != nil {
		t.Fatalf("date-only: %v", err)
	}
	if ts := dateOnly.(time.Time); ts.Year() != 2024 || ts.Month() != 3 || ts.Day() != 2 {
		t.Errorf("date-only parsed wrong: %v", ts)
	}
	// passthrough of an already-typed time.Time
	now := time.Now()
	if got, _ := coerceScalar("created_at", FieldDate, now); !got.(time.Time).Equal(now) {
		t.Errorf("time.Time passthrough failed")
	}
	for _, bad := range []any{"03/02/2024", "not-a-date", 12345.0} {
		if _, err := coerceScalar("created_at", FieldDate, bad); !isInvalidValueType(err) {
			t.Errorf("coerceScalar(%#v) want InvalidValueTypeError, got %v", bad, err)
		}
	}
}

func TestCoerceScalar_UUID(t *testing.T) {
	const u = "11111111-2222-3333-4444-555555555555"
	if got, err := coerceScalar("id", FieldUUID, u); err != nil || got != u {
		t.Fatalf("uuid: got %#v err %v", got, err)
	}
	if _, err := coerceScalar("id", FieldUUID, 5.0); !isInvalidValueType(err) {
		t.Errorf("non-string uuid should fail, got %v", err)
	}
}

func TestCoerceList_Array(t *testing.T) {
	got, err := coerceList("rank", FieldInt, []any{1.0, 2.0, 3.0})
	if err != nil {
		t.Fatalf("coerceList: %v", err)
	}
	if len(got) != 3 || got[0] != int64(1) || got[2] != int64(3) {
		t.Errorf("got %#v", got)
	}
	// one bad element fails the whole list
	if _, err := coerceList("rank", FieldInt, []any{1.0, "x"}); !isInvalidValueType(err) {
		t.Errorf("bad element should fail, got %v", err)
	}
}

func TestCoerceList_CommaString(t *testing.T) {
	got, err := coerceList("tags", FieldArray, "a, b ,c,")
	if err != nil {
		t.Fatalf("coerceList: %v", err)
	}
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Errorf("comma split got %#v", got)
	}
}

func TestCoerceList_SingleScalarWrapped(t *testing.T) {
	got, err := coerceList("rank", FieldInt, 9.0)
	if err != nil {
		t.Fatalf("coerceList: %v", err)
	}
	if len(got) != 1 || got[0] != int64(9) {
		t.Errorf("single scalar wrap got %#v", got)
	}
}

func TestCoerceList_Nil(t *testing.T) {
	if _, err := coerceList("rank", FieldInt, nil); !isInvalidValueType(err) {
		t.Errorf("nil list want InvalidValueTypeError, got %v", err)
	}
}

func isInvalidValueType(err error) bool {
	var e *InvalidValueTypeError
	return errors.As(err, &e)
}

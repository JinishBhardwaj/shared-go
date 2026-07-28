package pgx

import "reflect"

// sliceLen returns the number of elements in dest, which the searcher expects to
// be a pointer to a slice (the scan destination). If dest is not a pointer to a
// slice it returns 1, which is a safe non-zero value: CorrectEmptyFirstPage only
// acts on a zero-length first page, so an unintrospectable dest never triggers a
// spurious count correction.
func sliceLen(dest any) int {
	v := reflect.ValueOf(dest)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return 1
	}
	v = v.Elem()
	if v.Kind() != reflect.Slice {
		return 1
	}
	return v.Len()
}

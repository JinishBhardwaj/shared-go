package search

import (
	"errors"
	"fmt"
)

// ValidationError is the common interface implemented by every request-level
// error this package returns. Boundaries map it to HTTP 400 (or a more specific
// status for the typed variants below) via errors.As. Its message is safe to
// surface to the caller.
type ValidationError interface {
	error
	isValidationError()
}

// IsValidationError reports whether err (or anything it wraps) is a
// request-level ValidationError from this package.
func IsValidationError(err error) bool {
	var v ValidationError
	return errors.As(err, &v)
}

// InvalidFieldError: the request referenced a field not present in the resource
// config. → HTTP 400.
type InvalidFieldError struct {
	Field    string
	Resource string
}

func (e *InvalidFieldError) Error() string {
	return fmt.Sprintf("field %q is not a valid field for resource %q", e.Field, e.Resource)
}
func (*InvalidFieldError) isValidationError() {}

// UnsupportedOperatorError: the operator is not in the field's allow-list. → 400.
type UnsupportedOperatorError struct {
	Field    string
	Operator string
}

func (e *UnsupportedOperatorError) Error() string {
	return fmt.Sprintf("operator %q is not supported for field %q", e.Operator, e.Field)
}
func (*UnsupportedOperatorError) isValidationError() {}

// FieldNotSortableError: a sort referenced a non-sortable field. → 400.
type FieldNotSortableError struct {
	Field    string
	Resource string
}

func (e *FieldNotSortableError) Error() string {
	return fmt.Sprintf("field %q is not sortable for resource %q", e.Field, e.Resource)
}
func (*FieldNotSortableError) isValidationError() {}

// InvalidValueTypeError: a filter value could not be coerced to the field's
// declared type, or had the wrong shape for the operator. → HTTP 422.
type InvalidValueTypeError struct {
	Field    string
	Expected string
	Got      string
}

func (e *InvalidValueTypeError) Error() string {
	return fmt.Sprintf("field %q expects %s, got %s", e.Field, e.Expected, e.Got)
}
func (*InvalidValueTypeError) isValidationError() {}

// PageOutOfRangeError: requested page beyond the available range. → HTTP 400.
type PageOutOfRangeError struct {
	Page       int
	TotalPages int
}

func (e *PageOutOfRangeError) Error() string {
	return fmt.Sprintf("page %d is out of range (total pages: %d)", e.Page, e.TotalPages)
}
func (*PageOutOfRangeError) isValidationError() {}

// UnknownResourceError: the registry has no config for the named resource. This
// is a routing/config error, not a client input error — boundaries typically
// map it to HTTP 404. It deliberately does NOT implement ValidationError.
type UnknownResourceError struct {
	Resource string
}

func (e *UnknownResourceError) Error() string {
	return fmt.Sprintf("unknown search resource %q", e.Resource)
}

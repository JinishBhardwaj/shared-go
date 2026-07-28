package search

import (
	"errors"
	"fmt"
	"testing"
)

func TestIsValidationError(t *testing.T) {
	validationErrs := []error{
		&InvalidFieldError{Field: "f", Resource: "r"},
		&UnsupportedOperatorError{Field: "f", Operator: "regex"},
		&FieldNotSortableError{Field: "f", Resource: "r"},
		&InvalidValueTypeError{Field: "f", Expected: "int", Got: "string"},
		&PageOutOfRangeError{Page: 9, TotalPages: 2},
	}
	for _, err := range validationErrs {
		if !IsValidationError(err) {
			t.Errorf("%T should be a ValidationError", err)
		}
	}

	// not validation errors
	notValidation := []error{
		&UnknownResourceError{Resource: "x"}, // routing error → 404
		errors.New("plain"),
		nil,
	}
	for _, err := range notValidation {
		if IsValidationError(err) {
			t.Errorf("%v should NOT be a ValidationError", err)
		}
	}
}

func TestValidationError_UnwrapsThroughWrap(t *testing.T) {
	wrapped := fmt.Errorf("compile failed: %w", &InvalidFieldError{Field: "f", Resource: "r"})
	if !IsValidationError(wrapped) {
		t.Error("IsValidationError should see through fmt.Errorf wrapping")
	}
	var fe *InvalidFieldError
	if !errors.As(wrapped, &fe) || fe.Field != "f" {
		t.Errorf("errors.As failed to extract InvalidFieldError: %v", wrapped)
	}
}

func TestErrorMessages(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{&InvalidFieldError{Field: "name", Resource: "registry"}, `field "name" is not a valid field for resource "registry"`},
		{&UnsupportedOperatorError{Field: "id", Operator: "gt"}, `operator "gt" is not supported for field "id"`},
		{&FieldNotSortableError{Field: "active", Resource: "registry"}, `field "active" is not sortable for resource "registry"`},
		{&InvalidValueTypeError{Field: "rank", Expected: "integer", Got: "string"}, `field "rank" expects integer, got string`},
		{&UnknownResourceError{Resource: "ghost"}, `unknown search resource "ghost"`},
	}
	for _, tc := range cases {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("Error() = %q, want %q", got, tc.want)
		}
	}
}

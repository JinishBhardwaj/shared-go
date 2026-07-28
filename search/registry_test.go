package search

import (
	"errors"
	"testing"
)

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := NewRegistry()
	cfg := &ResourceConfig{Name: "registry"}
	r.Register(cfg)
	got, err := r.Get("registry")
	if err != nil || got != cfg {
		t.Fatalf("Get = %v, %v", got, err)
	}
}

func TestRegistry_UnknownResource(t *testing.T) {
	r := NewRegistry()
	_, err := r.Get("missing")
	var ue *UnknownResourceError
	if !errors.As(err, &ue) {
		t.Fatalf("want UnknownResourceError, got %v", err)
	}
	// routing error, not a ValidationError
	if IsValidationError(err) {
		t.Error("UnknownResourceError must not be a ValidationError")
	}
}

func TestRegistry_DuplicatePanics(t *testing.T) {
	r := NewRegistry()
	r.Register(&ResourceConfig{Name: "dup"})
	defer func() {
		if recover() == nil {
			t.Error("duplicate Register should panic")
		}
	}()
	r.Register(&ResourceConfig{Name: "dup"})
}

func TestRegistry_EmptyNamePanics(t *testing.T) {
	r := NewRegistry()
	defer func() {
		if recover() == nil {
			t.Error("empty name should panic")
		}
	}()
	r.Register(&ResourceConfig{Name: ""})
}

func TestRegistry_NilConfigPanics(t *testing.T) {
	r := NewRegistry()
	defer func() {
		if recover() == nil {
			t.Error("nil config should panic")
		}
	}()
	r.Register(nil)
}

func TestRegistry_Names(t *testing.T) {
	r := NewRegistry()
	r.Register(&ResourceConfig{Name: "a"})
	r.Register(&ResourceConfig{Name: "b"})
	names := r.Names()
	if len(names) != 2 {
		t.Fatalf("Names = %v", names)
	}
	set := map[string]bool{names[0]: true, names[1]: true}
	if !set["a"] || !set["b"] {
		t.Errorf("Names = %v, want a and b", names)
	}
}

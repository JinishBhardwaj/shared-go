package search

import "testing"

func TestTranslateWildcard(t *testing.T) {
	cases := []struct {
		in      string
		pattern string
		typ     WildcardPattern
	}{
		{"ac*", "ac%", PatternPrefix},
		{"*ac*", "%ac%", PatternContains},
		{"a?b", "a_b", PatternContains},
		{"plain", "plain", PatternExact},
		{"a_b%c", `a\_b\%c`, PatternExact},  // literals escaped, no user wildcards
		{`a\b`, `a\\b`, PatternExact},       // backslash escaped
		{"a*_b", `a%\_b`, PatternContains},  // mix: * translated, literal _ escaped
		{"pre*x", "pre%x", PatternContains}, // % not at end → contains
		{"100%*", `100\%%`, PatternPrefix},  // literal % escaped, trailing * → still a pure prefix
	}
	for _, tc := range cases {
		got := TranslateWildcard(tc.in)
		if got.Pattern != tc.pattern || got.PatternType != tc.typ {
			t.Errorf("TranslateWildcard(%q) = {%q, %v}, want {%q, %v}",
				tc.in, got.Pattern, got.PatternType, tc.pattern, tc.typ)
		}
	}
}

func TestIsAllWildcard(t *testing.T) {
	for _, in := range []string{"", "*", "***", "?", "*?*"} {
		if !IsAllWildcard(in) {
			t.Errorf("IsAllWildcard(%q) = false, want true", in)
		}
	}
	for _, in := range []string{"a", "*a", "a*", " "} {
		if IsAllWildcard(in) {
			t.Errorf("IsAllWildcard(%q) = true, want false", in)
		}
	}
}

func TestWildcardToLike(t *testing.T) {
	if got := wildcardToLike("ac*"); got != "ac%" {
		t.Errorf("wildcardToLike = %q", got)
	}
}

package search

import "strings"

// WildcardPattern classifies a translated LIKE pattern so callers can reason
// about index usage (a prefix pattern is B-tree friendly; a contains pattern
// generally needs a trigram index). It is observational only — the compiler
// always emits ILIKE regardless.
type WildcardPattern int

const (
	PatternExact WildcardPattern = iota
	PatternPrefix
	PatternContains
)

// WildcardResult is the outcome of translating a user search term.
type WildcardResult struct {
	Pattern     string          // SQL LIKE pattern (literal % and _ already escaped)
	PatternType WildcardPattern // classification for index-usage hints / metrics
}

// TranslateWildcard converts a user term's * and ? to SQL LIKE % and _, escaping
// literal %, _ and \ first so they stay literals (default LIKE escape char '\').
// A term with no wildcards is returned as an exact pattern.
func TranslateWildcard(term string) WildcardResult {
	if !containsWildcard(term) {
		return WildcardResult{Pattern: escapeLikeLiterals(term), PatternType: PatternExact}
	}
	p := escapeLikeLiterals(term)
	p = strings.ReplaceAll(p, "*", "%")
	p = strings.ReplaceAll(p, "?", "_")
	return WildcardResult{Pattern: p, PatternType: classifyPattern(p)}
}

// wildcardToLike returns just the translated LIKE pattern (the common case used
// by free-text search compilation).
func wildcardToLike(term string) string { return TranslateWildcard(term).Pattern }

// escapeLikeLiterals escapes the SQL LIKE metacharacters so the user's literal
// %, _ and \ are matched literally before * / ? translation.
func escapeLikeLiterals(s string) string {
	return strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(s)
}

// classifyPattern reports whether a translated pattern is a pure prefix match
// ("abc%") versus a contains/infix match. Escaped metacharacters (\% and \_)
// are literals, not wildcards, so they are skipped — e.g. "100\%%" (from the
// user term "100%*") is still a pure prefix.
func classifyPattern(pattern string) WildcardPattern {
	var pct, under int
	pctAtEnd := false
	rs := []rune(pattern)
	for i := 0; i < len(rs); i++ {
		if rs[i] == '\\' { // escape: the next rune is a literal, skip it
			i++
			continue
		}
		switch rs[i] {
		case '%':
			pct++
			pctAtEnd = i == len(rs)-1
		case '_':
			under++
		}
	}
	if pct == 1 && under == 0 && pctAtEnd {
		return PatternPrefix
	}
	return PatternContains
}

func containsWildcard(term string) bool {
	return strings.ContainsAny(term, "*?")
}

// IsAllWildcard reports whether a term is empty or consists solely of wildcard
// characters (* / ?). Such terms match everything and are skipped in search.
func IsAllWildcard(term string) bool {
	if term == "" {
		return true
	}
	for _, c := range term {
		if c != '*' && c != '?' {
			return false
		}
	}
	return true
}

package versioning

import "strings"

// splitPath splits a URL path into non-empty segments.
// e.g., "/domains/test.net" → ["domains", "test.net"]
func splitPath(path string) []string {
	var segments []string
	for _, s := range strings.Split(path, "/") {
		if s != "" {
			segments = append(segments, s)
		}
	}
	return segments
}

// matchPattern checks if a concrete URL path matches a Gin route pattern.
// Pattern segments starting with ":" match any single path segment.
// Pattern segments starting with "*" match one or more remaining segments.
//
// Examples:
//
//	matchPattern("/domains/test.net", "/domains/:id_or_name") → true
//	matchPattern("/domains/test.net/transfer/approve", "/domains/:name/transfer/:action") → true
//	matchPattern("/domains", "/domains/:id_or_name") → false (segment count differs)
//	matchPattern("/domains/search", "/domains/search") → true (exact match)
func matchPattern(urlPath, pattern string) bool {
	urlParts := splitPath(urlPath)
	patParts := splitPath(pattern)

	for i, pat := range patParts {
		if strings.HasPrefix(pat, "*") {
			return len(urlParts) >= i+1
		}

		if i >= len(urlParts) {
			return false
		}

		if strings.HasPrefix(pat, ":") {
			continue
		}

		if pat != urlParts[i] {
			return false
		}
	}

	return len(urlParts) == len(patParts)
}

// extractBasePath strips the "/api" prefix from a request URL path.
// e.g., "/api/domains/test.net" → "/domains/test.net"
// e.g., "/api/admin/domains" → "/admin/domains"
func extractBasePath(urlPath string) string {
	const prefix = "/api"
	if strings.HasPrefix(urlPath, prefix) {
		result := urlPath[len(prefix):]
		if result == "" {
			return "/"
		}
		return result
	}
	return urlPath
}

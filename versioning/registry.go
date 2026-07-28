package versioning

import (
	"sort"
	"strings"
	"sync"
)

// RouteKey uniquely identifies an endpoint independent of version.
type RouteKey struct {
	Method  string // "GET", "POST", etc.
	Pattern string // unversioned relative pattern, e.g., "/domains/:id_or_name"
}

// RouteVersionRegistry tracks which API versions are registered for each endpoint.
// It is populated at route registration time via VersionedGroup and consulted
// by the middleware to determine per-endpoint version support.
type RouteVersionRegistry struct {
	mu     sync.RWMutex
	routes map[RouteKey]map[string]bool
}

// NewRouteVersionRegistry creates a new empty registry.
func NewRouteVersionRegistry() *RouteVersionRegistry {
	return &RouteVersionRegistry{
		routes: make(map[RouteKey]map[string]bool),
	}
}

// Register records that the given method+pattern combination has a handler for the given version.
func (r *RouteVersionRegistry) Register(method, pattern, version string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := RouteKey{Method: strings.ToUpper(method), Pattern: pattern}
	if r.routes[key] == nil {
		r.routes[key] = make(map[string]bool)
	}
	r.routes[key][version] = true
}

// Lookup checks whether a concrete URL path has a registered handler for the given version.
// It matches the urlPath against all registered patterns for the given method.
// Returns endpointExists=true if any version is registered for a matching pattern,
// and versionSupported=true if the specific version is registered.
func (r *RouteVersionRegistry) Lookup(method, urlPath, version string) (endpointExists bool, versionSupported bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	method = strings.ToUpper(method)

	var matchedKey *RouteKey
	for key := range r.routes {
		if key.Method != method {
			continue
		}
		if matchPattern(urlPath, key.Pattern) {
			k := key
			if matchedKey == nil {
				matchedKey = &k
			} else if isMoreSpecific(key.Pattern, matchedKey.Pattern) {
				matchedKey = &k
			}
		}
	}

	if matchedKey == nil {
		return false, false
	}
	return true, r.routes[*matchedKey][version]
}

// SupportedVersions returns the sorted list of versions registered for a matching pattern.
// When multiple patterns match, the most specific one is used (consistent with Lookup).
func (r *RouteVersionRegistry) SupportedVersions(method, urlPath string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	method = strings.ToUpper(method)

	var matchedKey *RouteKey
	for key := range r.routes {
		if key.Method != method {
			continue
		}
		if matchPattern(urlPath, key.Pattern) {
			k := key
			if matchedKey == nil {
				matchedKey = &k
			} else if isMoreSpecific(key.Pattern, matchedKey.Pattern) {
				matchedKey = &k
			}
		}
	}

	if matchedKey == nil {
		return nil
	}

	var versions []string
	for v := range r.routes[*matchedKey] {
		versions = append(versions, v)
	}
	sort.Strings(versions)
	return versions
}

// isMoreSpecific returns true if pattern a has more literal (non-param) segments than b.
func isMoreSpecific(a, b string) bool {
	return countLiteralSegments(a) > countLiteralSegments(b)
}

func countLiteralSegments(pattern string) int {
	count := 0
	for _, seg := range splitPath(pattern) {
		if !strings.HasPrefix(seg, ":") && !strings.HasPrefix(seg, "*") {
			count++
		}
	}
	return count
}

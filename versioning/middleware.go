package versioning

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

// Middleware reads the API version from the request (using the configured
// VersionReadingStrategy), validates it, checks per-endpoint support via the
// RouteVersionRegistry, and re-writes the request path to include the version.
//
// When registry is nil, the middleware skips per-endpoint version checking
// (backward-compatible with services that haven't migrated to VersionedGroup yet).
//
// When no config is provided, DefaultConfig() is used (header-based, x-version,
// default v1, require header — preserving current behavior).
func Middleware(engine *gin.Engine, registry *RouteVersionRegistry, configs ...Config) gin.HandlerFunc {
	cfg := DefaultConfig()
	if len(configs) > 0 {
		cfg = configs[0]
	}

	// Default Reader if not set to prevent nil panic at request time.
	if cfg.Reader == nil {
		cfg.Reader = NewHeaderVersionStrategy(DefaultVersionHeaderName)
	}

	versionRegex := regexp.MustCompile(cfg.VersionFormat)

	return func(c *gin.Context) {
		if !shouldVersionRoute(c) {
			c.Next()
			return
		}

		// Step 1: Read version using the configured strategy
		version, found := cfg.Reader.ReadVersion(c)
		if !found {
			if cfg.AssumeDefaultVersionWhenUnspecified {
				version = cfg.DefaultVersion
			} else {
				writeProblem(c, "Missing API version")
				return
			}
		}

		if version == "" {
			version = cfg.DefaultVersion
		}

		c.Header(DefaultVersionHeaderName, version)

		// Step 2: Validate version format
		if !versionRegex.MatchString(version) {
			writeProblem(c, "Invalid API version format")
			return
		}

		// Step 3: Per-endpoint version check via registry
		if registry != nil {
			basePath := extractBasePathForLookup(c.Request.URL.Path)
			endpointExists, versionSupported := registry.Lookup(c.Request.Method, basePath, version)

			if endpointExists && !versionSupported {
				writeProblem(c, "Unsupported API version")
				return
			}

			if cfg.ReportApiVersions && endpointExists {
				supported := registry.SupportedVersions(c.Request.Method, basePath)
				c.Header("api-supported-versions", strings.Join(supported, ", "))
			}
		}

		// Step 4: Rewrite URL if version not already in path, then re-dispatch
		if !hasVersionPrefix(c, version) {
			uriSegments := strings.SplitAfter(c.Request.URL.Path, "/api")
			segments := uriSegments[1:]
			c.Request.URL.Path = fmt.Sprintf("/api/%s%s", version, strings.Join(segments, ""))
			engine.HandleContext(c)
			c.Abort()
		}

		c.Next()
	}
}

// shouldVersionRoute returns false for routes that should skip versioning.
// Only routes under /api/ are versioned.
func shouldVersionRoute(c *gin.Context) bool {
	path := c.Request.URL.Path

	if path == "/" ||
		path == "/health" ||
		strings.HasPrefix(path, "/test") ||
		strings.HasPrefix(path, "/swagger") ||
		c.Request.Method == "OPTIONS" {
		return false
	}

	// Only version routes under /api/
	if !strings.HasPrefix(path, "/api") {
		return false
	}

	return true
}

// hasVersionPrefix returns true if the URL path already contains a version segment.
func hasVersionPrefix(c *gin.Context, version string) bool {
	segments := strings.FieldsFunc(c.Request.URL.Path, func(r rune) bool {
		return r == '/'
	})
	for index, segment := range segments {
		if segment == version && index == 1 {
			return true
		}
	}
	return false
}

// extractBasePathForLookup strips the "/api" prefix and any version segment
// from a request URL path, returning the unversioned resource path for registry lookups.
// e.g., "/api/domains/test.net" → "/domains/test.net"
// e.g., "/api/v2/domains/test.net" → "/domains/test.net"
func extractBasePathForLookup(urlPath string) string {
	base := extractBasePath(urlPath) // strips "/api" → "/v2/domains/test.net" or "/domains/test.net"

	// If the base starts with a version segment (e.g., "/v2/..."), strip it.
	if len(base) > 1 && base[0] == '/' {
		rest := base[1:]
		if slashIdx := strings.IndexByte(rest, '/'); slashIdx >= 0 {
			candidate := rest[:slashIdx]
			if strings.HasPrefix(candidate, "v") && len(candidate) > 1 {
				return rest[slashIdx:]
			}
		}
	}
	return base
}

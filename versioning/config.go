// Package versioning provides a configurable API versioning middleware for Gin.
//
// It supports per-endpoint version tracking via a RouteVersionRegistry,
// pluggable version reading strategies (header, query string, URL segment),
// and RFC 9457 Problem Details error responses.
package versioning

const (
	// DefaultVersionHeaderName is the default header name for API versioning.
	DefaultVersionHeaderName = "x-version"

	// DefaultVersionValue is the default API version when none is specified.
	DefaultVersionValue = "v1"

	// DefaultVersionFormat is the default regex pattern for validating version strings.
	DefaultVersionFormat = `^v\d+(b\d+)?$`
)

// Config configures the versioning middleware behavior.
// Configured once at service startup and applies to all endpoints in the service.
type Config struct {
	// DefaultVersion is the version assumed when no version is specified.
	DefaultVersion string

	// AssumeDefaultVersionWhenUnspecified controls whether requests without
	// a version indicator are allowed (using DefaultVersion) or rejected with 400.
	AssumeDefaultVersionWhenUnspecified bool

	// ReportApiVersions controls whether the response includes an
	// "api-supported-versions" header listing all versions for the matched endpoint.
	ReportApiVersions bool

	// Reader is the strategy used to extract the version from requests.
	// Use NewHeaderVersionStrategy, NewCompositeVersionStrategy, etc.
	Reader VersionReadingStrategy

	// VersionFormat is a regex pattern that validates the version string format.
	VersionFormat string
}

// DefaultConfig returns a configuration that preserves common Tucows API behavior:
// header-based versioning via x-version, default v1, require header, no version reporting.
func DefaultConfig() Config {
	return Config{
		DefaultVersion:                     DefaultVersionValue,
		AssumeDefaultVersionWhenUnspecified: false,
		ReportApiVersions:                  false,
		Reader:                             NewHeaderVersionStrategy(DefaultVersionHeaderName),
		VersionFormat:                      DefaultVersionFormat,
	}
}

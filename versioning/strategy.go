package versioning

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// VersionReadingStrategy is the Strategy interface for extracting
// the API version from an incoming request.
type VersionReadingStrategy interface {
	// ReadVersion extracts the version from the request.
	// Returns the version string and true if found, or "" and false if not present.
	ReadVersion(c *gin.Context) (version string, found bool)
}

// HeaderVersionStrategy reads the version from a request header.
type HeaderVersionStrategy struct {
	HeaderName string
}

// NewHeaderVersionStrategy creates a strategy that reads the version from the given header.
func NewHeaderVersionStrategy(headerName string) *HeaderVersionStrategy {
	return &HeaderVersionStrategy{HeaderName: headerName}
}

func (s *HeaderVersionStrategy) ReadVersion(c *gin.Context) (string, bool) {
	v := c.GetHeader(s.HeaderName)
	if v != "" {
		return v, true
	}
	// Header present but empty — return found=true so the middleware
	// can apply the default version (preserves original behavior where
	// sending an empty x-version header defaults to v1).
	if _, exists := c.Request.Header[http.CanonicalHeaderKey(s.HeaderName)]; exists {
		return "", true
	}
	return "", false
}

// QueryStringVersionStrategy reads the version from a query parameter.
type QueryStringVersionStrategy struct {
	ParamName string
}

// NewQueryStringVersionStrategy creates a strategy that reads the version from the given query parameter.
func NewQueryStringVersionStrategy(paramName string) *QueryStringVersionStrategy {
	return &QueryStringVersionStrategy{ParamName: paramName}
}

func (s *QueryStringVersionStrategy) ReadVersion(c *gin.Context) (string, bool) {
	v := c.Query(s.ParamName)
	if v == "" {
		return "", false
	}
	return v, true
}

// URLSegmentVersionStrategy reads the version from the URL path segment.
// It detects paths like /api/v1/... or /api/v2/... and extracts the version.
type URLSegmentVersionStrategy struct{}

func (s URLSegmentVersionStrategy) ReadVersion(c *gin.Context) (string, bool) {
	path := c.Request.URL.Path
	if !strings.HasPrefix(path, "/api/") {
		return "", false
	}
	remainder := strings.TrimPrefix(path, "/api/")
	parts := strings.SplitN(remainder, "/", 2)
	if len(parts) == 0 {
		return "", false
	}
	candidate := parts[0]
	if strings.HasPrefix(candidate, "v") && len(candidate) > 1 {
		return candidate, true
	}
	return "", false
}

// CompositeVersionStrategy tries multiple strategies in order.
// The first strategy that returns a version wins.
type CompositeVersionStrategy struct {
	strategies []VersionReadingStrategy
}

// NewCompositeVersionStrategy creates a strategy that tries each provided strategy in order.
func NewCompositeVersionStrategy(strategies ...VersionReadingStrategy) *CompositeVersionStrategy {
	return &CompositeVersionStrategy{strategies: strategies}
}

func (s *CompositeVersionStrategy) ReadVersion(c *gin.Context) (string, bool) {
	for _, strategy := range s.strategies {
		if version, found := strategy.ReadVersion(c); found {
			return version, true
		}
	}
	return "", false
}

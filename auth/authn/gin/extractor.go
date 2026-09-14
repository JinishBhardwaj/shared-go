package gin

import (
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
)

var (
	ErrNoCredentialsFound = errors.New("authn: no credentials found in request")
	ErrMultipleCredTypes  = errors.New("authn: multiple conflicting credential types provided")
	ErrInvalidHeader      = errors.New("authn: malformed authorization header")
)

// ExtractedCredential represents the type and raw payload of credentials extracted from an HTTP request.
type CredentialType string

const (
	CredentialTypeBearer CredentialType = "bearer"
	CredentialTypeAPIKey CredentialType = "api_key"
)

type ExtractedCredential struct {
	Type  CredentialType
	Token string
}

// ExtractorConfig configures header names and options for credential extraction.
type ExtractorConfig struct {
	// APIKeyHeader is the HTTP header to check for API keys. Defaults to "X-API-Key".
	APIKeyHeader string

	// AllowQueryAPIKey allows extracting the API key from a query parameter named "api_key".
	// Default is false for security (query parameters can leak in logs/referrers).
	AllowQueryAPIKey bool

	// APIKeyQueryParam specifies the query param name when AllowQueryAPIKey is true. Defaults to "api_key".
	APIKeyQueryParam string
}

// DefaultExtractorConfig provides standard settings.
func DefaultExtractorConfig() ExtractorConfig {
	return ExtractorConfig{
		APIKeyHeader:     "X-API-Key",
		AllowQueryAPIKey: false,
		APIKeyQueryParam: "api_key",
	}
}

// CredentialExtractor extracts credentials (Bearer tokens or API Keys) from Gin requests.
type CredentialExtractor struct {
	config ExtractorConfig
}

// NewCredentialExtractor returns a new CredentialExtractor with given options.
func NewCredentialExtractor(cfg ExtractorConfig) *CredentialExtractor {
	if cfg.APIKeyHeader == "" {
		cfg.APIKeyHeader = "X-API-Key"
	}
	if cfg.APIKeyQueryParam == "" {
		cfg.APIKeyQueryParam = "api_key"
	}
	return &CredentialExtractor{config: cfg}
}

// Extract parses the Gin context and returns the extracted credential or an
// error.
//
// Structured as a Chain of Responsibility over three named, independently
// testable sources, tried in precedence order (gap-analysis-final.md Tier 4
// line 130: "CredentialExtractor.Extract is a monolithic if-chain" -- "the
// actual CoR gap"): the Authorization header, the dedicated API-key header,
// then (lowest precedence, opt-in only) a query parameter.
//
// Deliberately NOT a generic uniform-merge chain (e.g. a `[]Source` slice
// merged by one identical rule): the three sources do not merge
// symmetrically today, and a fully generic redesign would either silently
// drop or silently add a conflict check that isn't there. Confirmed by
// reading the pre-refactor implementation before touching it: the
// Authorization-header-derived api key and the dedicated-header-derived
// api key ARE conflict-checked against each other (differing values ->
// ErrMultipleCredTypes); the query-param fallback is NOT conflict-checked
// against either header source -- it is consulted only when no header
// source already produced an api key, and never raises a conflict even if
// it disagrees with one. This method's orchestration preserves that
// asymmetry exactly; see extractor_test.go's
// "query param enabled but a header api key already won" case, which pins
// it directly and would fail under a naive uniform-merge redesign.
func (e *CredentialExtractor) Extract(c *gin.Context) (*ExtractedCredential, error) {
	bearerToken, apiKey, err := e.extractFromAuthorizationHeader(c)
	if err != nil {
		return nil, err
	}

	if headerAPIKey := e.extractFromAPIKeyHeader(c); headerAPIKey != "" {
		if apiKey != "" && apiKey != headerAPIKey {
			return nil, ErrMultipleCredTypes
		}
		apiKey = headerAPIKey
	}

	if apiKey == "" {
		if queryAPIKey := e.extractFromQueryParam(c); queryAPIKey != "" {
			apiKey = queryAPIKey
		}
	}

	// Disallow sending both a Bearer token and an API key simultaneously.
	if bearerToken != "" && apiKey != "" {
		return nil, ErrMultipleCredTypes
	}

	if bearerToken != "" {
		return &ExtractedCredential{
			Type:  CredentialTypeBearer,
			Token: bearerToken,
		}, nil
	}

	if apiKey != "" {
		return &ExtractedCredential{
			Type:  CredentialTypeAPIKey,
			Token: apiKey,
		}, nil
	}

	return nil, ErrNoCredentialsFound
}

// extractFromAuthorizationHeader is the highest-precedence source: it
// parses the standard Authorization header, if present, into a candidate
// bearer token OR api key (scheme "apikey"/"key"). A present-but-malformed
// header (no scheme/value separated by a space, or an unrecognized scheme)
// is a hard parse error (ErrInvalidHeader), not a "nothing found here, try
// the next source" outcome -- unchanged from the pre-refactor behavior,
// where a malformed Authorization header short-circuited Extract entirely
// without ever consulting the other two sources.
func (e *CredentialExtractor) extractFromAuthorizationHeader(c *gin.Context) (bearerToken, apiKey string, err error) {
	authHeader := strings.TrimSpace(c.GetHeader("Authorization"))
	if authHeader == "" {
		return "", "", nil
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		return "", "", ErrInvalidHeader
	}

	scheme := strings.ToLower(parts[0])
	token := strings.TrimSpace(parts[1])

	switch scheme {
	case "bearer":
		return token, "", nil
	case "apikey", "key":
		return "", token, nil
	default:
		return "", "", ErrInvalidHeader
	}
}

// extractFromAPIKeyHeader reads the configured dedicated API-key header
// (e.g. "X-API-Key"). It only ever reports what it found here; the
// conflict check against extractFromAuthorizationHeader's own api-key
// candidate is Extract's responsibility, not this method's -- unchanged
// from the pre-refactor behavior.
func (e *CredentialExtractor) extractFromAPIKeyHeader(c *gin.Context) string {
	return strings.TrimSpace(c.GetHeader(e.config.APIKeyHeader))
}

// extractFromQueryParam reads the optional API-key query parameter, only
// when AllowQueryAPIKey is enabled. This is the LOWEST-precedence source
// and, unlike the two header sources above, is never conflict-checked
// against an already-found header value by Extract -- it is purely a
// fallback, consulted only when nothing else has already supplied an api
// key. This asymmetry is deliberate and preserved unchanged from the
// pre-refactor behavior (see Extract's own doc comment).
func (e *CredentialExtractor) extractFromQueryParam(c *gin.Context) string {
	if !e.config.AllowQueryAPIKey {
		return ""
	}
	return strings.TrimSpace(c.Query(e.config.APIKeyQueryParam))
}

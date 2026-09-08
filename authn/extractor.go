package authn

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

// Extract parses the Gin context and returns the extracted credential or an error.
func (e *CredentialExtractor) Extract(c *gin.Context) (*ExtractedCredential, error) {
	authHeader := strings.TrimSpace(c.GetHeader("Authorization"))
	apiKeyHeader := strings.TrimSpace(c.GetHeader(e.config.APIKeyHeader))

	var bearerToken string
	var apiKey string

	// 1. Check Authorization header
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 {
			scheme := strings.ToLower(parts[0])
			token := strings.TrimSpace(parts[1])

			switch scheme {
			case "bearer":
				bearerToken = token
			case "apikey", "key":
				apiKey = token
			default:
				return nil, ErrInvalidHeader
			}
		} else {
			return nil, ErrInvalidHeader
		}
	}

	// 2. Check X-API-Key header
	if apiKeyHeader != "" {
		if apiKey != "" && apiKey != apiKeyHeader {
			return nil, ErrMultipleCredTypes
		}
		apiKey = apiKeyHeader
	}

	// 3. Optional query parameter for API Key
	if apiKey == "" && e.config.AllowQueryAPIKey {
		qKey := strings.TrimSpace(c.Query(e.config.APIKeyQueryParam))
		if qKey != "" {
			apiKey = qKey
		}
	}

	// Disallow sending both a Bearer token and an API key simultaneously
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

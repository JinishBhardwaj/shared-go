package gin

import (
	"context"
	"errors"
	"fmt"

	"github.com/JinishBhardwaj/shared-go/auth/authn"
	"github.com/JinishBhardwaj/shared-go/auth/principal"
	"github.com/gin-gonic/gin"
)

var (
	ErrAuthenticatorNotConfigured = errors.New("authn: no validator configured for credential type")
)

// Authenticator handles extraction and validation of authentication credentials from a Gin request.
type Authenticator interface {
	Authenticate(c *gin.Context) (*principal.Principal, error)
}

// AuthenticationHandler is an ASP.NET Core naming alias for Authenticator (IAuthenticationHandler).
type AuthenticationHandler = Authenticator

// BearerTokenValidator defines the contract for validating Bearer tokens.
// Satisfied by both JWTValidator and OIDCValidator (coreos/go-oidc/v3).
type BearerTokenValidator interface {
	ValidateToken(ctx context.Context, tokenStr string) (*principal.Principal, error)
}

// KeyValidator defines the contract for validating API keys.
// Satisfied by APIKeyValidator.
type KeyValidator interface {
	ValidateKey(ctx context.Context, rawKey string) (*principal.Principal, error)
}

// CompositeAuthenticator combines Bearer JWT and API Key validation.
type CompositeAuthenticator struct {
	extractor       *CredentialExtractor
	bearerValidator BearerTokenValidator
	apiKeyValidator KeyValidator
}

// SchemeHandler is an ASP.NET Core naming alias for CompositeAuthenticator.
type SchemeHandler = CompositeAuthenticator

// SchemeHandlerConfig is an ASP.NET Core naming alias for CompositeAuthenticatorConfig.
type SchemeHandlerConfig = CompositeAuthenticatorConfig

// NewSchemeHandler is an ASP.NET Core naming alias for NewCompositeAuthenticator.
var NewSchemeHandler = NewCompositeAuthenticator

// CompositeAuthenticatorConfig configures the CompositeAuthenticator.
type CompositeAuthenticatorConfig struct {
	ExtractorConfig ExtractorConfig

	// BearerValidator validates incoming Bearer JWTs (e.g. JWTValidator or OIDCValidator).
	BearerValidator BearerTokenValidator

	// JWTValidator is a convenience alias for BearerValidator.
	JWTValidator *authn.JWTValidator

	// APIKeyValidator validates incoming API keys.
	APIKeyValidator KeyValidator
}

// NewCompositeAuthenticator creates an Authenticator supporting both JWTs/OIDC and API keys.
func NewCompositeAuthenticator(cfg CompositeAuthenticatorConfig) *CompositeAuthenticator {
	bearerVal := cfg.BearerValidator
	if bearerVal == nil && cfg.JWTValidator != nil {
		bearerVal = cfg.JWTValidator
	}

	return &CompositeAuthenticator{
		extractor:       NewCredentialExtractor(cfg.ExtractorConfig),
		bearerValidator: bearerVal,
		apiKeyValidator: cfg.APIKeyValidator,
	}
}

// Authenticate extracts the incoming credential and dispatches to the corresponding validator.
func (a *CompositeAuthenticator) Authenticate(c *gin.Context) (*principal.Principal, error) {
	cred, err := a.extractor.Extract(c)
	if err != nil {
		return nil, err
	}

	switch cred.Type {
	case CredentialTypeBearer:
		if a.bearerValidator == nil {
			return nil, fmt.Errorf("%w: bearer token validator not provided", ErrAuthenticatorNotConfigured)
		}
		return a.bearerValidator.ValidateToken(c.Request.Context(), cred.Token)

	case CredentialTypeAPIKey:
		if a.apiKeyValidator == nil {
			return nil, fmt.Errorf("%w: api key validator not provided", ErrAuthenticatorNotConfigured)
		}
		return a.apiKeyValidator.ValidateKey(c.Request.Context(), cred.Token)

	default:
		return nil, ErrNoCredentialsFound
	}
}

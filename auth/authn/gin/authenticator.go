package gin

import (
	"context"
	"errors"
	"fmt"
	"time"

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

// AuthEvent describes the outcome of one CompositeAuthenticator.Authenticate
// call, reported to the optional OnAuthenticate hook
// (CompositeAuthenticatorConfig.OnAuthenticate). Tier 4 audit-hook /
// metrics-decorator support: built from an already-fully-computed
// result -- see Authenticate's doc comment for why this cannot suppress or
// change the returned Principal/error.
type AuthEvent struct {
	// CredentialType is "bearer", "apikey", or "" if no credential could be
	// extracted at all.
	CredentialType string
	Success        bool
	Duration       time.Duration
}

// CompositeAuthenticator combines Bearer JWT and API Key validation.
type CompositeAuthenticator struct {
	extractor       *CredentialExtractor
	bearerValidator BearerTokenValidator
	apiKeyValidator KeyValidator
	onAuthenticate  func(context.Context, AuthEvent)
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

	// OnAuthenticate, if set, is called once per Authenticate call with the
	// already-fully-computed outcome (Tier 4 audit-hook / metrics-decorator
	// support). Same no-suppression, no-recover contract as
	// authz.PolicyEngine.SetOnDecision: fn receives a value describing a
	// result that has already been returned to the caller, so it cannot
	// change or suppress that result; fn must not block or panic.
	OnAuthenticate func(context.Context, AuthEvent)
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
		onAuthenticate:  cfg.OnAuthenticate,
	}
}

// Authenticate extracts the incoming credential and dispatches to the corresponding validator.
func (a *CompositeAuthenticator) Authenticate(c *gin.Context) (*principal.Principal, error) {
	start := time.Now()
	p, credType, err := a.authenticate(c)
	if a.onAuthenticate != nil {
		a.onAuthenticate(c.Request.Context(), AuthEvent{
			CredentialType: credType,
			Success:        err == nil,
			Duration:       time.Since(start),
		})
	}
	return p, err
}

// authenticate does the actual extraction/dispatch; Authenticate wraps it to
// time the call and report an AuthEvent without changing what it returns.
func (a *CompositeAuthenticator) authenticate(c *gin.Context) (*principal.Principal, string, error) {
	cred, err := a.extractor.Extract(c)
	if err != nil {
		return nil, "", err
	}

	switch cred.Type {
	case CredentialTypeBearer:
		if a.bearerValidator == nil {
			return nil, "bearer", fmt.Errorf("%w: bearer token validator not provided", ErrAuthenticatorNotConfigured)
		}
		p, err := a.bearerValidator.ValidateToken(c.Request.Context(), cred.Token)
		return p, "bearer", err

	case CredentialTypeAPIKey:
		if a.apiKeyValidator == nil {
			return nil, "apikey", fmt.Errorf("%w: api key validator not provided", ErrAuthenticatorNotConfigured)
		}
		p, err := a.apiKeyValidator.ValidateKey(c.Request.Context(), cred.Token)
		return p, "apikey", err

	default:
		return nil, "", ErrNoCredentialsFound
	}
}

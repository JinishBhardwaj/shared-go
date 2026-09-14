package gin

import (
	"context"
	"fmt"

	"github.com/JinishBhardwaj/shared-go/auth/authn"
	"github.com/JinishBhardwaj/shared-go/auth/principal"
	"github.com/gin-gonic/gin"
)

// CognitoOptions configures AWS Cognito authentication for the builder.
type CognitoOptions struct {
	Region          string
	UserPoolID      string
	IssuerURL       string
	CustomKeySetURL string
	ClientID        string
}

// AuthenticationBuilder provides a fluent builder for authn configuration,
// mirroring ASP.NET Core's builder.Services.AddAuthentication().
type AuthenticationBuilder struct {
	extractorConfig   *ExtractorConfig
	bearerValidator   BearerTokenValidator
	apiKeyValidator   KeyValidator
	claimsTransformer principal.ClaimsTransformer
	middlewareOptions []Option
	err               error
}

// NewBuilder creates a new AuthenticationBuilder.
func NewBuilder() *AuthenticationBuilder {
	return &AuthenticationBuilder{}
}

// WithCognito configures AWS Cognito OIDC token validation.
func (b *AuthenticationBuilder) WithCognito(ctx context.Context, opts CognitoOptions) *AuthenticationBuilder {
	if b.err != nil {
		return b
	}

	issuerURL := opts.IssuerURL
	if issuerURL == "" && opts.Region != "" && opts.UserPoolID != "" {
		issuerURL = fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", opts.Region, opts.UserPoolID)
	}

	validator, err := authn.NewOIDCValidator(ctx, authn.OIDCValidatorConfig{
		IssuerURL:            issuerURL,
		ExpectedClientID:     opts.ClientID,
		SkipClientIDCheck:    true, // Dynamic multi-client validation
		SupportedSigningAlgs: []string{"RS256"},
		Normalizer:           authn.NewCognitoClaimsNormalizer(),
		CustomKeySetURL:      opts.CustomKeySetURL,
	})
	if err != nil {
		b.err = fmt.Errorf("authn: failed configuring Cognito validator: %w", err)
		return b
	}

	b.bearerValidator = validator
	return b
}

// AddCognito is an alias for WithCognito matching ASP.NET Core AddCognito() semantics.
func (b *AuthenticationBuilder) AddCognito(ctx context.Context, opts CognitoOptions) *AuthenticationBuilder {
	return b.WithCognito(ctx, opts)
}

// WithBearerValidator sets an explicit BearerTokenValidator (e.g. mock validator or custom JWT validator).
func (b *AuthenticationBuilder) WithBearerValidator(validator BearerTokenValidator) *AuthenticationBuilder {
	b.bearerValidator = validator
	return b
}

// AddBearerValidator is an alias for WithBearerValidator.
func (b *AuthenticationBuilder) AddBearerValidator(validator BearerTokenValidator) *AuthenticationBuilder {
	return b.WithBearerValidator(validator)
}

// WithApiKeyValidator sets an API key validator.
func (b *AuthenticationBuilder) WithApiKeyValidator(validator KeyValidator) *AuthenticationBuilder {
	b.apiKeyValidator = validator
	return b
}

// AddApiKeyValidator is an alias for WithApiKeyValidator.
func (b *AuthenticationBuilder) AddApiKeyValidator(validator KeyValidator) *AuthenticationBuilder {
	return b.WithApiKeyValidator(validator)
}

// WithExtractorConfig sets custom extraction options.
func (b *AuthenticationBuilder) WithExtractorConfig(cfg ExtractorConfig) *AuthenticationBuilder {
	b.extractorConfig = &cfg
	return b
}

// WithClaimsTransformation registers a ClaimsTransformer (ASP.NET Core IClaimsTransformation).
func (b *AuthenticationBuilder) WithClaimsTransformation(transformer principal.ClaimsTransformer) *AuthenticationBuilder {
	b.claimsTransformer = transformer
	return b
}

// AddClaimsTransformation is an alias for WithClaimsTransformation.
func (b *AuthenticationBuilder) AddClaimsTransformation(transformer principal.ClaimsTransformer) *AuthenticationBuilder {
	return b.WithClaimsTransformation(transformer)
}

// WithOption appends middleware configuration options (e.g. WithContextKey, WithRealm).
func (b *AuthenticationBuilder) WithOption(opts ...Option) *AuthenticationBuilder {
	b.middlewareOptions = append(b.middlewareOptions, opts...)
	return b
}

// Build creates the Authenticator (CompositeAuthenticator).
func (b *AuthenticationBuilder) Build() (Authenticator, error) {
	if b.err != nil {
		return nil, b.err
	}

	extCfg := DefaultExtractorConfig()
	if b.extractorConfig != nil {
		extCfg = *b.extractorConfig
	}

	compositeAuth := NewCompositeAuthenticator(CompositeAuthenticatorConfig{
		ExtractorConfig: extCfg,
		BearerValidator: b.bearerValidator,
		APIKeyValidator: b.apiKeyValidator,
	})

	return compositeAuth, nil
}

// BuildMiddleware constructs the Gin authentication middleware (app.UseAuthentication).
func (b *AuthenticationBuilder) BuildMiddleware() (gin.HandlerFunc, error) {
	auth, err := b.Build()
	if err != nil {
		return nil, err
	}

	opts := b.middlewareOptions
	if b.claimsTransformer != nil {
		opts = append(opts, WithClaimsTransformation(b.claimsTransformer))
	}

	return UseAuthentication(auth, opts...), nil
}

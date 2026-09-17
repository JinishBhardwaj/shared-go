package gin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/JinishBhardwaj/shared-go/auth/authn"
	"github.com/JinishBhardwaj/shared-go/auth/authn/mapping"
	"github.com/JinishBhardwaj/shared-go/auth/authn/oidc"
	"github.com/JinishBhardwaj/shared-go/auth/principal"
	"github.com/gin-gonic/gin"
)

// ErrNoValidatorConfigured is returned by Build() when neither a bearer
// token validator nor an API key validator has been configured. Tier 1:
// "fail at wire time, not request time" -- without this check, Build()
// would succeed with an authenticator that can never validate any
// credential, and the misconfiguration would only surface per-request as
// ErrAuthenticatorNotConfigured.
var ErrNoValidatorConfigured = errors.New("authn: no bearer or API key validator configured -- call WithCognito/WithBearerValidator/WithApiKeyValidator before Build()")

// CognitoOptions configures AWS Cognito authentication for the builder.
type CognitoOptions struct {
	Region          string
	UserPoolID      string
	IssuerURL       string
	CustomKeySetURL string

	// ClientID is the single expected app-client audience. Set this when
	// the API is consumed by exactly one Cognito app client.
	ClientID string

	// AllowedAudiences lists acceptable app-client audiences when more
	// than one Cognito app client must be accepted. Ignored if ClientID
	// is set.
	//
	// Tier 0 #4: WithCognito used to hardcode SkipClientIDCheck: true
	// unconditionally, disabling audience/client-ID validation for every
	// Cognito consumer regardless of configuration (RFC 9068 §4 / RFC 7519
	// §4.1.3 confused-deputy exposure). Set ClientID or AllowedAudiences to
	// get real enforcement.
	AllowedAudiences []string

	// AudienceValidator, if set, is consulted as an additional, independent
	// acceptance path alongside ClientID/AllowedAudiences -- e.g. a
	// runtime-onboarded M2M client list stored in a database, which can't be
	// known as a static ID/list at builder-construction time. See
	// authn.AudienceValidator's own doc comment for its full contract
	// (bounded, breaker-guarded, fail-closed; a 401, never a 403).
	AudienceValidator authn.AudienceValidator

	// AudienceValidatorTimeout bounds each AudienceValidator call. Defaults
	// to 50ms. Ignored if AudienceValidator is nil.
	AudienceValidatorTimeout time.Duration

	// SkipClientIDCheck explicitly disables audience/client-ID enforcement.
	// This must be set true on purpose -- it is never silently implied by
	// leaving ClientID and AllowedAudiences empty (that path still works,
	// per the underlying OIDC validator's requirements, but logs a loud
	// server-side warning instead of skipping silently).
	SkipClientIDCheck bool

	// TypEnforcement controls RFC 9068 "typ: at+jwt" header enforcement.
	// Defaults to authn.TypEnforcementOff (the zero value) -- AWS Cognito
	// access tokens do not set a typ header by default, so enabling
	// authn.TypEnforcementStrict here without confirming your own user
	// pool's token shape will reject every token. See
	// authn.TypEnforcementMode's doc comment.
	TypEnforcement authn.TypEnforcementMode
}

// AuthenticationBuilder provides a fluent builder for authn configuration,
// mirroring ASP.NET Core's builder.Services.AddAuthentication().
type AuthenticationBuilder struct {
	extractorConfig   *ExtractorConfig
	bearerValidator   BearerTokenValidator
	issuerRegistry    *authn.IssuerRegistry
	apiKeyValidator   KeyValidator
	authenticator     Authenticator
	claimsTransformer principal.ClaimsTransformer
	middlewareOptions []Option
	onAuthenticate    func(context.Context, AuthEvent)
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

	validator, err := oidc.NewOIDCValidator(ctx, oidc.OIDCValidatorConfig{
		IssuerURL:                issuerURL,
		ExpectedClientID:         opts.ClientID,
		AllowedAudiences:         opts.AllowedAudiences,
		AudienceValidator:        opts.AudienceValidator,
		AudienceValidatorTimeout: opts.AudienceValidatorTimeout,
		SkipClientIDCheck:        opts.SkipClientIDCheck,
		SupportedSigningAlgs:     []string{"RS256"},
		Normalizer:               mapping.NewCognitoClaimsNormalizer(),
		CustomKeySetURL:          opts.CustomKeySetURL,
		TypEnforcement:           opts.TypEnforcement,
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

// WithIssuerValidator registers validator to handle Bearer tokens whose
// (unverified, selection-only -- see authn.IssuerRegistry's doc comment)
// "iss" claim equals issuer, enabling multi-IdP/multi-tenant authentication
// from a single AuthenticationBuilder (gap-analysis-final.md Tier 4 line
// 130: "Registry keyed by iss for multi-IdP/multi-tenant"). May be called
// more than once, once per issuer; each call registers one more issuer
// without discarding the others. The underlying authn.IssuerRegistry is
// created lazily on first use and, once created, is what b.bearerValidator
// is set to -- so a WithIssuerValidator call after WithCognito/
// WithBearerValidator replaces the single validator those set with the
// registry (the previously-set single validator is not automatically
// migrated into the registry; register it explicitly under its own issuer
// if it must also participate). A token whose "iss" does not match any
// issuer registered here is rejected (authn.ErrUnknownIssuer) -- there is no
// default/fallback validator.
func (b *AuthenticationBuilder) WithIssuerValidator(issuer string, validator BearerTokenValidator) *AuthenticationBuilder {
	if b.err != nil {
		return b
	}
	if b.issuerRegistry == nil {
		b.issuerRegistry = authn.NewIssuerRegistry()
	}
	b.issuerRegistry.Register(issuer, validator)
	b.bearerValidator = b.issuerRegistry
	return b
}

// AddIssuerValidator is an alias for WithIssuerValidator.
func (b *AuthenticationBuilder) AddIssuerValidator(issuer string, validator BearerTokenValidator) *AuthenticationBuilder {
	return b.WithIssuerValidator(issuer, validator)
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

// WithAuthenticator sets an explicit Authenticator, bypassing credential
// extraction and WithBearerValidator/WithCognito/WithApiKeyValidator
// entirely -- Build()/BuildMiddleware() return it directly (still
// decorated with WithOnAuthenticate's hook and WithClaimsTransformation, if
// either is set, exactly as the composite path is). For an Authenticator
// that doesn't fit the bearer/API-key credential model at all -- e.g.
// authtest.NoopAuthenticator for a dev-mode bypass, which needs to run
// through the same pipeline.Setup path production wiring does, not a
// hand-rolled router.Use call. Most callers should use
// WithBearerValidator/WithCognito/WithApiKeyValidator instead; this is the
// escape hatch for when none of those apply. Takes precedence over any
// bearer/API-key validator also configured on this builder.
func (b *AuthenticationBuilder) WithAuthenticator(a Authenticator) *AuthenticationBuilder {
	b.authenticator = a
	return b
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

// WithOnAuthenticate registers fn to be called once per Authenticate call on
// the built Authenticator, with the already-fully-computed outcome (Tier 4
// audit-hook / metrics-decorator support -- see AuthEvent and
// CompositeAuthenticatorConfig.OnAuthenticate).
func (b *AuthenticationBuilder) WithOnAuthenticate(fn func(context.Context, AuthEvent)) *AuthenticationBuilder {
	if b.err != nil {
		return b
	}
	b.onAuthenticate = fn
	return b
}

// WithOption appends middleware configuration options (e.g. WithContextKey, WithRealm).
func (b *AuthenticationBuilder) WithOption(opts ...Option) *AuthenticationBuilder {
	b.middlewareOptions = append(b.middlewareOptions, opts...)
	return b
}

// Build creates the Authenticator (CompositeAuthenticator, or whatever
// WithAuthenticator supplied).
func (b *AuthenticationBuilder) Build() (Authenticator, error) {
	if b.err != nil {
		return nil, b.err
	}

	if b.authenticator != nil {
		if b.onAuthenticate == nil {
			return b.authenticator, nil
		}
		return &hookedAuthenticator{inner: b.authenticator, onAuthenticate: b.onAuthenticate}, nil
	}

	if b.bearerValidator == nil && b.apiKeyValidator == nil {
		return nil, ErrNoValidatorConfigured
	}

	extCfg := DefaultExtractorConfig()
	if b.extractorConfig != nil {
		extCfg = *b.extractorConfig
	}

	compositeAuth := NewCompositeAuthenticator(CompositeAuthenticatorConfig{
		ExtractorConfig: extCfg,
		BearerValidator: b.bearerValidator,
		APIKeyValidator: b.apiKeyValidator,
		OnAuthenticate:  b.onAuthenticate,
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

// hookedAuthenticator decorates an Authenticator supplied via
// AuthenticationBuilder.WithAuthenticator so WithOnAuthenticate's metrics
// hook still fires uniformly -- matching CompositeAuthenticator.Authenticate's
// own reporting. CredentialType is always empty here: a
// WithAuthenticator-supplied Authenticator does its own thing entirely, with
// no CredentialExtractor-recognized bearer/apikey distinction to report.
type hookedAuthenticator struct {
	inner          Authenticator
	onAuthenticate func(context.Context, AuthEvent)
}

func (h *hookedAuthenticator) Authenticate(c *gin.Context) (*principal.Principal, error) {
	start := time.Now()
	p, err := h.inner.Authenticate(c)
	h.onAuthenticate(c.Request.Context(), AuthEvent{Success: err == nil, Duration: time.Since(start)})
	return p, err
}

package gin

import (
	"context"
	"fmt"
	"time"

	"github.com/JinishBhardwaj/shared-go/auth/authz"
	"github.com/JinishBhardwaj/shared-go/cache"
	"github.com/gin-gonic/gin"
)

// AuthorizationBuilder provides fluent chained configuration for authorization,
// mirroring ASP.NET Core's builder.Services.AddAuthorization().
type AuthorizationBuilder struct {
	options           *authz.AuthorizationOptions
	handlers          []authz.RequirementHandler
	middlewareOptions []MiddlewareOption
	onDecision        func(context.Context, authz.DecisionEvent)
	err               error
}

// NewBuilder creates a new AuthorizationBuilder.
func NewBuilder() *AuthorizationBuilder {
	return &AuthorizationBuilder{
		options: authz.NewOptions(),
	}
}

// WithOptions sets the pre-configured AuthorizationOptions.
func (b *AuthorizationBuilder) WithOptions(opts *authz.AuthorizationOptions) *AuthorizationBuilder {
	if opts != nil {
		b.options = opts
	}
	return b
}

// AddPolicy registers a policy by name and policy definition.
func (b *AuthorizationBuilder) AddPolicy(name string, policy authz.Policy) *AuthorizationBuilder {
	b.options.AddPolicy(name, policy)
	return b
}

// WithDefaultPolicy sets the default policy.
func (b *AuthorizationBuilder) WithDefaultPolicy(policy *authz.Policy) *AuthorizationBuilder {
	b.options.DefaultPolicy = policy
	return b
}

// WithFallbackPolicy sets the fallback policy.
func (b *AuthorizationBuilder) WithFallbackPolicy(policy *authz.Policy) *AuthorizationBuilder {
	b.options.FallbackPolicy = policy
	return b
}

// WithOnDecision registers fn to be called once per Evaluate/EvaluatePolicy
// call on the built AuthorizationService, after the Decision has already
// been fully computed (Tier 4 audit-hook / metrics-decorator support -- see
// authz.DecisionEvent and authz.PolicyEngine.SetOnDecision). Passing nil is
// a safe no-op/disable, per SetOnDecision's own doc comment.
func (b *AuthorizationBuilder) WithOnDecision(fn func(context.Context, authz.DecisionEvent)) *AuthorizationBuilder {
	b.onDecision = fn
	return b
}

// WithHandler registers a custom requirement handler.
func (b *AuthorizationBuilder) WithHandler(handler authz.RequirementHandler) *AuthorizationBuilder {
	if handler != nil {
		b.handlers = append(b.handlers, handler)
	}
	return b
}

// AddHandler is an alias for WithHandler.
func (b *AuthorizationBuilder) AddHandler(handler authz.RequirementHandler) *AuthorizationBuilder {
	return b.WithHandler(handler)
}

// PARCOption configures a authz.PARCHandlerConfig before it is passed to
// authz.NewPARCHandler, for options that WithPARC/WithMemoryPARC's own fixed
// parameter list doesn't cover (e.g. WithCacheOutcomeHook).
type PARCOption func(*authz.PARCHandlerConfig)

// WithCacheOutcomeHook returns a PARCOption that wires fn as the resulting
// PARCHandler's OnCacheOutcome hook (Tier 4 audit-hook / metrics-decorator
// support -- see authz.CacheOutcome).
func WithCacheOutcomeHook(fn func(authz.CacheOutcome)) PARCOption {
	return func(cfg *authz.PARCHandlerConfig) { cfg.OnCacheOutcome = fn }
}

// WithPARC configures fine-grained PARC evaluation using the specified repository, cache, and grant TTL.
func (b *AuthorizationBuilder) WithPARC(repo authz.PermissionRepository, c cache.Cache[*authz.PrincipalPermissions], grantTTL time.Duration, opts ...PARCOption) *AuthorizationBuilder {
	if b.err != nil {
		return b
	}

	cfg := authz.PARCHandlerConfig{
		Repository: repo,
		Cache:      c,
		GrantTTL:   grantTTL,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	parcHandler, err := authz.NewPARCHandler(cfg)
	if err != nil {
		b.err = fmt.Errorf("authz: failed initializing PARC handler: %w", err)
		return b
	}

	b.handlers = append(b.handlers, parcHandler)
	return b
}

// AddPARC is an alias for WithPARC.
func (b *AuthorizationBuilder) AddPARC(repo authz.PermissionRepository, c cache.Cache[*authz.PrincipalPermissions], grantTTL time.Duration, opts ...PARCOption) *AuthorizationBuilder {
	return b.WithPARC(repo, c, grantTTL, opts...)
}

// WithMemoryPARC provides an in-memory PARC evaluator with default L1 cache
// and the specified grant TTL. repo may be nil, in which case a default
// authz.NewMemoryPermissionRepository() is used.
func (b *AuthorizationBuilder) WithMemoryPARC(grantTTL time.Duration, repo authz.PermissionRepository, opts ...PARCOption) *AuthorizationBuilder {
	if b.err != nil {
		return b
	}

	r := repo
	if r == nil {
		r = authz.NewMemoryPermissionRepository()
	}

	return b.WithPARC(r, nil, grantTTL, opts...)
}

// AddMemoryPARC is an alias for WithMemoryPARC.
func (b *AuthorizationBuilder) AddMemoryPARC(grantTTL time.Duration, repo authz.PermissionRepository, opts ...PARCOption) *AuthorizationBuilder {
	return b.WithMemoryPARC(grantTTL, repo, opts...)
}

// WithMiddlewareOption adds options for the Gin authorization middleware (e.g. WithResultHandler, WithFallbackPolicy).
func (b *AuthorizationBuilder) WithMiddlewareOption(opts ...MiddlewareOption) *AuthorizationBuilder {
	b.middlewareOptions = append(b.middlewareOptions, opts...)
	return b
}

// Build creates the AuthorizationService (PolicyEngine).
func (b *AuthorizationBuilder) Build() (*authz.AuthorizationService, error) {
	if b.err != nil {
		return nil, b.err
	}
	service := authz.NewAuthorizationService(b.options, b.handlers...)
	service.SetOnDecision(b.onDecision)
	return service, nil
}

// BuildMiddleware creates the Gin authorization middleware (app.UseAuthorization).
func (b *AuthorizationBuilder) BuildMiddleware() (gin.HandlerFunc, error) {
	service, err := b.Build()
	if err != nil {
		return nil, err
	}
	return UseAuthorization(service, b.middlewareOptions...), nil
}

// BuildEngineAndMiddleware builds the AuthorizationService exactly once and
// returns both it and its configured Gin middleware, so a caller that needs
// the engine instance for Require(WithEngine(engine), ...) elsewhere gets
// the SAME instance that is wired into the returned middleware -- calling
// Build() and BuildMiddleware() separately would construct two independent
// engines (NewAuthorizationService allocates a new *authz.PolicyEngine on
// every call), silently wiring a different engine into the router than the
// one the caller holds a reference to.
func (b *AuthorizationBuilder) BuildEngineAndMiddleware() (*authz.AuthorizationService, gin.HandlerFunc, error) {
	service, err := b.Build()
	if err != nil {
		return nil, nil, err
	}
	return service, UseAuthorization(service, b.middlewareOptions...), nil
}

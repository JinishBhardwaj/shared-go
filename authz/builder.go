package authz

import (
	"fmt"
	"time"

	"github.com/JinishBhardwaj/shared-go/authz/cache"
	"github.com/gin-gonic/gin"
)

// AuthorizationBuilder provides fluent chained configuration for authorization,
// mirroring ASP.NET Core's builder.Services.AddAuthorization().
type AuthorizationBuilder struct {
	options           *AuthorizationOptions
	handlers          []RequirementHandler
	middlewareOptions []MiddlewareOption
	err               error
}

// NewBuilder creates a new AuthorizationBuilder.
func NewBuilder() *AuthorizationBuilder {
	return &AuthorizationBuilder{
		options: NewOptions(),
	}
}

// WithOptions sets the pre-configured AuthorizationOptions.
func (b *AuthorizationBuilder) WithOptions(opts *AuthorizationOptions) *AuthorizationBuilder {
	if opts != nil {
		b.options = opts
	}
	return b
}

// AddPolicy registers a policy by name and policy definition.
func (b *AuthorizationBuilder) AddPolicy(name string, policy Policy) *AuthorizationBuilder {
	b.options.AddPolicy(name, policy)
	return b
}

// WithDefaultPolicy sets the default policy.
func (b *AuthorizationBuilder) WithDefaultPolicy(policy *Policy) *AuthorizationBuilder {
	b.options.DefaultPolicy = policy
	return b
}

// WithFallbackPolicy sets the fallback policy.
func (b *AuthorizationBuilder) WithFallbackPolicy(policy *Policy) *AuthorizationBuilder {
	b.options.FallbackPolicy = policy
	return b
}

// WithHandler registers a custom requirement handler.
func (b *AuthorizationBuilder) WithHandler(handler RequirementHandler) *AuthorizationBuilder {
	if handler != nil {
		b.handlers = append(b.handlers, handler)
	}
	return b
}

// AddHandler is an alias for WithHandler.
func (b *AuthorizationBuilder) AddHandler(handler RequirementHandler) *AuthorizationBuilder {
	return b.WithHandler(handler)
}

// WithPARC configures fine-grained PARC evaluation using the specified repository, cache provider, and grant TTL.
func (b *AuthorizationBuilder) WithPARC(repo PermissionRepository, cacheProvider cache.CacheProvider, grantTTL time.Duration) *AuthorizationBuilder {
	if b.err != nil {
		return b
	}

	parcHandler, err := NewPARCHandler(PARCHandlerConfig{
		Repository: repo,
		Cache:      cacheProvider,
		GrantTTL:   grantTTL,
	})
	if err != nil {
		b.err = fmt.Errorf("authz: failed initializing PARC handler: %w", err)
		return b
	}

	b.handlers = append(b.handlers, parcHandler)
	return b
}

// AddPARC is an alias for WithPARC.
func (b *AuthorizationBuilder) AddPARC(repo PermissionRepository, cacheProvider cache.CacheProvider, grantTTL time.Duration) *AuthorizationBuilder {
	return b.WithPARC(repo, cacheProvider, grantTTL)
}

// WithMemoryPARC provides an in-memory PARC evaluator with default L1 cache and the specified grant TTL.
func (b *AuthorizationBuilder) WithMemoryPARC(grantTTL time.Duration, repo ...PermissionRepository) *AuthorizationBuilder {
	if b.err != nil {
		return b
	}

	var r PermissionRepository
	if len(repo) > 0 && repo[0] != nil {
		r = repo[0]
	} else {
		r = NewMemoryPermissionRepository()
	}

	return b.WithPARC(r, nil, grantTTL)
}

// AddMemoryPARC is an alias for WithMemoryPARC.
func (b *AuthorizationBuilder) AddMemoryPARC(grantTTL time.Duration, repo ...PermissionRepository) *AuthorizationBuilder {
	return b.WithMemoryPARC(grantTTL, repo...)
}

// WithMiddlewareOption adds options for the Gin authorization middleware (e.g. WithResultHandler, WithFallbackPolicy).
func (b *AuthorizationBuilder) WithMiddlewareOption(opts ...MiddlewareOption) *AuthorizationBuilder {
	b.middlewareOptions = append(b.middlewareOptions, opts...)
	return b
}

// Build creates the AuthorizationService (PolicyEngine).
func (b *AuthorizationBuilder) Build() (*AuthorizationService, error) {
	if b.err != nil {
		return nil, b.err
	}
	return NewAuthorizationService(b.options, b.handlers...), nil
}

// BuildMiddleware creates the Gin authorization middleware (app.UseAuthorization).
func (b *AuthorizationBuilder) BuildMiddleware() (gin.HandlerFunc, error) {
	service, err := b.Build()
	if err != nil {
		return nil, err
	}
	return UseAuthorization(service, b.middlewareOptions...), nil
}

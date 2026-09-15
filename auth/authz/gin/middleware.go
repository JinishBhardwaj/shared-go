package gin

import (
	"fmt"
	"net/http"
	"time"

	"github.com/JinishBhardwaj/shared-go/auth/authz"
	ginprincipal "github.com/JinishBhardwaj/shared-go/auth/principal/gin"
	"github.com/gin-gonic/gin"
	"github.com/tucowsinc/tdp-shared-go/problem"
)

const (
	ContextKeyAllowAnonymous       = "authz.allow_anonymous"
	ContextKeyEndpointPolicy       = "authz.endpoint_policy"
	ContextKeyEndpointResource     = "authz.endpoint_resource"
	ContextKeyAuthorizationService = "authz.service"
)

// ResultHandler is a pluggable function to customize challenge (401) or forbidden (403) responses
// (mirrors ASP.NET Core IAuthorizationMiddlewareResultHandler).
type ResultHandler func(c *gin.Context, result authz.AuthorizationResult, policyName string)

// MiddlewareConfig configures the authorization middleware.
type MiddlewareConfig struct {
	resultHandler  ResultHandler
	fallbackPolicy *authz.Policy
	defaultPolicy  *authz.Policy
	actionResolver ActionResolver
}

// MiddlewareOption configures the authorization middleware.
type MiddlewareOption func(*MiddlewareConfig)

// WithResultHandler configures a custom result handler (mirrors IAuthorizationMiddlewareResultHandler).
func WithResultHandler(handler ResultHandler) MiddlewareOption {
	return func(cfg *MiddlewareConfig) {
		cfg.resultHandler = handler
	}
}

// WithFallbackPolicy sets the policy evaluated when an endpoint specifies no explicit policy
// (enforces Zero-Trust across all routes by default).
func WithFallbackPolicy(policy authz.Policy) MiddlewareOption {
	return func(cfg *MiddlewareConfig) {
		cfg.fallbackPolicy = &policy
	}
}

// WithDefaultPolicy sets the policy evaluated when an endpoint specifies Authorize() without a policy name.
func WithDefaultPolicy(policy authz.Policy) MiddlewareOption {
	return func(cfg *MiddlewareConfig) {
		cfg.defaultPolicy = &policy
	}
}

// WithFallbackActionResolver overrides how the FallbackPolicy check derives a
// logical Action.Name from the incoming request's HTTP verb (Tier 1 line 98,
// "Unify action semantics"). Defaults to DefaultActionResolver. (Named
// distinctly from Require's own WithActionResolver, which configures a single
// route guard rather than this middleware-wide default.)
func WithFallbackActionResolver(resolver ActionResolver) MiddlewareOption {
	return func(cfg *MiddlewareConfig) {
		cfg.actionResolver = resolver
	}
}

// UseAuthorization creates a pipeline authorization middleware (mirrors ASP.NET Core app.UseAuthorization()).
func UseAuthorization(service *authz.PolicyEngine, opts ...MiddlewareOption) gin.HandlerFunc {
	return New(service, opts...)
}

// New creates an authorization middleware.
func New(service *authz.PolicyEngine, opts ...MiddlewareOption) gin.HandlerFunc {
	if service == nil {
		panic("authz: PolicyEngine cannot be nil")
	}

	cfg := MiddlewareConfig{
		fallbackPolicy: service.FallbackPolicy(),
		defaultPolicy:  service.DefaultPolicy(),
		actionResolver: defaultActionResolver,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return func(c *gin.Context) {
		// 1. Store the authorization service in context for all downstream Authorize / AuthorizeResource calls
		c.Set(ContextKeyAuthorizationService, service)

		// 2. FallbackPolicy enforcement (Zero-Trust)
		// If a FallbackPolicy is configured, check if this route was
		// registered through Group/ProtectGroup (routes.go) -- explicit,
		// registration-time route metadata that replaces the former
		// HandlerNames() substring scan (gap-analysis-final.md Tier 1
		// line 97).
		if cfg.fallbackPolicy != nil {
			// If the route has NO explicit authorization annotation, evaluate FallbackPolicy BEFORE executing handler
			if !hasExplicitAuthAnnotation(c) {
				user := ginprincipal.User(c)
				if user == nil {
					handleResult(c, authz.FailedResult("Authentication required"), cfg.fallbackPolicy.Name, cfg.resultHandler)
					c.Abort()
					return
				}

				evalCtx := &authz.EvaluationContext{
					Action: authz.Action{
						Name:       cfg.actionResolver(c.Request.Method),
						HTTPMethod: c.Request.Method,
					},
					Context: authz.Context{
						ClientIP:  c.ClientIP(),
						Timestamp: time.Now().UTC(),
					},
				}

				decision, err := service.Evaluate(c.Request.Context(), *cfg.fallbackPolicy, user, evalCtx)
				result := decision.ToResult()
				if err != nil || !result.Succeeded {
					// The full, unsanitized result (whose FailureReason may
					// carry a wrapped internal error -- see httpsec.go) is
					// still passed through to a caller-supplied
					// cfg.resultHandler, exactly as before; only the
					// built-in default writer inside handleResult stops
					// echoing it (Tier 0 #7).
					handleResult(c, result, cfg.fallbackPolicy.Name, cfg.resultHandler)
					c.Abort()
					return
				}
			}
		}

		c.Next()
	}
}

// AllowAnonymous marks an endpoint as exempt from all authorization checks
// (mirrors ASP.NET Core [AllowAnonymous]). New()'s FallbackPolicy
// enforcement recognizes a route as exempt only when it was registered
// through Group/ProtectGroup (routes.go) -- attaching AllowAnonymous()
// directly to a route on the raw router still marks that request (via
// ContextKeyAllowAnonymous, below) but does NOT by itself skip
// FallbackPolicy; use Group(rg) to register genuinely anonymous routes so
// FallbackPolicy recognizes them. AllowAnonymous() also sets
// ContextKeyAllowAnonymous on the gin context, which AuthorizeResource below
// genuinely reads back (G6: "make AllowAnonymous real" --
// gap-analysis-final.md Tier 1 line 96) -- see .claude/authfix/state.md's
// G6 note for the fail-open analysis of this context-key read.
func AllowAnonymous() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(ContextKeyAllowAnonymous, true)
		c.Next()
	}
}

// AuthorizeResource provides imperative authorization inside request handlers (mirrors _authService.AuthorizeAsync).
// If the route was marked AllowAnonymous() earlier in this same request's
// handler chain, this short-circuits to a successful result -- the only
// place in this package where ContextKeyAllowAnonymous is genuinely
// consulted (G6, Tier 1 line 96).
func AuthorizeResource(c *gin.Context, resource authz.Resource, policyName string) authz.AuthorizationResult {
	if anon, exists := c.Get(ContextKeyAllowAnonymous); exists && anon == true {
		return authz.SuccessResult()
	}

	serviceVal, exists := c.Get(ContextKeyAuthorizationService)
	if !exists {
		return authz.FailedResult("authz: authorization service not found in context")
	}
	service, ok := serviceVal.(*authz.PolicyEngine)
	if !ok {
		return authz.FailedResult("authz: invalid authorization service in context")
	}

	user := ginprincipal.User(c)
	if user == nil {
		return authz.FailedResult("Authentication required")
	}

	evalCtx := &authz.EvaluationContext{
		Action: authz.Action{
			Name:       defaultActionResolver(c.Request.Method),
			HTTPMethod: c.Request.Method,
		},
		Resource: resource,
		Context: authz.Context{
			ClientIP:  c.ClientIP(),
			Timestamp: time.Now().UTC(),
		},
	}

	result, err := service.Authorize(c.Request.Context(), user, policyName, evalCtx)
	if err != nil {
		return authz.FailedResult(err.Error())
	}
	return result
}

// handleResult writes the HTTP response for a failed authorization result.
// authz never emits 401 -- that is authn's job (gap-analysis-final.md Tier 2
// line 107, G8-5): a FailedResult carrying descAuthenticationRequired here
// means New()'s FallbackPolicy check found no principal in context, a
// misconfiguration/missing-authn condition, not a credential challenge, so
// it is answered exactly like any other authorization failure -- 403, no
// WWW-Authenticate (that header exists to accompany a 401 challenge, which
// this package no longer issues). Tier 0 #7: result.FailureReason is
// deliberately NOT echoed here -- see httpsec.go. The real reason is logged
// server-side only.
func handleResult(c *gin.Context, result authz.AuthorizationResult, policyName string, customHandler ResultHandler) {
	if customHandler != nil {
		customHandler(c, result, policyName)
		return
	}

	if !result.Succeeded && result.FailureReason == descAuthenticationRequired {
		logAuthzDenial("request", result.FailureReason)
		writeForbiddenProblem(c, "forbidden", descAuthenticationRequired, nil)
		return
	}

	// No WWW-Authenticate here: rfc6750InsufficientScope is an RFC 6750
	// OAuth *scope* error code, and this is a generic policy denial, not a
	// scope shortfall -- see requireScopeGuard for the one path that
	// legitimately uses it.
	logAuthzDenial(fmt.Sprintf("policy %q", policyName), result.FailureReason)
	writeForbiddenProblem(c, "forbidden", descAccessDeniedByPolicy, map[string]any{"policy": policyName})
}

// writeForbiddenProblem writes an RFC 9457 Problem Details 403 response.
// The legacy "error"/"error_description" OAuth-style fields (and any
// mode-specific fields in extra, e.g. "policy"/"missing_scopes") are carried
// as RFC 9457 section 3.2 extension members so existing clients parsing
// those keys keep working, while the response now also carries the
// registered type/title/status/instance members and the
// application/problem+json media type (WriteTo). Tier 0 #7: errCode/desc
// passed in here are always fixed literals or route-wiring constants, never
// raw error text -- callers are responsible for that, same as before.
func writeForbiddenProblem(c *gin.Context, errCode, desc string, extra map[string]any) {
	ext := map[string]any{"error": errCode, "error_description": desc}
	for k, v := range extra {
		ext[k] = v
	}
	problem.Details{
		Status:     http.StatusForbidden,
		Title:      http.StatusText(http.StatusForbidden),
		Detail:     desc,
		Instance:   c.Request.URL.Path,
		Extensions: ext,
	}.WriteTo(c.Writer)
}

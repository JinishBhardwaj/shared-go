package gin

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/JinishBhardwaj/shared-go/auth/authz"
	ginprincipal "github.com/JinishBhardwaj/shared-go/auth/principal/gin"
	"github.com/gin-gonic/gin"
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
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return func(c *gin.Context) {
		// 1. Store the authorization service in context for all downstream Authorize / AuthorizeResource calls
		c.Set(ContextKeyAuthorizationService, service)

		// 2. FallbackPolicy enforcement (Zero-Trust)
		// If a FallbackPolicy is configured, check if this route has an explicit Authorize or AllowAnonymous handler
		if cfg.fallbackPolicy != nil {
			hasExplicitAuth := false
			for _, name := range c.HandlerNames() {
				if strings.Contains(name, "AllowAnonymous") ||
					strings.Contains(name, "Authorize") ||
					strings.Contains(name, "WithPolicy") ||
					strings.Contains(name, "RequirePolicy") ||
					strings.Contains(name, "RequirePARC") {
					hasExplicitAuth = true
					break
				}
			}

			// If the route has NO explicit authorization annotation, evaluate FallbackPolicy BEFORE executing handler
			if !hasExplicitAuth {
				user := ginprincipal.User(c)
				if user == nil {
					handleResult(c, authz.FailedResult("Authentication required"), cfg.fallbackPolicy.Name, cfg.resultHandler)
					c.Abort()
					return
				}

				evalCtx := &authz.EvaluationContext{
					Action: authz.Action{
						Name:       c.Request.Method,
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

// AllowAnonymous marks an endpoint as exempt from all authorization checks (mirrors ASP.NET Core [AllowAnonymous]).
func AllowAnonymous() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(ContextKeyAllowAnonymous, true)
		c.Next()
	}
}

// Authorize enforces a named authorization policy on an endpoint (mirrors ASP.NET Core [Authorize(Policy = "...")]).
// Can be used either:
// 1. In a pipeline configured with UseAuthorization: Authorize("AdminPolicy")
// 2. Standalone with direct engine: Authorize("AdminPolicy", engine)
func Authorize(policyName string, args ...any) gin.HandlerFunc {
	var engine *authz.PolicyEngine
	var extractor ResourceExtractorFunc

	for _, arg := range args {
		switch v := arg.(type) {
		case *authz.PolicyEngine:
			engine = v
		case ResourceExtractorFunc:
			extractor = v
		}
	}

	return func(c *gin.Context) {
		srv := engine
		if srv == nil {
			if sVal, exists := c.Get(ContextKeyAuthorizationService); exists {
				if s, ok := sVal.(*authz.PolicyEngine); ok {
					srv = s
				}
			}
		}
		if srv == nil {
			panic("authz: no PolicyEngine provided to Authorize or found in context via UseAuthorization")
		}

		user := ginprincipal.User(c)
		if user == nil {
			handleResult(c, authz.FailedResult("Authentication required"), policyName, nil)
			c.Abort()
			return
		}

		var res authz.Resource
		if extractor != nil {
			res = extractor(c)
		}

		evalCtx := &authz.EvaluationContext{
			Action: authz.Action{
				Name:       c.Request.Method,
				HTTPMethod: c.Request.Method,
			},
			Resource: res,
			Context: authz.Context{
				ClientIP:  c.ClientIP(),
				Timestamp: time.Now().UTC(),
			},
		}

		result, err := srv.Authorize(c.Request.Context(), user, policyName, evalCtx)
		if err != nil || !result.Succeeded {
			handleResult(c, result, policyName, nil)
			c.Abort()
			return
		}

		c.Next()
	}
}

// WithPolicy is a declarative alias for Authorize(policyName, ...).
func WithPolicy(policyName string, args ...any) gin.HandlerFunc {
	return Authorize(policyName, args...)
}

// AuthorizeResource provides imperative authorization inside request handlers (mirrors _authService.AuthorizeAsync).
func AuthorizeResource(c *gin.Context, resource authz.Resource, policyName string) authz.AuthorizationResult {
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
			Name:       c.Request.Method,
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

// handleResult writes the appropriate 401 or 403 HTTP response. Tier 0 #7:
// result.FailureReason is deliberately NOT echoed here -- see httpsec.go.
// The real reason is logged server-side only.
func handleResult(c *gin.Context, result authz.AuthorizationResult, policyName string, customHandler ResultHandler) {
	if customHandler != nil {
		customHandler(c, result, policyName)
		return
	}

	status := http.StatusForbidden
	if !result.Succeeded && result.FailureReason == descAuthenticationRequired {
		logAuthzDenial("request", result.FailureReason)
		status = http.StatusUnauthorized
		c.Header("WWW-Authenticate", fmt.Sprintf("Bearer error=%s, error_description=%s",
			quoteRFC7235(rfc6750Unauthorized), quoteRFC7235(descAuthenticationRequired)))
		c.JSON(status, gin.H{
			"error":             rfc6750Unauthorized,
			"error_description": descAuthenticationRequired,
		})
		return
	}

	logAuthzDenial(fmt.Sprintf("policy %q", policyName), result.FailureReason)
	c.Header("WWW-Authenticate", fmt.Sprintf("Bearer error=%s, error_description=%s",
		quoteRFC7235(rfc6750InsufficientScope), quoteRFC7235(descAccessDeniedByPolicy)))
	c.JSON(status, gin.H{
		"error":             "forbidden",
		"error_description": descAccessDeniedByPolicy,
		"policy":            policyName,
	})
}

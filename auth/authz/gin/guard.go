package gin

import (
	"fmt"
	"net/http"
	"time"

	"github.com/JinishBhardwaj/shared-go/auth/authz"
	ginprincipal "github.com/JinishBhardwaj/shared-go/auth/principal/gin"
	"github.com/gin-gonic/gin"
)

// ResourceExtractorFunc extracts the target domain Resource from the incoming Gin context.
type ResourceExtractorFunc func(c *gin.Context) authz.Resource

// ExtractResourceFromParam returns a ResourceExtractorFunc that populates Resource.ID from a URL route param.
func ExtractResourceFromParam(paramName, resourceType string) ResourceExtractorFunc {
	return func(c *gin.Context) authz.Resource {
		return authz.Resource{
			Type: resourceType,
			ID:   c.Param(paramName),
		}
	}
}

// RequirePolicy enforces an ASP.NET Core-style authorization policy on a Gin route.
func RequirePolicy(engine *authz.PolicyEngine, policyName string, getResource ...ResourceExtractorFunc) gin.HandlerFunc {
	if engine == nil {
		panic("authz: PolicyEngine cannot be nil")
	}

	return func(c *gin.Context) {
		user := ginprincipal.User(c) // Mirrors HttpContext.User
		if user == nil {
			c.Header("WWW-Authenticate", fmt.Sprintf("Bearer error=%s, error_description=%s",
				quoteRFC7235(rfc6750Unauthorized), quoteRFC7235(descAuthenticationRequired)))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             rfc6750Unauthorized,
				"error_description": descAuthenticationRequired,
			})
			return
		}

		var res authz.Resource
		if len(getResource) > 0 && getResource[0] != nil {
			res = getResource[0](c)
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

		// Tier 0 #7: decision.Reason is deliberately NOT echoed to the
		// caller -- it can be built from an arbitrary wrapped internal
		// error (see httpsec.go / authz/engine.go's Evaluate). Log it
		// server-side and answer with a fixed, generic description.
		decision, err := engine.EvaluatePolicy(c.Request.Context(), policyName, user, evalCtx)
		if err != nil || !decision.Allowed {
			logAuthzDenial(fmt.Sprintf("policy %q", policyName), decision.Reason)

			c.Header("WWW-Authenticate", fmt.Sprintf("Bearer error=%s, error_description=%s",
				quoteRFC7235(rfc6750InsufficientScope), quoteRFC7235(descAccessDeniedByPolicy)))
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":             "forbidden",
				"error_description": descAccessDeniedByPolicy,
				"policy":            policyName,
			})
			return
		}

		c.Next()
	}
}

// RequirePARC enforces an inline PARC requirement (action and resource type) on a Gin route.
func RequirePARC(engine *authz.PolicyEngine, action, resourceType string, getResource ...ResourceExtractorFunc) gin.HandlerFunc {
	if engine == nil {
		panic("authz: PolicyEngine cannot be nil")
	}

	inlinePolicy := authz.NewPolicy(fmt.Sprintf("inline:parc:%s:%s", action, resourceType)).
		RequirePARC(action, resourceType).
		Build()

	return func(c *gin.Context) {
		user := ginprincipal.User(c) // Mirrors HttpContext.User
		if user == nil {
			c.Header("WWW-Authenticate", fmt.Sprintf("Bearer error=%s, error_description=%s",
				quoteRFC7235(rfc6750Unauthorized), quoteRFC7235(descAuthenticationRequired)))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             rfc6750Unauthorized,
				"error_description": descAuthenticationRequired,
			})
			return
		}

		var res authz.Resource
		if len(getResource) > 0 && getResource[0] != nil {
			res = getResource[0](c)
		} else {
			res = authz.Resource{Type: resourceType, ID: "*"}
		}

		evalCtx := &authz.EvaluationContext{
			Action: authz.Action{
				Name:       action,
				HTTPMethod: c.Request.Method,
			},
			Resource: res,
			Context: authz.Context{
				ClientIP:  c.ClientIP(),
				Timestamp: time.Now().UTC(),
			},
		}

		// Tier 0 #7: decision.Reason is deliberately NOT echoed to the
		// caller (same reasoning as RequirePolicy above). The
		// action/resourceType-based description below is always safe --
		// both are route-wiring constants, never derived from an error.
		decision, err := engine.Evaluate(c.Request.Context(), inlinePolicy, user, evalCtx)
		if err != nil || !decision.Allowed {
			logAuthzDenial(fmt.Sprintf("PARC action=%q resource_type=%q", action, resourceType), decision.Reason)

			safeDesc := fmt.Sprintf("Missing permission for action '%s' on resource '%s'", action, resourceType)
			c.Header("WWW-Authenticate", fmt.Sprintf("Bearer error=%s, error_description=%s",
				quoteRFC7235(rfc6750InsufficientScope), quoteRFC7235(safeDesc)))
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":             "insufficient_permissions",
				"error_description": safeDesc,
				"action":            action,
				"resource_type":     resourceType,
			})
			return
		}

		c.Next()
	}
}

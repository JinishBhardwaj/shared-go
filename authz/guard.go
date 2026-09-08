package authz

import (
	"fmt"
	"net/http"
	"time"

	"github.com/JinishBhardwaj/shared-go/authn"
	"github.com/gin-gonic/gin"
)

// ResourceExtractorFunc extracts the target domain Resource from the incoming Gin context.
type ResourceExtractorFunc func(c *gin.Context) Resource

// ExtractResourceFromParam returns a ResourceExtractorFunc that populates Resource.ID from a URL route param.
func ExtractResourceFromParam(paramName, resourceType string) ResourceExtractorFunc {
	return func(c *gin.Context) Resource {
		return Resource{
			Type: resourceType,
			ID:   c.Param(paramName),
		}
	}
}

// RequirePolicy enforces an ASP.NET Core-style authorization policy on a Gin route.
func RequirePolicy(engine *PolicyEngine, policyName string, getResource ...ResourceExtractorFunc) gin.HandlerFunc {
	if engine == nil {
		panic("authz: PolicyEngine cannot be nil")
	}

	return func(c *gin.Context) {
		user := authn.User(c) // Mirrors HttpContext.User
		if user == nil {
			c.Header("WWW-Authenticate", `Bearer error="unauthorized", error_description="Authentication required"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "Authentication required",
			})
			return
		}

		var res Resource
		if len(getResource) > 0 && getResource[0] != nil {
			res = getResource[0](c)
		}

		evalCtx := &EvaluationContext{
			Action: Action{
				Name:       c.Request.Method,
				HTTPMethod: c.Request.Method,
			},
			Resource: res,
			Context: Context{
				ClientIP:  c.ClientIP(),
				Timestamp: time.Now().UTC(),
			},
		}

		decision, err := engine.EvaluatePolicy(c.Request.Context(), policyName, user, evalCtx)
		if err != nil || !decision.Allowed {
			reason := decision.Reason
			if reason == "" {
				reason = "Access denied by policy"
			}

			c.Header("WWW-Authenticate", fmt.Sprintf(`Bearer error="insufficient_scope", error_description="%s"`, reason))
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":             "forbidden",
				"error_description": reason,
				"policy":            policyName,
			})
			return
		}

		c.Next()
	}
}

// RequirePARC enforces an inline PARC requirement (action and resource type) on a Gin route.
func RequirePARC(engine *PolicyEngine, action, resourceType string, getResource ...ResourceExtractorFunc) gin.HandlerFunc {
	if engine == nil {
		panic("authz: PolicyEngine cannot be nil")
	}

	inlinePolicy := NewPolicy(fmt.Sprintf("inline:parc:%s:%s", action, resourceType)).
		RequirePARC(action, resourceType).
		Build()

	return func(c *gin.Context) {
		user := authn.User(c) // Mirrors HttpContext.User
		if user == nil {
			c.Header("WWW-Authenticate", `Bearer error="unauthorized", error_description="Authentication required"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "Authentication required",
			})
			return
		}

		var res Resource
		if len(getResource) > 0 && getResource[0] != nil {
			res = getResource[0](c)
		} else {
			res = Resource{Type: resourceType, ID: "*"}
		}

		evalCtx := &EvaluationContext{
			Action: Action{
				Name:       action,
				HTTPMethod: c.Request.Method,
			},
			Resource: res,
			Context: Context{
				ClientIP:  c.ClientIP(),
				Timestamp: time.Now().UTC(),
			},
		}

		decision, err := engine.Evaluate(c.Request.Context(), inlinePolicy, user, evalCtx)
		if err != nil || !decision.Allowed {
			reason := decision.Reason
			if reason == "" {
				reason = fmt.Sprintf("Missing permission for action '%s' on resource '%s'", action, resourceType)
			}

			c.Header("WWW-Authenticate", fmt.Sprintf(`Bearer error="insufficient_scope", error_description="%s"`, reason))
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":             "insufficient_permissions",
				"error_description": reason,
				"action":            action,
				"resource_type":     resourceType,
			})
			return
		}

		c.Next()
	}
}

package gin

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/JinishBhardwaj/shared-go/auth/authz"
	"github.com/JinishBhardwaj/shared-go/auth/principal"
	ginprincipal "github.com/JinishBhardwaj/shared-go/auth/principal/gin"
	"github.com/gin-gonic/gin"
)

// This file is the destination of the former authn/guards.go
// (gap-analysis-final.md §3.8 step 6). The guards below are gin.HandlerFunc
// route decorators, same as before, but each one now evaluates a built-in
// authz.Requirement through its RequirementHandler instead of re-implementing
// scope/role/method checks inline -- so this package and the PolicyEngine can
// never drift onto two different definitions of "has this scope" or "has this
// role" (Tier 2: "Move all of authn/guards.go into authz as built-in
// Requirement types"). The same port also fixes Tier 0 #6 (HasAnyScope /
// HasAnyRole with an empty list now fails closed, in principal.Principal) and
// Tier 0 #8 (RoleRequirement.RequireAll is honored by RoleRequirementHandler),
// since a straight copy would otherwise have carried both defects across.

var (
	scopeHandler  = &authz.ScopeRequirementHandler{}
	roleHandler   = &authz.RoleRequirementHandler{}
	methodHandler = &authz.MethodRequirementHandler{}
)

// RequireScope enforces that the authenticated principal possesses ALL specified scopes.
// If not, it responds with HTTP 403 Forbidden and RFC 6750 insufficient_scope error.
func RequireScope(requiredScopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := ginprincipal.User(c)
		if user == nil {
			respondUnauthenticated(c)
			return
		}

		req := authz.ScopeRequirement{Scopes: requiredScopes, RequireAll: true}
		allowed, _ := scopeHandler.Handle(c.Request.Context(), user, req, nil)
		if !allowed {
			// requiredScopes is route-wiring config, not attacker input --
			// but per Tier 0 #7 every auth-param value written into this
			// header goes through the same RFC 7235 quoting regardless.
			c.Header("WWW-Authenticate", fmt.Sprintf("Bearer error=%s, scope=%s",
				quoteRFC7235(rfc6750InsufficientScope), quoteRFC7235(strings.Join(requiredScopes, " "))))
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":             "insufficient_scope",
				"error_description": fmt.Sprintf("Requires all of the following scopes: %s", strings.Join(requiredScopes, ", ")),
				"missing_scopes":    missingScopes(user, requiredScopes),
			})
			return
		}

		c.Next()
	}
}

// RequireAnyScope enforces that the authenticated principal possesses AT LEAST ONE of the candidate scopes.
// An empty candidateScopes list fails closed (always denies) -- see Tier 0 #6.
func RequireAnyScope(candidateScopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := ginprincipal.User(c)
		if user == nil {
			respondUnauthenticated(c)
			return
		}

		req := authz.ScopeRequirement{Scopes: candidateScopes, RequireAll: false}
		allowed, _ := scopeHandler.Handle(c.Request.Context(), user, req, nil)
		if !allowed {
			c.Header("WWW-Authenticate", fmt.Sprintf("Bearer error=%s, scope=%s",
				quoteRFC7235(rfc6750InsufficientScope), quoteRFC7235(strings.Join(candidateScopes, " "))))
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":             "insufficient_scope",
				"error_description": fmt.Sprintf("Requires at least one of the following scopes: %s", strings.Join(candidateScopes, ", ")),
			})
			return
		}

		c.Next()
	}
}

// RequireMethod enforces that the request was authenticated with one of the allowed authentication methods / OAuth flows.
func RequireMethod(allowedMethods ...principal.AuthMethod) gin.HandlerFunc {
	methodNames := make([]string, len(allowedMethods))
	for i, m := range allowedMethods {
		methodNames[i] = string(m)
	}

	return func(c *gin.Context) {
		user := ginprincipal.User(c)
		if user == nil {
			respondUnauthenticated(c)
			return
		}

		req := authz.MethodRequirement{Methods: allowedMethods}
		allowed, _ := methodHandler.Handle(c.Request.Context(), user, req, nil)
		if !allowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":             "disallowed_auth_flow",
				"error_description": fmt.Sprintf("This endpoint requires authentication via [%s], but received [%s]", strings.Join(methodNames, ", "), user.Method),
				"current_method":    user.Method,
			})
			return
		}

		c.Next()
	}
}

// RequireUser enforces that an interactive user is present (AuthCode+PKCE or Device Flow).
func RequireUser() gin.HandlerFunc {
	return RequireMethod(principal.AuthMethodAuthCodePKCE, principal.AuthMethodDeviceFlow)
}

// RequireM2M enforces that the request came from an automated Machine-to-Machine flow (Client Credentials or API Key).
func RequireM2M() gin.HandlerFunc {
	return RequireMethod(principal.AuthMethodClientCredentials, principal.AuthMethodAPIKey)
}

// RequireRole enforces that the principal has the specified role(s) (case-insensitive).
func RequireRole(requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := ginprincipal.User(c)
		if user == nil {
			respondUnauthenticated(c)
			return
		}

		req := authz.RoleRequirement{Roles: requiredRoles, RequireAll: true}
		allowed, _ := roleHandler.Handle(c.Request.Context(), user, req, nil)
		if !allowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":             "insufficient_role",
				"error_description": fmt.Sprintf("Missing required role: %s", firstMissingRole(user, requiredRoles)),
			})
			return
		}

		c.Next()
	}
}

// RequireAnyRole enforces that the principal has at least one of the specified roles.
// An empty candidateRoles list fails closed (always denies) -- see Tier 0 #6.
func RequireAnyRole(candidateRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := ginprincipal.User(c)
		if user == nil {
			respondUnauthenticated(c)
			return
		}

		req := authz.RoleRequirement{Roles: candidateRoles, RequireAll: false}
		allowed, _ := roleHandler.Handle(c.Request.Context(), user, req, nil)
		if !allowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":             "insufficient_role",
				"error_description": fmt.Sprintf("Requires at least one of the following roles: %s", strings.Join(candidateRoles, ", ")),
			})
			return
		}

		c.Next()
	}
}

func respondUnauthenticated(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"error":             "unauthorized",
		"error_description": "Authentication required",
	})
}

func missingScopes(p *principal.Principal, required []string) []string {
	var missing []string
	for _, req := range required {
		if !p.HasScope(req) {
			missing = append(missing, req)
		}
	}
	return missing
}

func firstMissingRole(p *principal.Principal, required []string) string {
	for _, r := range required {
		if !p.HasRole(r) {
			return r
		}
	}
	return ""
}

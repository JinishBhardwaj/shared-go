package authn

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// RequireScope enforces that the authenticated principal possesses ALL specified scopes.
// If not, it responds with HTTP 403 Forbidden and RFC 6750 insufficient_scope error.
func RequireScope(requiredScopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := User(c)
		if user == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "Authentication required",
			})
			return
		}

		if !user.HasAllScopes(requiredScopes...) {
			c.Header("WWW-Authenticate", fmt.Sprintf(`Bearer error="insufficient_scope", scope="%s"`, strings.Join(requiredScopes, " ")))
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":             "insufficient_scope",
				"error_description": fmt.Sprintf("Requires all of the following scopes: %s", strings.Join(requiredScopes, ", ")),
				"missing_scopes":    getMissingScopes(user, requiredScopes),
			})
			return
		}

		c.Next()
	}
}

// RequireAnyScope enforces that the authenticated principal possesses AT LEAST ONE of the candidate scopes.
func RequireAnyScope(candidateScopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := User(c)
		if user == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "Authentication required",
			})
			return
		}

		if !user.HasAnyScope(candidateScopes...) {
			c.Header("WWW-Authenticate", fmt.Sprintf(`Bearer error="insufficient_scope", scope="%s"`, strings.Join(candidateScopes, " ")))
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
func RequireMethod(allowedMethods ...AuthMethod) gin.HandlerFunc {
	allowedMap := make(map[AuthMethod]bool, len(allowedMethods))
	methodNames := make([]string, len(allowedMethods))
	for i, m := range allowedMethods {
		allowedMap[m] = true
		methodNames[i] = string(m)
	}

	return func(c *gin.Context) {
		user := User(c)
		if user == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "Authentication required",
			})
			return
		}

		if !allowedMap[user.Method] {
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
	return RequireMethod(AuthMethodAuthCodePKCE, AuthMethodDeviceFlow)
}

// RequireM2M enforces that the request came from an automated Machine-to-Machine flow (Client Credentials or API Key).
func RequireM2M() gin.HandlerFunc {
	return RequireMethod(AuthMethodClientCredentials, AuthMethodAPIKey)
}

// RequireRole enforces that the principal has the specified role (case-insensitive).
func RequireRole(requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := User(c)
		if user == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "Authentication required",
			})
			return
		}

		for _, r := range requiredRoles {
			if !user.HasRole(r) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":             "insufficient_role",
					"error_description": fmt.Sprintf("Missing required role: %s", r),
				})
				return
			}
		}

		c.Next()
	}
}

// RequireAnyRole enforces that the principal has at least one of the specified roles.
func RequireAnyRole(candidateRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := User(c)
		if user == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "Authentication required",
			})
			return
		}

		if !user.HasAnyRole(candidateRoles...) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":             "insufficient_role",
				"error_description": fmt.Sprintf("Requires at least one of the following roles: %s", strings.Join(candidateRoles, ", ")),
			})
			return
		}

		c.Next()
	}
}

func getMissingScopes(p *Principal, required []string) []string {
	var missing []string
	for _, req := range required {
		if !p.HasScope(req) {
			missing = append(missing, req)
		}
	}
	return missing
}

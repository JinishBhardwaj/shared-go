package gin

import (
	"github.com/JinishBhardwaj/shared-go/auth/principal"
	"github.com/gin-gonic/gin"
)

const (
	// DefaultContextKeyPrincipal is the default key used to store the Principal in the Gin context.
	DefaultContextKeyPrincipal = "authn.principal"
)

// Set stores p in the Gin context under DefaultContextKeyPrincipal.
func Set(c *gin.Context, p *principal.Principal) {
	SetWithKey(c, DefaultContextKeyPrincipal, p)
}

// SetWithKey stores p in the Gin context under key.
func SetWithKey(c *gin.Context, key string, p *principal.Principal) {
	c.Set(key, p)
}

// User returns the authenticated Principal attached to the request, or nil if unauthenticated.
// Direct equivalent of ASP.NET Core HttpContext.User.
func User(c *gin.Context) *principal.Principal {
	p, _ := GetPrincipal(c)
	return p
}

// MustUser returns the authenticated Principal or panics if not authenticated.
// Ideal for routes protected by authn.New middleware.
func MustUser(c *gin.Context) *principal.Principal {
	p, ok := GetPrincipal(c)
	if !ok || p == nil {
		panic("principal/gin: no Principal found in gin context. Ensure the authn middleware is configured on this route.")
	}
	return p
}

// GetPrincipal extracts the authenticated Principal from the Gin context using the default key.
func GetPrincipal(c *gin.Context) (*principal.Principal, bool) {
	return GetPrincipalWithKey(c, DefaultContextKeyPrincipal)
}

// GetPrincipalWithKey extracts the authenticated Principal using a custom context key.
func GetPrincipalWithKey(c *gin.Context, key string) (*principal.Principal, bool) {
	val, exists := c.Get(key)
	if !exists {
		return nil, false
	}
	p, ok := val.(*principal.Principal)
	return p, ok
}

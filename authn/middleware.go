package authn

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	// DefaultContextKeyPrincipal is the default key used to store the Principal in the Gin context.
	DefaultContextKeyPrincipal = "authn.principal"

	// DefaultRealm is used in WWW-Authenticate header.
	DefaultRealm = "api"
)

// ErrorHandler is a custom function called when authentication fails.
type ErrorHandler func(c *gin.Context, err error, status int)

// MiddlewareConfig configures the authentication middleware behavior.
type MiddlewareConfig struct {
	contextKey        string
	realm             string
	errorHandler      ErrorHandler
	claimsTransformer ClaimsTransformer
}

// Option configures the middleware.
type Option func(*MiddlewareConfig)

// WithContextKey customizes the Gin context key used to store the authenticated Principal.
func WithContextKey(key string) Option {
	return func(cfg *MiddlewareConfig) {
		if key != "" {
			cfg.contextKey = key
		}
	}
}

// WithRealm sets the realm string in the WWW-Authenticate header.
func WithRealm(realm string) Option {
	return func(cfg *MiddlewareConfig) {
		if realm != "" {
			cfg.realm = realm
		}
	}
}

// WithCustomErrorHandler overrides the default JSON error response writer.
func WithCustomErrorHandler(handler ErrorHandler) Option {
	return func(cfg *MiddlewareConfig) {
		cfg.errorHandler = handler
	}
}

// WithClaimsTransformer registers a ClaimsTransformer (ASP.NET Core IClaimsTransformation).
// Executed after successful token validation to enrich the Principal with domain data.
func WithClaimsTransformer(transformer ClaimsTransformer) Option {
	return func(cfg *MiddlewareConfig) {
		cfg.claimsTransformer = transformer
	}
}

// New creates a Gin middleware that authenticates requests using the provided Authenticator.
func New(authenticator Authenticator, opts ...Option) gin.HandlerFunc {
	if authenticator == nil {
		panic("authn: authenticator cannot be nil")
	}

	cfg := MiddlewareConfig{
		contextKey: DefaultContextKeyPrincipal,
		realm:      DefaultRealm,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return func(c *gin.Context) {
		principal, err := authenticator.Authenticate(c)
		if err != nil {
			handleAuthError(c, err, cfg)
			c.Abort()
			return
		}

		// Run ClaimsTransformer (ASP.NET Core IClaimsTransformation) if configured
		if cfg.claimsTransformer != nil {
			principal, err = cfg.claimsTransformer.Transform(c.Request.Context(), principal)
			if err != nil {
				handleAuthError(c, err, cfg)
				c.Abort()
				return
			}
		}

		// Attach principal to context
		c.Set(cfg.contextKey, principal)
		c.Next()
	}
}

// handleAuthError emits RFC 6750 compliant headers and JSON response.
func handleAuthError(c *gin.Context, err error, cfg MiddlewareConfig) {
	status := http.StatusUnauthorized
	var errCode, errDesc string

	switch {
	case errors.Is(err, ErrNoCredentialsFound):
		errCode = "unauthorized"
		errDesc = "No credentials provided"
	case errors.Is(err, ErrTokenExpired), errors.Is(err, ErrAPIKeyExpired):
		errCode = "invalid_token"
		errDesc = "The credential has expired"
	case errors.Is(err, ErrAPIKeyRevoked):
		errCode = "invalid_token"
		errDesc = "The API key has been revoked"
	case errors.Is(err, ErrMultipleCredTypes):
		errCode = "invalid_request"
		errDesc = "Multiple conflicting authentication methods supplied"
	case errors.Is(err, ErrInvalidHeader):
		errCode = "invalid_request"
		errDesc = "Malformed authorization header"
	default:
		errCode = "invalid_token"
		errDesc = err.Error()
	}

	authHeaderVal := fmt.Sprintf(`Bearer realm="%s", error="%s", error_description="%s"`, cfg.realm, errCode, errDesc)
	c.Header("WWW-Authenticate", authHeaderVal)

	if cfg.errorHandler != nil {
		cfg.errorHandler(c, err, status)
		return
	}

	c.JSON(status, gin.H{
		"error":             errCode,
		"error_description": errDesc,
	})
}

// User returns the authenticated Principal attached to the request, or nil if unauthenticated.
// Direct equivalent of ASP.NET Core HttpContext.User.
func User(c *gin.Context) *Principal {
	p, _ := GetPrincipal(c)
	return p
}

// MustUser returns the authenticated Principal or panics if not authenticated.
// Ideal for routes protected by authn.New middleware.
func MustUser(c *gin.Context) *Principal {
	p, ok := GetPrincipal(c)
	if !ok || p == nil {
		panic("authn: no Principal found in gin context. Ensure the authn middleware is configured on this route.")
	}
	return p
}

// GetPrincipal extracts the authenticated Principal from the Gin context using the default key.
func GetPrincipal(c *gin.Context) (*Principal, bool) {
	return GetPrincipalWithKey(c, DefaultContextKeyPrincipal)
}

// GetPrincipalWithKey extracts the authenticated Principal using a custom context key.
func GetPrincipalWithKey(c *gin.Context, key string) (*Principal, bool) {
	val, exists := c.Get(key)
	if !exists {
		return nil, false
	}
	principal, ok := val.(*Principal)
	return principal, ok
}

package gin

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/JinishBhardwaj/shared-go/auth/authn"
	"github.com/JinishBhardwaj/shared-go/auth/principal"
	ginprincipal "github.com/JinishBhardwaj/shared-go/auth/principal/gin"
	"github.com/gin-gonic/gin"
)

const (
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
	claimsTransformer principal.ClaimsTransformer
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
func WithClaimsTransformer(transformer principal.ClaimsTransformer) Option {
	return func(cfg *MiddlewareConfig) {
		cfg.claimsTransformer = transformer
	}
}

// WithClaimsTransformation is an ASP.NET Core naming alias for WithClaimsTransformer.
func WithClaimsTransformation(transformation principal.ClaimsTransformation) Option {
	return WithClaimsTransformer(transformation)
}

// UseAuthentication creates a Gin authentication middleware (mirrors ASP.NET Core app.UseAuthentication()).
func UseAuthentication(authenticator Authenticator, opts ...Option) gin.HandlerFunc {
	return New(authenticator, opts...)
}

// New creates a Gin middleware that authenticates requests using the provided Authenticator.
func New(authenticator Authenticator, opts ...Option) gin.HandlerFunc {
	if authenticator == nil {
		panic("authn: authenticator cannot be nil")
	}

	cfg := MiddlewareConfig{
		contextKey: ginprincipal.DefaultContextKeyPrincipal,
		realm:      DefaultRealm,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return func(c *gin.Context) {
		p, err := authenticator.Authenticate(c)
		if err != nil {
			handleAuthError(c, err, cfg)
			c.Abort()
			return
		}

		// Run ClaimsTransformer (ASP.NET Core IClaimsTransformation) if configured
		if cfg.claimsTransformer != nil {
			p, err = cfg.claimsTransformer.Transform(c.Request.Context(), p)
			if err != nil {
				handleAuthError(c, err, cfg)
				c.Abort()
				return
			}
		}

		// Attach principal to context
		ginprincipal.SetWithKey(c, cfg.contextKey, p)
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
	case errors.Is(err, authn.ErrTokenExpired), errors.Is(err, authn.ErrAPIKeyExpired):
		errCode = "invalid_token"
		errDesc = "The credential has expired"
	case errors.Is(err, authn.ErrAPIKeyRevoked):
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

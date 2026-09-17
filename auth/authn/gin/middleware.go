package gin

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/JinishBhardwaj/shared-go/auth/authn"
	"github.com/JinishBhardwaj/shared-go/auth/authn/apikey"
	"github.com/JinishBhardwaj/shared-go/auth/authn/oidc"
	"github.com/JinishBhardwaj/shared-go/auth/principal"
	ginprincipal "github.com/JinishBhardwaj/shared-go/auth/principal/gin"
	"github.com/gin-gonic/gin"
	"github.com/tucowsinc/tdp-shared-go/problem"
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
	idTokenHeader     string
	idTokenEnricher   *oidc.IDTokenGroupsEnricher
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

// WithIDTokenGroupsEnrichment registers an oidc.IDTokenGroupsEnricher and
// the request header it should read a second, non-bearer ID token from (e.g.
// "X-Id-Token"). Runs once, right after successful authentication and before
// any configured ClaimsTransformer, so a database-backed transformer sees the
// enriched roles too. The header's token is never treated as a credential --
// see IDTokenGroupsEnricher's doc comment.
func WithIDTokenGroupsEnrichment(headerName string, enricher *oidc.IDTokenGroupsEnricher) Option {
	return func(cfg *MiddlewareConfig) {
		cfg.idTokenHeader = headerName
		cfg.idTokenEnricher = enricher
	}
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

		// ID token supplemental groups enrichment (see WithIDTokenGroupsEnrichment),
		// before ClaimsTransformer so a DB-backed transformer sees enriched roles too.
		if cfg.idTokenEnricher != nil && cfg.idTokenHeader != "" {
			if idTok := c.GetHeader(cfg.idTokenHeader); idTok != "" {
				p = cfg.idTokenEnricher.Enrich(c.Request.Context(), idTok, p)
			}
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

// RFC 6750 (Bearer Token Usage §3.1) defines a closed error-code vocabulary
// for the WWW-Authenticate challenge: invalid_request, invalid_token,
// insufficient_scope. "unauthorized" is not part of that registry but is
// this package's own long-standing, fixed, non-leaking convention for "no
// credentials were presented at all" (kept here for response-shape
// compatibility -- it carries no dynamic content, so it's as safe as the
// three RFC-defined codes).
//
// Tier 0 #7: every errCode/errDesc assigned in handleAuthError below MUST be
// one of a small set of fixed literals -- never the text of an arbitrary
// error. Internal validator errors (a wrapped go-oidc/JWKS failure, a
// custom BearerTokenValidator's own error, a DB message from a
// custom APIKeyStore, etc.) can contain IdP/DB internals and, unescaped,
// can also break the header's quoted-string and inject additional header
// fields or response content. Real detail is logged server-side only
// (logAuthFailure) and never echoed to the caller.
const (
	rfc6750Unauthorized   = "unauthorized"
	rfc6750InvalidRequest = "invalid_request"
	rfc6750InvalidToken   = "invalid_token"
)

// handleAuthError emits RFC 6750 compliant headers and JSON response.
func handleAuthError(c *gin.Context, err error, cfg MiddlewareConfig) {
	status := http.StatusUnauthorized
	var errCode, errDesc string

	switch {
	case errors.Is(err, ErrNoCredentialsFound):
		errCode = rfc6750Unauthorized
		errDesc = "No credentials provided"
	case errors.Is(err, authn.ErrTokenExpired), errors.Is(err, apikey.ErrAPIKeyExpired):
		errCode = rfc6750InvalidToken
		errDesc = "The credential has expired"
	case errors.Is(err, apikey.ErrAPIKeyRevoked):
		errCode = rfc6750InvalidToken
		errDesc = "The API key has been revoked"
	case errors.Is(err, ErrMultipleCredTypes):
		errCode = rfc6750InvalidRequest
		errDesc = "Multiple conflicting authentication methods supplied"
	case errors.Is(err, ErrInvalidHeader):
		errCode = rfc6750InvalidRequest
		errDesc = "Malformed authorization header"
	default:
		// Signature failures, JWKS/OIDC discovery errors, a custom
		// BearerTokenValidator/APIKeyStore's own errors, and anything else
		// not explicitly classified above land here. Their Error() text is
		// never safe to return to the caller (Tier 0 #7) -- log it
		// server-side and answer with a fixed, generic description only.
		errCode = rfc6750InvalidToken
		errDesc = "The provided credential could not be validated"
	}

	logAuthFailure(err)

	authHeaderVal := fmt.Sprintf("Bearer realm=%s, error=%s, error_description=%s",
		quoteRFC7235(cfg.realm), quoteRFC7235(errCode), quoteRFC7235(errDesc))
	c.Header("WWW-Authenticate", authHeaderVal)

	if cfg.errorHandler != nil {
		cfg.errorHandler(c, err, status)
		return
	}

	// RFC 9457 Problem Details body, with the legacy RFC 6750 error/
	// error_description keys carried as extension members (RFC 9457
	// section 3.2) so existing clients parsing those keys keep working.
	problem.Details{
		Status:   status,
		Title:    http.StatusText(status),
		Detail:   errDesc,
		Instance: c.Request.URL.Path,
		Extensions: map[string]any{
			"error":             errCode,
			"error_description": errDesc,
		},
	}.WriteTo(c.Writer)
}

// logAuthFailure records the real, unsanitized authentication error
// server-side only (Tier 0 #7's "log the real detail server-side only"
// requirement). Never called anywhere near a header or response body.
func logAuthFailure(err error) {
	log.Printf("authn: rejecting request: %v", err)
}

// quoteRFC7235 renders s as an RFC 7235 quoted-string for use as an
// auth-param value: wrapped in double quotes, with '"' and '\' backslash-
// escaped, and CR/LF/other control characters dropped outright (escaping
// them would still deliver them into the header value; RFC 7230 forbids
// them in a header field entirely). This is what stops a value containing
// a stray quote or embedded newline from truncating the auth-param early or
// injecting additional header fields / response content (Tier 0 #7).
func quoteRFC7235(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\r' || r == '\n' || r < 0x20 || r == 0x7f:
			continue
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

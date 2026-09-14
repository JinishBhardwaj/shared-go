package authn

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken       = errors.New("authn: invalid or malformed token")
	ErrTokenExpired       = errors.New("authn: token has expired")
	ErrTokenNotYetValid   = errors.New("authn: token is not valid yet (nbf)")
	ErrInvalidIssuer      = errors.New("authn: token issuer does not match expected issuer")
	ErrInvalidAudience    = errors.New("authn: token audience does not match expected audience")
	ErrMissingSubject     = errors.New("authn: token missing subject claim")
	ErrUnsupportedKeyFunc = errors.New("authn: no key function or public key configured for token verification")
)

// JWTValidatorConfig configures the JWT validation engine.
type JWTValidatorConfig struct {
	// KeyFunc provides the key for signature verification (HMAC, RSA, ECDSA, or JWKS).
	KeyFunc jwt.Keyfunc

	// ExpectedIssuer verifies the 'iss' claim matches this value. Optional.
	ExpectedIssuer string

	// ExpectedAudience verifies the 'aud' claim includes this value. Optional.
	ExpectedAudience string

	// AllowedSigningAlgs restricts acceptable JWT 'alg' headers (e.g. ["RS256", "ES256", "HS256"]).
	AllowedSigningAlgs []string

	// ClockSkewTolerance allows for slight clock differences when validating 'exp' and 'nbf'.
	// Defaults to 1 minute if zero.
	ClockSkewTolerance time.Duration

	// Normalizer maps claims into an Identity. Optional.
	// Defaults to StandardOIDCNormalizer if nil.
	Normalizer ClaimsNormalizer
}

// JWTValidator validates Bearer JWT tokens and maps them to an Identity.
type JWTValidator struct {
	config JWTValidatorConfig
}

// NewJWTValidator creates a new JWT validator.
func NewJWTValidator(cfg JWTValidatorConfig) (*JWTValidator, error) {
	if cfg.KeyFunc == nil {
		return nil, ErrUnsupportedKeyFunc
	}
	if cfg.ClockSkewTolerance == 0 {
		cfg.ClockSkewTolerance = 1 * time.Minute
	}
	if cfg.Normalizer == nil {
		cfg.Normalizer = NewStandardOIDCNormalizer()
	}
	return &JWTValidator{config: cfg}, nil
}

// ValidateToken parses, cryptographically verifies, and extracts a Principal from a JWT string.
func (v *JWTValidator) ValidateToken(ctx context.Context, tokenStr string) (*principal.Principal, error) {
	parserOpts := []jwt.ParserOption{
		jwt.WithLeeway(v.config.ClockSkewTolerance),
	}
	if len(v.config.AllowedSigningAlgs) > 0 {
		parserOpts = append(parserOpts, jwt.WithValidMethods(v.config.AllowedSigningAlgs))
	}
	if v.config.ExpectedIssuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(v.config.ExpectedIssuer))
	}
	if v.config.ExpectedAudience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(v.config.ExpectedAudience))
	}

	claims := jwt.MapClaims{}
	parsedToken, err := jwt.ParseWithClaims(tokenStr, claims, v.config.KeyFunc, parserOpts...)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, ErrTokenNotYetValid
		}
		if errors.Is(err, jwt.ErrTokenInvalidIssuer) {
			return nil, ErrInvalidIssuer
		}
		if errors.Is(err, jwt.ErrTokenInvalidAudience) {
			return nil, ErrInvalidAudience
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !parsedToken.Valid {
		return nil, ErrInvalidToken
	}

	return v.config.Normalizer.Normalize(claims, tokenStr)
}

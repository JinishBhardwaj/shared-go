// Package bearer provides static-key/JWKS-keyfunc JWT bearer token
// validation (JWTValidator), as opposed to authn/oidc's dynamic OIDC
// discovery flow.
package bearer

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/JinishBhardwaj/shared-go/auth/authn"
	"github.com/JinishBhardwaj/shared-go/auth/authn/mapping"
	"github.com/JinishBhardwaj/shared-go/auth/principal"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sony/gobreaker/v2"
)

// JWTValidatorConfig configures the JWT validation engine.
type JWTValidatorConfig struct {
	// KeyFunc provides the key for signature verification (HMAC, RSA, ECDSA, or JWKS).
	KeyFunc jwt.Keyfunc

	// ExpectedIssuer verifies the 'iss' claim matches this value. Optional.
	ExpectedIssuer string

	// ExpectedAudience verifies the 'aud' claim includes this value. Optional.
	ExpectedAudience string

	// AudienceValidator, if set, is consulted as an additional, independent
	// acceptance path alongside ExpectedAudience -- a token is accepted if
	// it matches either. Setting this defers audience enforcement out of
	// the parser (jwt.WithAudience is not applied) so this callback always
	// gets a chance to accept a token ExpectedAudience alone would have
	// rejected. See authn.AudienceValidator's own doc comment for its
	// contract (bounded, breaker-guarded, fail-closed).
	AudienceValidator authn.AudienceValidator

	// AudienceValidatorTimeout bounds each AudienceValidator call with a
	// context deadline. Defaults to 50ms, same reasoning as
	// oidc.OIDCValidatorConfig.AudienceValidatorTimeout. Ignored if
	// AudienceValidator is nil.
	AudienceValidatorTimeout time.Duration

	// AllowedSigningAlgs restricts acceptable JWT 'alg' headers (e.g. ["RS256", "ES256", "HS256"]).
	AllowedSigningAlgs []string

	// ClockSkewTolerance allows for slight clock differences when validating 'exp' and 'nbf'.
	// Defaults to 1 minute if zero.
	ClockSkewTolerance time.Duration

	// Normalizer maps claims into an Identity. Optional.
	// Defaults to mapping.NewStandardOIDCNormalizer() if nil.
	Normalizer authn.ClaimsNormalizer

	// TypEnforcement controls RFC 9068 "typ: at+jwt" header enforcement.
	// Defaults to authn.TypEnforcementOff (the zero value) -- see
	// authn.TypEnforcementMode's doc comment for why this must not default
	// to strict.
	TypEnforcement authn.TypEnforcementMode
}

// JWTValidator validates Bearer JWT tokens and maps them to an Identity.
type JWTValidator struct {
	config JWTValidatorConfig

	// audienceValidatorBreaker guards JWTValidatorConfig.AudienceValidator
	// calls -- see oidc.OIDCValidator's own audienceValidatorBreaker doc
	// comment for why this is a separate breaker rather than reusing any
	// other one.
	audienceValidatorBreaker *gobreaker.CircuitBreaker[bool]
}

// NewJWTValidator creates a new JWT validator.
func NewJWTValidator(cfg JWTValidatorConfig) (*JWTValidator, error) {
	if cfg.KeyFunc == nil {
		return nil, authn.ErrUnsupportedKeyFunc
	}
	if cfg.ClockSkewTolerance == 0 {
		cfg.ClockSkewTolerance = 1 * time.Minute
	}
	if cfg.Normalizer == nil {
		cfg.Normalizer = mapping.NewStandardOIDCNormalizer()
	}
	if cfg.AudienceValidatorTimeout <= 0 {
		cfg.AudienceValidatorTimeout = 50 * time.Millisecond
	}
	return &JWTValidator{
		config:                   cfg,
		audienceValidatorBreaker: gobreaker.NewCircuitBreaker[bool](gobreaker.Settings{Name: "authn-jwt-audience-validator"}),
	}, nil
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
	// Only enforced at the parser level when there's no AudienceValidator to
	// also consult -- jwt.WithAudience would otherwise hard-reject a token
	// before the dynamic check ever runs, the same reasoning as
	// oidc.OIDCValidator's deferToValidateToken.
	if v.config.ExpectedAudience != "" && v.config.AudienceValidator == nil {
		parserOpts = append(parserOpts, jwt.WithAudience(v.config.ExpectedAudience))
	}

	claims := jwt.MapClaims{}
	parsedToken, err := jwt.ParseWithClaims(tokenStr, claims, v.config.KeyFunc, parserOpts...)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, authn.ErrTokenExpired
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, authn.ErrTokenNotYetValid
		}
		if errors.Is(err, jwt.ErrTokenInvalidIssuer) {
			return nil, authn.ErrInvalidIssuer
		}
		if errors.Is(err, jwt.ErrTokenInvalidAudience) {
			return nil, authn.ErrInvalidAudience
		}
		return nil, fmt.Errorf("%w: %v", authn.ErrInvalidToken, err)
	}

	if !parsedToken.Valid {
		return nil, authn.ErrInvalidToken
	}

	// RFC 9068 typ enforcement (Tier 4, optional hardening -- config-gated,
	// defaults to off; see authn.TypEnforcementMode's doc comment). Applied
	// only after the signature above has already been verified, since the
	// typ header is part of the signed content and is only safe to trust
	// once verification has succeeded.
	if err := authn.EnforceTyp(v.config.TypEnforcement, tokenStr); err != nil {
		return nil, err
	}

	// When an AudienceValidator is configured, ExpectedAudience was NOT
	// enforced at the parser level above, so enforce full audience
	// acceptance here: accepted if the token matches either ExpectedAudience
	// or the dynamic AudienceValidator. See authn.AudienceValidator's doc
	// comment for its fail-closed/breaker contract.
	if v.config.AudienceValidator != nil {
		aud, _ := claims.GetAudience()
		accepted := v.config.ExpectedAudience != "" && authn.AudienceIntersects(aud, []string{v.config.ExpectedAudience})

		if !accepted {
			actx, cancel := context.WithTimeout(ctx, v.config.AudienceValidatorTimeout)
			ok, dynErr := v.audienceValidatorBreaker.Execute(func() (bool, error) {
				return v.config.AudienceValidator(actx, claims)
			})
			cancel()
			accepted = dynErr == nil && ok
		}

		if !accepted {
			return nil, fmt.Errorf("%w: token audience %v not accepted", authn.ErrInvalidAudience, aud)
		}
	}

	return v.config.Normalizer.Normalize(claims, tokenStr)
}

package authn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

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
func (v *JWTValidator) ValidateToken(ctx context.Context, tokenStr string) (*Principal, error) {
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

// mapClaimsToPrincipal transforms parsed JWT claims into our unified Principal structure.
func (v *JWTValidator) mapClaimsToPrincipal(claims jwt.MapClaims, rawToken string) (*Principal, error) {
	return v.config.Normalizer.Normalize(claims, rawToken)
}

// extractClientID retrieves client_id, azp (authorized party), or cid claim.
func extractClientID(claims jwt.MapClaims) string {
	if cid, ok := claims["client_id"].(string); ok && cid != "" {
		return cid
	}
	if azp, ok := claims["azp"].(string); ok && azp != "" {
		return azp
	}
	if cid, ok := claims["cid"].(string); ok && cid != "" {
		return cid
	}
	return ""
}

// extractScopes parses scopes from space-delimited string or array.
func extractScopes(claims jwt.MapClaims) []string {
	var scopes []string

	// Try standard 'scope' claim (can be string or []interface{})
	if rawScope, ok := claims["scope"]; ok {
		switch val := rawScope.(type) {
		case string:
			for _, s := range strings.Split(val, " ") {
				s = strings.TrimSpace(s)
				if s != "" {
					scopes = append(scopes, s)
				}
			}
		case []any:
			for _, item := range val {
				if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
					scopes = append(scopes, strings.TrimSpace(s))
				}
			}
		}
	}

	// Try Microsoft / Okta 'scp' array
	if len(scopes) == 0 {
		if rawScp, ok := claims["scp"]; ok {
			if scpSlice, ok := rawScp.([]any); ok {
				for _, item := range scpSlice {
					if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
						scopes = append(scopes, strings.TrimSpace(s))
					}
				}
			}
		}
	}

	return scopes
}

// extractRoles extracts role/permission assignments from claims.
func extractRoles(claims jwt.MapClaims) []string {
	var roles []string

	extractFromSlice := func(val any) {
		if slice, ok := val.([]any); ok {
			for _, item := range slice {
				if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
					roles = append(roles, strings.TrimSpace(s))
				}
			}
		} else if slice, ok := val.([]string); ok {
			roles = append(roles, slice...)
		}
	}

	// Direct roles or permissions claim
	if r, ok := claims["roles"]; ok {
		extractFromSlice(r)
	}
	if len(roles) == 0 {
		if p, ok := claims["permissions"]; ok {
			extractFromSlice(p)
		}
	}

	// Keycloak realm_access.roles
	if len(roles) == 0 {
		if ra, ok := claims["realm_access"].(map[string]any); ok {
			if r, ok := ra["roles"]; ok {
				extractFromSlice(r)
			}
		}
	}

	return roles
}

// determineOAuthFlow inspects grant type claims (gty, grant_type, amr) to classify the OAuth flow.
func determineOAuthFlow(claims jwt.MapClaims, clientID, sub string) AuthMethod {
	// 1. Inspect explicit 'gty' (Auth0/Okta standard) or 'grant_type'
	grantType := ""
	if gt, ok := claims["gty"].(string); ok && gt != "" {
		grantType = gt
	} else if gt, ok := claims["grant_type"].(string); ok && gt != "" {
		grantType = gt
	}

	switch strings.ToLower(grantType) {
	case "client_credentials", "client-credentials":
		return AuthMethodClientCredentials
	case "urn:ietf:params:oauth:grant-type:device_code", "device_code", "device":
		return AuthMethodDeviceFlow
	case "authorization_code", "auth_code", "pkce":
		return AuthMethodAuthCodePKCE
	}

	// 2. Inspect 'amr' (Authentication Methods References - RFC 8176)
	if amrRaw, ok := claims["amr"]; ok {
		if amrList, ok := amrRaw.([]any); ok {
			for _, item := range amrList {
				if s, ok := item.(string); ok {
					sLower := strings.ToLower(s)
					if sLower == "pkce" {
						return AuthMethodAuthCodePKCE
					}
					if strings.Contains(sLower, "device") {
						return AuthMethodDeviceFlow
					}
				}
			}
		}
	}

	// 3. Fallback heuristic:
	// If sub matches client_id or starts with service-account / client-, it's machine-to-machine.
	if clientID != "" && (sub == clientID || strings.HasPrefix(sub, "service-account-") || strings.HasPrefix(sub, "client-")) {
		return AuthMethodClientCredentials
	}

	// If device code metadata is attached
	if _, ok := claims["device_code"]; ok {
		return AuthMethodDeviceFlow
	}

	// If an end-user subject exists and no M2M markers were detected, default to AuthCode+PKCE
	if sub != "" {
		return AuthMethodAuthCodePKCE
	}

	return AuthMethodUnknown
}

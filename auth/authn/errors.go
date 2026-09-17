package authn

import "errors"

// Sentinel errors shared by every concrete TokenValidator implementation
// (authn/oidc.OIDCValidator, authn/bearer.JWTValidator) so callers can
// errors.Is against one fixed set regardless of which validator produced
// the failure.
var (
	ErrInvalidToken       = errors.New("authn: invalid or malformed token")
	ErrTokenExpired       = errors.New("authn: token has expired")
	ErrTokenNotYetValid   = errors.New("authn: token is not valid yet (nbf)")
	ErrInvalidIssuer      = errors.New("authn: token issuer does not match expected issuer")
	ErrInvalidAudience    = errors.New("authn: token audience does not match expected audience")
	ErrMissingSubject     = errors.New("authn: token missing subject claim")
	ErrUnsupportedKeyFunc = errors.New("authn: no key function or public key configured for token verification")
)

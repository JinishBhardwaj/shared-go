package authn

import (
	"github.com/JinishBhardwaj/shared-go/auth/principal"
	"github.com/golang-jwt/jwt/v5"
)

// ClaimsNormalizer defines the strategy for mapping IdP-specific JWT claims into a normalized Principal.
// Conforms to the Strategy Pattern and Open/Closed Principle. Concrete
// implementations (StandardOIDCNormalizer, CognitoClaimsNormalizer) live in
// authn/mapping.
type ClaimsNormalizer interface {
	// Normalize parses token claims and builds a Principal.
	Normalize(claims jwt.MapClaims, rawToken string) (*principal.Principal, error)
}

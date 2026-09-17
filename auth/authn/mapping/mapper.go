// Package mapping provides IdP-specific claims-to-Principal mapping
// (ClaimsNormalizer implementations) and group/role extraction strategies.
// Deliberately depends on no other authn subpackage -- every type here
// satisfies authn.ClaimsNormalizer structurally, without importing it.
package mapping

import "github.com/golang-jwt/jwt/v5"

// GroupsExtractor extracts group/role names from one specific IdP-defined
// claim shape. New Cognito claim shapes (or a customer's own custom-attribute
// name) are added by implementing this interface, never by editing
// CognitoClaimsNormalizer.Normalize (Strategy pattern, Open/Closed).
type GroupsExtractor interface {
	ExtractGroups(claims jwt.MapClaims) []string
}

// GroupFilter reports whether a group name extracted by a GroupsExtractor
// should be kept. Composed onto a normalizer via WithGroupFilter so
// Cognito-specific noise (e.g. a synthetic IdP-association pseudo-group) can
// be dropped without touching extraction logic.
type GroupFilter func(group string) bool

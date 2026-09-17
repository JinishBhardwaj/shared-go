package mapping

import (
	"time"

	"github.com/JinishBhardwaj/shared-go/auth/authn"
	"github.com/JinishBhardwaj/shared-go/auth/principal"
	"github.com/golang-jwt/jwt/v5"
)

// StandardOIDCNormalizer normalizes RFC 7519 / OpenID Connect standard claims.
// Works seamlessly across Keycloak, Auth0, Okta, and generic OAuth 2.0 authorization servers.
type StandardOIDCNormalizer struct{}

// NewStandardOIDCNormalizer returns a new StandardOIDCNormalizer.
func NewStandardOIDCNormalizer() *StandardOIDCNormalizer {
	return &StandardOIDCNormalizer{}
}

// Normalize extracts standard claims: sub, iss, aud, exp, nbf, scopes, and roles.
func (n *StandardOIDCNormalizer) Normalize(claims jwt.MapClaims, rawToken string) (*principal.Principal, error) {
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, authn.ErrMissingSubject
	}

	clientID := ExtractClientID(claims)
	scopes := extractScopes(claims)
	roles := extractRoles(claims)
	flow := determineOAuthFlow(claims, clientID, sub)

	var issuedAt, expiresAt time.Time
	if iat, err := claims.GetIssuedAt(); err == nil && iat != nil {
		issuedAt = iat.Time
	}
	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
		expiresAt = exp.Time
	}

	issuer, _ := claims.GetIssuer()
	audiences, _ := claims.GetAudience()

	metadata := filterStandardClaims(claims)

	return &principal.Principal{
		Subject:  sub,
		ClientID: clientID,
		Method:   flow,
		// Computed from the same positive-signal-only flow determination as
		// Method, at this same trusted point -- see principal.Principal.UserPresent's
		// doc comment for why IsUserPresent() reads this field directly
		// instead of re-deriving it from Method.
		UserPresent: flow == principal.AuthMethodAuthCodePKCE || flow == principal.AuthMethodDeviceFlow,
		Scopes:      scopes,
		Roles:       roles,
		Issuer:      issuer,
		Audiences:   audiences,
		IssuedAt:    issuedAt,
		ExpiresAt:   expiresAt,
		Metadata:    metadata,
		RawToken:    rawToken,
	}, nil
}

// nativeArrayGroupsExtractor reads a claim holding a real JSON array of
// strings, e.g. Cognito's built-in "cognito:groups".
type nativeArrayGroupsExtractor struct{ claim string }

// NewNativeArrayGroupsExtractor returns a GroupsExtractor for a claim shaped
// as a genuine array of strings.
func NewNativeArrayGroupsExtractor(claim string) GroupsExtractor {
	return nativeArrayGroupsExtractor{claim: claim}
}

func (e nativeArrayGroupsExtractor) ExtractGroups(claims jwt.MapClaims) []string {
	raw, ok := claims[e.claim]
	if !ok {
		return nil
	}
	slice, ok := raw.([]any)
	if !ok {
		return nil
	}
	var groups []string
	for _, g := range slice {
		if s, ok := g.(string); ok && s != "" {
			groups = append(groups, s)
		}
	}
	return groups
}

package authn

import (
	"context"
	"log"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
	"github.com/golang-jwt/jwt/v5"
)

// idTokenVerifier is the narrow capability IDTokenGroupsEnricher depends on
// (Dependency Inversion): verify a token and return its claims, nothing more.
// *OIDCValidator satisfies this via VerifyClaims; tests can supply a stub.
type idTokenVerifier interface {
	VerifyClaims(ctx context.Context, tokenStr string) (jwt.MapClaims, error)
}

// IDTokenGroupsEnricher enriches a Principal -- already authenticated off an
// access token -- with group/role claims that only ever appear on the
// corresponding Cognito ID token, e.g. a SAML "groups" attribute Cognito
// mapped onto a custom attribute such as "custom:groups".
//
// It never accepts the ID token as authentication proof: the token is
// independently signature- and claims-verified (via the same verifier used
// for the access token), its groups are extracted and filtered exactly as
// CognitoClaimsNormalizer would, and only the resulting group names are
// merged into the principal the real authentication step already produced.
// A missing, invalid, or unverifiable ID token degrades enrichment, never
// authentication: Enrich returns the principal unchanged rather than an
// error, since the ID token is optional supplemental input, not a second
// credential the caller must present correctly.
type IDTokenGroupsEnricher struct {
	verifier   idTokenVerifier
	extractors []GroupsExtractor
	filters    []GroupFilter
}

// NewIDTokenGroupsEnricher builds an enricher backed by verifier (typically
// the same *OIDCValidator used to authenticate the access token, against the
// same Cognito user pool/app client, so its verifier already trusts the
// right issuer and audience) and the given GroupsExtractors/GroupFilters
// (e.g. NewCognitoCustomAttrListExtractor("custom:groups")).
func NewIDTokenGroupsEnricher(verifier *OIDCValidator, extractors []GroupsExtractor, filters ...GroupFilter) *IDTokenGroupsEnricher {
	return &IDTokenGroupsEnricher{verifier: verifier, extractors: extractors, filters: filters}
}

// Enrich verifies idTokenStr and returns a copy of p with any extracted
// groups merged into Roles. p is never mutated in place. If idTokenStr is
// empty, p is nil, or verification fails, p is returned unchanged (a
// verification failure is logged server-side, not surfaced as an error --
// see the type doc comment on why enrichment failure must not block the
// request).
func (e *IDTokenGroupsEnricher) Enrich(ctx context.Context, idTokenStr string, p *principal.Principal) *principal.Principal {
	if idTokenStr == "" || p == nil {
		return p
	}

	claims, err := e.verifier.VerifyClaims(ctx, idTokenStr)
	if err != nil {
		log.Printf("authn: ID token groups enrichment skipped: %v", err)
		return p
	}

	var groups []string
	for _, extractor := range e.extractors {
		groups = mergeRoles(groups, filterGroups(extractor.ExtractGroups(claims), e.filters))
	}
	if len(groups) == 0 {
		return p
	}

	out := *p
	out.Roles = mergeRoles(append([]string(nil), p.Roles...), groups)
	return &out
}

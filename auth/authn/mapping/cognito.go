package mapping

import (
	"errors"
	"strings"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
	"github.com/golang-jwt/jwt/v5"
)

// ErrIDTokenRejected is returned when a Cognito token's token_use claim
// identifies it as an ID token (or anything other than "access") but it was
// presented where an access token is required. Tier 0 #5: token_use was
// previously read only to resolve ClientID and never enforced, so a
// Cognito ID token would normalize successfully and be accepted as if it
// were a valid access token.
var ErrIDTokenRejected = errors.New("authn: token_use is not \"access\" -- ID tokens are not accepted for API authorization")

// cognitoCustomAttrListExtractor reads a Cognito custom attribute populated
// via SAML attribute mapping from a multi-valued IdP attribute (e.g. Google
// SAML's "groups"). Cognito custom attributes are always plain strings, so a
// multi-valued source attribute is flattened into Cognito's own bracketed,
// comma-separated textual form ("[a, b, c]") rather than a real JSON array --
// this extractor exists specifically to parse that shape, distinct from
// nativeArrayGroupsExtractor above.
type cognitoCustomAttrListExtractor struct{ claim string }

// NewCognitoCustomAttrListExtractor returns a GroupsExtractor for a Cognito
// custom attribute holding a stringified bracketed list, as produced by
// mapping a multi-valued SAML attribute (such as a Google SAML "groups"
// attribute) onto a Cognito custom attribute.
func NewCognitoCustomAttrListExtractor(claim string) GroupsExtractor {
	return cognitoCustomAttrListExtractor{claim: claim}
}

func (e cognitoCustomAttrListExtractor) ExtractGroups(claims jwt.MapClaims) []string {
	raw, ok := claims[e.claim].(string)
	if !ok {
		return nil
	}
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")
	if raw == "" {
		return nil
	}
	var groups []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			groups = append(groups, part)
		}
	}
	return groups
}

// ExcludeIdPAssociationGroups returns a GroupFilter that drops Cognito's
// synthetic "<userPoolID>_<providerName>" pseudo-group. Cognito auto-injects
// this into cognito:groups to record which federated IdP a user linked
// through -- it is IdP-association bookkeeping, not an authorization
// grouping an admin assigned, and should not be treated as a role.
func ExcludeIdPAssociationGroups(userPoolID string) GroupFilter {
	prefix := userPoolID + "_"
	return func(group string) bool {
		return !strings.HasPrefix(group, prefix)
	}
}

// CognitoClaimsNormalizer normalizes AWS Cognito User Pool tokens, including tokens federated from Google SAML.
type CognitoClaimsNormalizer struct {
	standard         *StandardOIDCNormalizer
	groupsExtractors []GroupsExtractor
	groupFilters     []GroupFilter
}

// CognitoNormalizerOption configures a CognitoClaimsNormalizer at construction.
type CognitoNormalizerOption func(*CognitoClaimsNormalizer)

// WithGroupsExtractor adds a GroupsExtractor to the normalizer's pipeline, in
// addition to the built-in "cognito:groups" extractor. Groups from every
// configured extractor are merged (deduplicated case-insensitively) into
// Principal.Roles.
func WithGroupsExtractor(e GroupsExtractor) CognitoNormalizerOption {
	return func(c *CognitoClaimsNormalizer) {
		c.groupsExtractors = append(c.groupsExtractors, e)
	}
}

// WithCustomGroupsAttribute is a convenience option for the common case: a
// Cognito custom attribute (named by the admin in the Cognito console, e.g.
// "custom:groups") populated via SAML attribute mapping from an external
// IdP's multi-valued "groups" attribute.
func WithCustomGroupsAttribute(claim string) CognitoNormalizerOption {
	return WithGroupsExtractor(NewCognitoCustomAttrListExtractor(claim))
}

// WithGroupFilter adds a GroupFilter applied to every extractor's output
// before merging into Principal.Roles. See ExcludeIdPAssociationGroups for
// the common Cognito case.
func WithGroupFilter(f GroupFilter) CognitoNormalizerOption {
	return func(c *CognitoClaimsNormalizer) {
		c.groupFilters = append(c.groupFilters, f)
	}
}

// NewCognitoClaimsNormalizer creates an AWS Cognito claims normalizer. By
// default it extracts only Cognito's built-in "cognito:groups" claim; pass
// WithCustomGroupsAttribute or WithGroupsExtractor to also read groups from a
// Cognito custom attribute (e.g. SAML-mapped groups), and WithGroupFilter
// (e.g. ExcludeIdPAssociationGroups) to drop unwanted entries.
func NewCognitoClaimsNormalizer(opts ...CognitoNormalizerOption) *CognitoClaimsNormalizer {
	c := &CognitoClaimsNormalizer{
		standard:         NewStandardOIDCNormalizer(),
		groupsExtractors: []GroupsExtractor{NewNativeArrayGroupsExtractor("cognito:groups")},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Normalize handles AWS Cognito specific claims:
// - Maps 'cognito:groups' to Roles
// - Resolves client_id from 'client_id' (access token) or 'aud' (id token)
// - Extracts Google SAML federation attributes from 'identities' claim
// - Extracts 'cognito:username' and 'token_use'
func (c *CognitoClaimsNormalizer) Normalize(claims jwt.MapClaims, rawToken string) (*principal.Principal, error) {
	p, err := c.standard.Normalize(claims, rawToken)
	if err != nil {
		return nil, err
	}

	// 0. Enforce token_use (Tier 0 #5). Cognito stamps every token with
	// token_use: "access" or token_use: "id". This normalizer backs
	// API-facing authentication, so an ID token must be rejected outright
	// rather than silently normalized and accepted as an access token. A
	// token with no token_use claim at all is not a Cognito-shaped token in
	// the first place and passes through unchanged (StandardOIDCNormalizer
	// has no token_use concept, and this normalizer's job is limited to the
	// claims Cognito actually defines).
	if tokenUse, ok := claims["token_use"].(string); ok && tokenUse != "access" {
		return nil, ErrIDTokenRejected
	}

	// 1. Map groups to Roles via every configured GroupsExtractor (built-in
	// "cognito:groups" plus any custom-attribute extractor configured via
	// WithCustomGroupsAttribute/WithGroupsExtractor), filtered through any
	// configured GroupFilters (e.g. ExcludeIdPAssociationGroups).
	for _, extractor := range c.groupsExtractors {
		groups := FilterGroups(extractor.ExtractGroups(claims), c.groupFilters)
		p.Roles = MergeRoles(p.Roles, groups)
	}

	// 2. Resolve Client ID in Cognito ID tokens vs Access tokens
	if p.ClientID == "" {
		if cid, ok := claims["client_id"].(string); ok && cid != "" {
			p.ClientID = cid
		} else if tokenUse, ok := claims["token_use"].(string); ok && tokenUse == "id" {
			// In Cognito ID tokens, the app client ID is in 'aud'
			if len(p.Audiences) > 0 {
				p.ClientID = p.Audiences[0]
			}
		}
	}

	// 3. Detect Google SAML or external IdP federation in Cognito
	// When Google SAML is federated through Cognito, Cognito attaches the 'identities' JSON claim
	if identitiesRaw, ok := claims["identities"]; ok {
		if idList, ok := identitiesRaw.([]any); ok && len(idList) > 0 {
			if firstId, ok := idList[0].(map[string]any); ok {
				if providerName, ok := firstId["providerName"].(string); ok {
					p.Metadata["federated_provider"] = providerName
					if strings.EqualFold(providerName, "Google") || strings.Contains(strings.ToLower(providerName), "saml") {
						p.Metadata["auth_origin"] = "google_saml"
					}
				}
			}
		}
	}

	// 4. Attach Cognito Username if present
	if uname, ok := claims["cognito:username"].(string); ok && uname != "" {
		p.Metadata["cognito_username"] = uname
	}

	return p, nil
}

package authn

import (
	"errors"
	"strings"
	"time"

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

// ClaimsNormalizer defines the strategy for mapping IdP-specific JWT claims into a normalized Principal.
// Conforms to the Strategy Pattern and Open/Closed Principle.
type ClaimsNormalizer interface {
	// Normalize parses token claims and builds a Principal.
	Normalize(claims jwt.MapClaims, rawToken string) (*principal.Principal, error)
}

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
		return nil, ErrMissingSubject
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

func filterGroups(groups []string, filters []GroupFilter) []string {
	if len(filters) == 0 {
		return groups
	}
	out := groups[:0:0]
	for _, g := range groups {
		keep := true
		for _, f := range filters {
			if !f(g) {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, g)
		}
	}
	return out
}

// mergeRoles appends incoming to existing, skipping empty values and any
// value already present (case-insensitive). Shared by every GroupsExtractor
// consumer (CognitoClaimsNormalizer and IDTokenGroupsEnricher) so there is a
// single definition of "already have this role."
func mergeRoles(existing []string, incoming []string) []string {
	seen := make(map[string]bool, len(existing))
	for _, r := range existing {
		seen[strings.ToLower(r)] = true
	}
	merged := existing
	for _, g := range incoming {
		if g == "" {
			continue
		}
		key := strings.ToLower(g)
		if seen[key] {
			continue
		}
		seen[key] = true
		merged = append(merged, g)
	}
	return merged
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
		groups := filterGroups(extractor.ExtractGroups(claims), c.groupFilters)
		p.Roles = mergeRoles(p.Roles, groups)
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

func filterStandardClaims(claims jwt.MapClaims) map[string]any {
	metadata := make(map[string]any, len(claims))
	standardClaims := map[string]bool{
		"iss": true, "sub": true, "aud": true, "exp": true,
		"nbf": true, "iat": true, "jti": true, "scope": true,
		"scp": true, "roles": true, "permissions": true,
	}
	for k, val := range claims {
		if !standardClaims[k] {
			metadata[k] = val
		}
	}
	return metadata
}

// ExtractClientID retrieves the client_id, azp (authorized party), or cid
// claim -- exported so an AudienceValidator callback can identify the
// caller for token shapes (e.g. AWS Cognito client_credentials access
// tokens) that carry no "aud" claim at all, only client_id.
func ExtractClientID(claims jwt.MapClaims) string {
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
func determineOAuthFlow(claims jwt.MapClaims, clientID, sub string) principal.AuthMethod {
	// 1. Inspect explicit 'gty' (Auth0/Okta standard) or 'grant_type'
	grantType := ""
	if gt, ok := claims["gty"].(string); ok && gt != "" {
		grantType = gt
	} else if gt, ok := claims["grant_type"].(string); ok && gt != "" {
		grantType = gt
	}

	switch strings.ToLower(grantType) {
	case "client_credentials", "client-credentials":
		return principal.AuthMethodClientCredentials
	case "urn:ietf:params:oauth:grant-type:device_code", "device_code", "device":
		return principal.AuthMethodDeviceFlow
	case "authorization_code", "auth_code", "pkce":
		return principal.AuthMethodAuthCodePKCE
	}

	// 2. Inspect 'amr' (Authentication Methods References - RFC 8176)
	if amrRaw, ok := claims["amr"]; ok {
		if amrList, ok := amrRaw.([]any); ok {
			for _, item := range amrList {
				if s, ok := item.(string); ok {
					sLower := strings.ToLower(s)
					if sLower == "pkce" {
						return principal.AuthMethodAuthCodePKCE
					}
					if strings.Contains(sLower, "device") {
						return principal.AuthMethodDeviceFlow
					}
				}
			}
		}
	}

	// 3. Fallback heuristic:
	// If sub matches client_id or starts with service-account / client-, it's machine-to-machine.
	if clientID != "" && (sub == clientID || strings.HasPrefix(sub, "service-account-") || strings.HasPrefix(sub, "client-")) {
		return principal.AuthMethodClientCredentials
	}

	// If device code metadata is attached
	if _, ok := claims["device_code"]; ok {
		return principal.AuthMethodDeviceFlow
	}

	// Tier 0 #3: do NOT default to AuthMethodAuthCodePKCE just because a
	// subject is present. Many client-credentials tokens (especially from
	// IdPs that omit gty/amr) still carry a sub claim, and inferring "user
	// present" from sub alone let client-credentials tokens satisfy
	// RequireUser()/UserPresentRequirement. "User present" must be a
	// positive signal (an explicit grant_type/gty, amr, or a per-issuer
	// opt-in), never an inference from the absence of M2M markers.
	return principal.AuthMethodUnknown
}

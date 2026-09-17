package mapping

import (
	"strings"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
	"github.com/golang-jwt/jwt/v5"
)

// FilterGroups applies filters to groups, keeping only entries every filter accepts.
func FilterGroups(groups []string, filters []GroupFilter) []string {
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

// MergeRoles appends incoming to existing, skipping empty values and any
// value already present (case-insensitive). Shared by every GroupsExtractor
// consumer (CognitoClaimsNormalizer and authn/oidc.IDTokenGroupsEnricher) so
// there is a single definition of "already have this role."
func MergeRoles(existing []string, incoming []string) []string {
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
// claim -- exported so an authn.AudienceValidator callback can identify the
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

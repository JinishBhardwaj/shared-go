package authn

import (
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ClaimsNormalizer defines the strategy for mapping IdP-specific JWT claims into a normalized Principal.
// Conforms to the Strategy Pattern and Open/Closed Principle.
type ClaimsNormalizer interface {
	// Normalize parses token claims and builds a Principal.
	Normalize(claims jwt.MapClaims, rawToken string) (*Principal, error)
}

// StandardOIDCNormalizer normalizes RFC 7519 / OpenID Connect standard claims.
// Works seamlessly across Keycloak, Auth0, Okta, and generic OAuth 2.0 authorization servers.
type StandardOIDCNormalizer struct{}

// NewStandardOIDCNormalizer returns a new StandardOIDCNormalizer.
func NewStandardOIDCNormalizer() *StandardOIDCNormalizer {
	return &StandardOIDCNormalizer{}
}

// Normalize extracts standard claims: sub, iss, aud, exp, nbf, scopes, and roles.
func (n *StandardOIDCNormalizer) Normalize(claims jwt.MapClaims, rawToken string) (*Principal, error) {
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, ErrMissingSubject
	}

	clientID := extractClientID(claims)
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

	return &Principal{
		Subject:   sub,
		ClientID:  clientID,
		Method:    flow,
		Scopes:    scopes,
		Roles:     roles,
		Issuer:    issuer,
		Audiences: audiences,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
		Metadata:  metadata,
		RawToken:  rawToken,
	}, nil
}

// CognitoClaimsNormalizer normalizes AWS Cognito User Pool tokens, including tokens federated from Google SAML.
type CognitoClaimsNormalizer struct {
	standard *StandardOIDCNormalizer
}

// NewCognitoClaimsNormalizer creates an AWS Cognito claims normalizer.
func NewCognitoClaimsNormalizer() *CognitoClaimsNormalizer {
	return &CognitoClaimsNormalizer{
		standard: NewStandardOIDCNormalizer(),
	}
}

// Normalize handles AWS Cognito specific claims:
// - Maps 'cognito:groups' to Roles
// - Resolves client_id from 'client_id' (access token) or 'aud' (id token)
// - Extracts Google SAML federation attributes from 'identities' claim
// - Extracts 'cognito:username' and 'token_use'
func (c *CognitoClaimsNormalizer) Normalize(claims jwt.MapClaims, rawToken string) (*Principal, error) {
	p, err := c.standard.Normalize(claims, rawToken)
	if err != nil {
		return nil, err
	}

	// 1. Map Cognito Groups to Roles (e.g. ["Admins", "Managers"])
	if rawGroups, ok := claims["cognito:groups"]; ok {
		if groupsSlice, ok := rawGroups.([]any); ok {
			existingRoles := make(map[string]bool, len(p.Roles))
			for _, r := range p.Roles {
				existingRoles[strings.ToLower(r)] = true
			}
			for _, g := range groupsSlice {
				if gStr, ok := g.(string); ok && gStr != "" {
					if !existingRoles[strings.ToLower(gStr)] {
						p.Roles = append(p.Roles, gStr)
						existingRoles[strings.ToLower(gStr)] = true
					}
				}
			}
		}
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

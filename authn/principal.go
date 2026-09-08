package authn

import (
	"context"
	"strings"
	"time"
)

// AuthMethod represents the mechanism or OAuth flow through which the request was authenticated.
type AuthMethod string

const (
	// AuthMethodAuthCodePKCE represents OAuth 2.0 Authorization Code Flow with PKCE.
	AuthMethodAuthCodePKCE AuthMethod = "oauth:auth_code_pkce"

	// AuthMethodClientCredentials represents OAuth 2.0 Client Credentials Grant (Machine-to-Machine).
	AuthMethodClientCredentials AuthMethod = "oauth:client_credentials"

	// AuthMethodDeviceFlow represents OAuth 2.0 Device Authorization Grant (RFC 8628).
	AuthMethodDeviceFlow AuthMethod = "oauth:device_flow"

	// AuthMethodAPIKey represents API Key authentication (header or bearer-based).
	AuthMethodAPIKey AuthMethod = "api_key"

	// AuthMethodUnknown represents an authenticated token whose specific flow could not be determined.
	AuthMethodUnknown AuthMethod = "unknown"
)

// Principal represents the normalized security principal extracted from validated credentials.
// Direct equivalent of ASP.NET Core ClaimsPrincipal (HttpContext.User).
type Principal struct {
	// Subject is the unique ID of the user or machine principal (OAuth `sub` claim or API key owner).
	Subject string `json:"subject"`

	// ClientID is the OAuth client identifier or API key client identifier.
	ClientID string `json:"client_id,omitempty"`

	// Method is the authentication method or OAuth flow used.
	Method AuthMethod `json:"method"`

	// Scopes is the list of granted permission scopes (e.g. ["read:users", "write:orders"]).
	Scopes []string `json:"scopes,omitempty"`

	// Roles is the list of granted roles (e.g. ["admin", "editor"]).
	Roles []string `json:"roles,omitempty"`

	// Issuer is the OAuth token issuer URL or identifier.
	Issuer string `json:"issuer,omitempty"`

	// Audiences is the list of target audiences for the token.
	Audiences []string `json:"audiences,omitempty"`

	// IssuedAt is the timestamp when the credential was issued.
	IssuedAt time.Time `json:"issued_at"`

	// ExpiresAt is the timestamp when the credential expires.
	ExpiresAt time.Time `json:"expires_at"`

	// Metadata holds arbitrary custom claims, user info, tenant details, or enriched database profile data.
	Metadata map[string]any `json:"metadata,omitempty"`

	// RawToken contains the raw credential string (JWT string or API Key).
	RawToken string `json:"-"`
}

// HasScope checks if the principal has a specific permission scope (case-sensitive).
func (p *Principal) HasScope(scope string) bool {
	if p == nil {
		return false
	}
	for _, s := range p.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasAllScopes returns true if the principal has every scope specified in requiredScopes.
func (p *Principal) HasAllScopes(requiredScopes ...string) bool {
	if p == nil {
		return false
	}
	for _, req := range requiredScopes {
		if !p.HasScope(req) {
			return false
		}
	}
	return true
}

// HasAnyScope returns true if the principal has at least one of the scopes in candidateScopes.
func (p *Principal) HasAnyScope(candidateScopes ...string) bool {
	if p == nil {
		return false
	}
	if len(candidateScopes) == 0 {
		return true
	}
	for _, candidate := range candidateScopes {
		if p.HasScope(candidate) {
			return true
		}
	}
	return false
}

// HasRole checks if the principal has a specific role (case-insensitive comparison).
func (p *Principal) HasRole(role string) bool {
	if p == nil {
		return false
	}
	target := strings.ToLower(role)
	for _, r := range p.Roles {
		if strings.ToLower(r) == target {
			return true
		}
	}
	return false
}

// HasAnyRole returns true if the principal has at least one of the candidate roles.
func (p *Principal) HasAnyRole(candidateRoles ...string) bool {
	if p == nil {
		return false
	}
	if len(candidateRoles) == 0 {
		return true
	}
	for _, candidate := range candidateRoles {
		if p.HasRole(candidate) {
			return true
		}
	}
	return false
}

// IsUserPresent returns true if the request was authenticated by an interactive end-user flow
// (e.g. AuthCode+PKCE or Device Flow), as opposed to an automated M2M client or API key.
func (p *Principal) IsUserPresent() bool {
	if p == nil {
		return false
	}
	return p.Method == AuthMethodAuthCodePKCE || p.Method == AuthMethodDeviceFlow
}

// ClaimsTransformer dynamically augments an authenticated Principal with domain data from the database.
// Direct equivalent of ASP.NET Core IClaimsTransformation.
type ClaimsTransformer interface {
	Transform(ctx context.Context, principal *Principal) (*Principal, error)
}

// ClaimsTransformerFunc allows using a standalone function as a ClaimsTransformer.
type ClaimsTransformerFunc func(ctx context.Context, principal *Principal) (*Principal, error)

func (f ClaimsTransformerFunc) Transform(ctx context.Context, principal *Principal) (*Principal, error) {
	return f(ctx, principal)
}

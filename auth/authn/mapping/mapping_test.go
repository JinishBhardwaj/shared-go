package mapping

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestCognitoClaimsNormalizer(t *testing.T) {
	norm := NewCognitoClaimsNormalizer()

	now := time.Now().UTC()
	exp := now.Add(1 * time.Hour)

	claims := jwt.MapClaims{
		"sub":            "cognito-usr-777",
		"cognito:groups": []any{"Admins", "Engineering"},
		"client_id":      "app-client-xyz",
		"iss":            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abcdef",
		"token_use":      "access",
		"scope":          "aws.cognito.signin.user.admin read:reports",
		"iat":            now.Unix(),
		"exp":            exp.Unix(),
		"identities": []any{
			map[string]any{
				"providerName": "Google",
				"providerType": "SAML",
			},
		},
	}

	id, err := norm.Normalize(claims, "dummy.raw.token")
	if err != nil {
		t.Fatalf("failed to normalize Cognito claims: %v", err)
	}

	if id.Subject != "cognito-usr-777" {
		t.Errorf("expected subject 'cognito-usr-777', got '%s'", id.Subject)
	}

	if !id.HasRole("Admins") || !id.HasRole("Engineering") {
		t.Errorf("expected roles Admins and Engineering, got: %v", id.Roles)
	}

	if !id.HasScope("read:reports") {
		t.Errorf("expected scope 'read:reports', got: %v", id.Scopes)
	}

	if id.Metadata["auth_origin"] != "google_saml" {
		t.Errorf("expected auth_origin to be google_saml, got: %v", id.Metadata["auth_origin"])
	}
}

// TestCognitoClaimsNormalizer_TokenUseEnforcement is the Tier 0 #5
// regression test (gap-analysis-final.md: "token_use read only to resolve
// ClientID, never enforced -- Cognito ID tokens are accepted as access
// tokens"). Normalize must reject a token whose token_use is "id" (or
// anything other than "access") rather than silently normalizing it as if
// it were a valid access token.
func TestCognitoClaimsNormalizer_TokenUseEnforcement(t *testing.T) {
	norm := NewCognitoClaimsNormalizer()
	now := time.Now().UTC()
	exp := now.Add(1 * time.Hour)

	baseClaims := func(tokenUse string) jwt.MapClaims {
		claims := jwt.MapClaims{
			"sub": "cognito-usr-777",
			"iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abcdef",
			"aud": "app-client-xyz",
			"iat": now.Unix(),
			"exp": exp.Unix(),
		}
		if tokenUse != "" {
			claims["token_use"] = tokenUse
		}
		return claims
	}

	t.Run("token_use=id is rejected", func(t *testing.T) {
		_, err := norm.Normalize(baseClaims("id"), "dummy.raw.token")
		if err == nil {
			t.Fatal("expected an error rejecting an ID token presented as an access token, got nil")
		}
	})

	t.Run("token_use=access is accepted", func(t *testing.T) {
		id, err := norm.Normalize(baseClaims("access"), "dummy.raw.token")
		if err != nil {
			t.Fatalf("expected an access token to normalize successfully, got: %v", err)
		}
		if id.Subject != "cognito-usr-777" {
			t.Errorf("expected subject 'cognito-usr-777', got '%s'", id.Subject)
		}
	})

	t.Run("token_use absent still normalizes (no Cognito token_use claim to enforce)", func(t *testing.T) {
		if _, err := norm.Normalize(baseClaims(""), "dummy.raw.token"); err != nil {
			t.Fatalf("expected a token with no token_use claim to still normalize, got: %v", err)
		}
	})
}

// TestCognitoClaimsNormalizer_CustomGroupsAttribute covers a Cognito custom
// attribute mapped from a SAML IdP's multi-valued "groups" attribute.
// Cognito always stringifies custom attributes, so a multi-valued source
// attribute lands as a bracketed, comma-separated STRING ("[a, b]"), never a
// real JSON array -- distinct from the native "cognito:groups" claim.
func TestCognitoClaimsNormalizer_CustomGroupsAttribute(t *testing.T) {
	norm := NewCognitoClaimsNormalizer(WithCustomGroupsAttribute("custom:groups"))

	claims := jwt.MapClaims{
		"sub":            "cognito-usr-777",
		"token_use":      "access",
		"cognito:groups": []any{"grafana-stg-users"},
		"custom:groups":  "[domains-tcc-access, domains-iuxp-access]",
	}

	id, err := norm.Normalize(claims, "dummy.raw.token")
	if err != nil {
		t.Fatalf("failed to normalize: %v", err)
	}

	for _, want := range []string{"grafana-stg-users", "domains-tcc-access", "domains-iuxp-access"} {
		if !id.HasRole(want) {
			t.Errorf("expected role %q, got roles: %v", want, id.Roles)
		}
	}
}

// TestCognitoClaimsNormalizer_ExcludeIdPAssociationGroups covers Cognito's
// synthetic "<userPoolID>_<providerName>" pseudo-group, auto-injected into
// cognito:groups to record IdP linkage rather than an assigned role.
func TestCognitoClaimsNormalizer_ExcludeIdPAssociationGroups(t *testing.T) {
	norm := NewCognitoClaimsNormalizer(WithGroupFilter(ExcludeIdPAssociationGroups("us-east-1_DNMvWNMWv")))

	claims := jwt.MapClaims{
		"sub":       "cognito-usr-777",
		"token_use": "access",
		"cognito:groups": []any{
			"grafana-stg-users",
			"us-east-1_DNMvWNMWv_GoogleSAML",
		},
	}

	id, err := norm.Normalize(claims, "dummy.raw.token")
	if err != nil {
		t.Fatalf("failed to normalize: %v", err)
	}

	if !id.HasRole("grafana-stg-users") {
		t.Errorf("expected role grafana-stg-users, got: %v", id.Roles)
	}
	if id.HasRole("us-east-1_DNMvWNMWv_GoogleSAML") {
		t.Errorf("expected IdP-association pseudo-group to be filtered out, got: %v", id.Roles)
	}
}

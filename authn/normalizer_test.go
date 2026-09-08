package authn

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

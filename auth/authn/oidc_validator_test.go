package authn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestOIDCValidator_WithMockOIDCServer(t *testing.T) {
	ctx := context.Background()

	// 1. Generate RSA key pair for the mock OIDC provider
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	kid := "test-key-id-1"
	nStr := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
	eStr := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes())

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 server.URL,
				"jwks_uri":               server.URL + "/jwks.json",
				"response_types_supported": []string{"code", "token", "id_token"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})

		case "/jwks.json":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]any{
					{
						"kty": "RSA",
						"alg": "RS256",
						"use": "sig",
						"kid": kid,
						"n":   nStr,
						"e":   eStr,
					},
				},
			})

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// 2. Initialize OIDCValidator pointing to the mock discovery server
	validator, err := NewOIDCValidator(ctx, OIDCValidatorConfig{
		IssuerURL:         server.URL,
		SkipClientIDCheck: true,
		Normalizer:         NewStandardOIDCNormalizer(),
	})
	if err != nil {
		t.Fatalf("failed to initialize OIDCValidator: %v", err)
	}

	// 3. Issue a signed JWT token
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   server.URL,
		"sub":   "user-cognito-888",
		"aud":   "my-api-client",
		"iat":   now.Unix(),
		"exp":   now.Add(1 * time.Hour).Unix(),
		"scope": "read:data write:data",
		"roles": []string{"developer"},
	})
	token.Header["kid"] = kid

	tokenStr, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	// 4. Validate token using coreos/go-oidc/v3
	id, err := validator.ValidateToken(ctx, tokenStr)
	if err != nil {
		t.Fatalf("expected token validation to succeed with go-oidc, got error: %v", err)
	}

	if id.Subject != "user-cognito-888" {
		t.Errorf("expected subject 'user-cognito-888', got '%s'", id.Subject)
	}

	if !id.HasScope("read:data") {
		t.Errorf("expected scope 'read:data'")
	}

	if !id.HasRole("developer") {
		t.Errorf("expected role 'developer'")
	}
}

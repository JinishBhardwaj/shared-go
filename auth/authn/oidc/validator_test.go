package oidc

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

	"github.com/JinishBhardwaj/shared-go/auth/authn/mapping"
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
				"issuer":                                server.URL,
				"jwks_uri":                              server.URL + "/jwks.json",
				"response_types_supported":              []string{"code", "token", "id_token"},
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
		Normalizer:        mapping.NewStandardOIDCNormalizer(),
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

// newMockOIDCServer spins up a minimal OIDC discovery + JWKS server backed
// by a freshly generated RSA key pair, for tests that need a real
// oidc.Provider/oidc.IDTokenVerifier rather than a bare KeyFunc.
func newMockOIDCServer(t *testing.T) (server *httptest.Server, privateKey *rsa.PrivateKey, kid string) {
	t.Helper()

	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	kid = "test-key-id-1"
	nStr := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
	eStr := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes())

	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                server.URL,
				"jwks_uri":                              server.URL + "/jwks.json",
				"response_types_supported":              []string{"code", "token", "id_token"},
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
	t.Cleanup(server.Close)
	return server, privateKey, kid
}

func signMockOIDCToken(t *testing.T, privateKey *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	s, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return s
}

// TestOIDCValidator_AllowedAudiences is the Tier 0 #4 regression test
// (gap-analysis-final.md: "WithCognito hardcodes SkipClientIDCheck: true --
// audience validation off for every Cognito consumer"). AllowedAudiences
// lets a caller accept one of several app-client audiences, but a token
// whose aud matches none of them must still be rejected -- audience
// enforcement must be a real, active check, not silently disabled.
func TestOIDCValidator_AllowedAudiences(t *testing.T) {
	ctx := context.Background()
	server, privateKey, kid := newMockOIDCServer(t)

	validator, err := NewOIDCValidator(ctx, OIDCValidatorConfig{
		IssuerURL:        server.URL,
		AllowedAudiences: []string{"app-client-a", "app-client-b"},
		Normalizer:       mapping.NewStandardOIDCNormalizer(),
	})
	if err != nil {
		t.Fatalf("failed to initialize OIDCValidator: %v", err)
	}

	now := time.Now()
	baseClaims := func(aud string) jwt.MapClaims {
		return jwt.MapClaims{
			"iss": server.URL,
			"sub": "user-1",
			"aud": aud,
			"iat": now.Unix(),
			"exp": now.Add(1 * time.Hour).Unix(),
		}
	}

	t.Run("audience in AllowedAudiences -> accepted", func(t *testing.T) {
		tok := signMockOIDCToken(t, privateKey, kid, baseClaims("app-client-b"))
		if _, err := validator.ValidateToken(ctx, tok); err != nil {
			t.Errorf("expected token with an allowed audience to validate, got: %v", err)
		}
	})

	t.Run("audience NOT in AllowedAudiences -> rejected", func(t *testing.T) {
		tok := signMockOIDCToken(t, privateKey, kid, baseClaims("some-other-client"))
		if _, err := validator.ValidateToken(ctx, tok); err == nil {
			t.Errorf("expected token with an unlisted audience to be rejected, but it validated")
		}
	})
}

// TestOIDCValidator_NoAudienceConfigured_StillWorks documents the
// deliberate opt-out path: when a caller configures neither
// ExpectedClientID nor AllowedAudiences, the validator still has to work
// (matching the underlying go-oidc library's own requirement that
// SkipClientIDCheck must be true when ClientID is empty) -- but this is
// the ONLY case that may skip audience enforcement, and it happens because
// no restriction was configured at all, never as a hidden default bundled
// into a specific provider helper (that was Tier 0 #4's actual defect).
func TestOIDCValidator_NoAudienceConfigured_StillWorks(t *testing.T) {
	ctx := context.Background()
	server, privateKey, kid := newMockOIDCServer(t)

	validator, err := NewOIDCValidator(ctx, OIDCValidatorConfig{
		IssuerURL:  server.URL,
		Normalizer: mapping.NewStandardOIDCNormalizer(),
	})
	if err != nil {
		t.Fatalf("failed to initialize OIDCValidator: %v", err)
	}

	now := time.Now()
	tok := signMockOIDCToken(t, privateKey, kid, jwt.MapClaims{
		"iss": server.URL,
		"sub": "user-1",
		"aud": "anything",
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
	})
	if _, err := validator.ValidateToken(ctx, tok); err != nil {
		t.Errorf("expected validation to still succeed with no audience restriction configured, got: %v", err)
	}
}

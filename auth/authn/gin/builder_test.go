package gin

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

	"github.com/JinishBhardwaj/shared-go/auth/principal"
	ginprincipal "github.com/JinishBhardwaj/shared-go/auth/principal/gin"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type mockValidator struct {
	principal *principal.Principal
}

func (m *mockValidator) ValidateToken(ctx context.Context, tokenStr string) (*principal.Principal, error) {
	return m.principal, nil
}

type testClaimsTransformer struct{}

func (t *testClaimsTransformer) Transform(ctx context.Context, p *principal.Principal) (*principal.Principal, error) {
	if p.Metadata == nil {
		p.Metadata = make(map[string]any)
	}
	p.Metadata["transformed"] = true
	return p, nil
}

func TestAuthenticationBuilder(t *testing.T) {
	gin.SetMode(gin.TestMode)

	val := &mockValidator{
		principal: &principal.Principal{
			Subject:  "user_123",
			Method:   principal.AuthMethodAuthCodePKCE,
			Roles:    []string{"admin"},
			Metadata: make(map[string]any),
		},
	}

	middleware, err := NewBuilder().
		WithBearerValidator(val).
		WithClaimsTransformation(&testClaimsTransformer{}).
		BuildMiddleware()

	if err != nil {
		t.Fatalf("unexpected error building middleware: %v", err)
	}

	r := gin.New()
	r.Use(middleware)
	r.GET("/test", func(c *gin.Context) {
		p, exists := ginprincipal.GetPrincipal(c)
		if !exists {
			c.String(http.StatusUnauthorized, "no principal")
			return
		}
		if p.Metadata["transformed"] != true {
			c.String(http.StatusInternalServerError, "not transformed")
			return
		}
		c.String(http.StatusOK, p.Subject)
	})

	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer dummy-token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != "user_123" {
		t.Errorf("expected subject user_123, got %s", w.Body.String())
	}
}

// mockOIDCServer spins up a minimal OIDC discovery + JWKS server for tests
// that need WithCognito to perform real (not KeyFunc-stubbed) OIDC
// discovery/verification.
func mockOIDCServer(t *testing.T) (server *httptest.Server, privateKey *rsa.PrivateKey, kid string) {
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
					{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid, "n": nStr, "e": eStr},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server, privateKey, kid
}

// TestWithCognito_NoLongerHardcodesSkipClientIDCheck is the Tier 0 #4
// regression test (gap-analysis-final.md: "WithCognito hardcodes
// SkipClientIDCheck: true -- audience validation off for every Cognito
// consumer"). A validator built via WithCognito with an explicit
// AllowedAudiences list must actually reject a token whose audience is not
// in that list -- under the old hardcoded-true behavior this token would
// have been silently accepted.
func TestWithCognito_NoLongerHardcodesSkipClientIDCheck(t *testing.T) {
	ctx := context.Background()
	server, privateKey, kid := mockOIDCServer(t)

	b := NewBuilder().WithCognito(ctx, CognitoOptions{
		IssuerURL:        server.URL,
		AllowedAudiences: []string{"expected-app-client"},
	})
	auth, err := b.Build()
	if err != nil {
		t.Fatalf("unexpected error building authenticator: %v", err)
	}

	signToken := func(aud string) string {
		now := time.Now()
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": server.URL,
			"sub": "cognito-user-1",
			"aud": aud,
			"iat": now.Unix(),
			"exp": now.Add(time.Hour).Unix(),
		})
		token.Header["kid"] = kid
		s, err := token.SignedString(privateKey)
		if err != nil {
			t.Fatalf("failed signing token: %v", err)
		}
		return s
	}

	r := gin.New()
	r.Use(New(auth))
	r.GET("/me", func(c *gin.Context) {
		p, exists := ginprincipal.GetPrincipal(c)
		if !exists {
			c.String(http.StatusUnauthorized, "no principal")
			return
		}
		c.String(http.StatusOK, p.Subject)
	})

	t.Run("token with an unlisted audience is rejected", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/me", nil)
		req.Header.Set("Authorization", "Bearer "+signToken("some-other-app-client"))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 for a token with an unlisted audience, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("token with the allowed audience is accepted", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/me", nil)
		req.Header.Set("Authorization", "Bearer "+signToken("expected-app-client"))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected 200 for a token with the allowed audience, got %d: %s", w.Code, w.Body.String())
		}
	})
}

// TestWithCognito_SingleClientID_StillEnforced covers the other half of
// Tier 0 #4: a single ClientID (not AllowedAudiences) must also be
// enforced. Under the old hardcoded SkipClientIDCheck: true, a caller who
// set ClientID still got no audience enforcement at all -- this is the
// original, most direct manifestation of the defect (go-oidc's own
// ClientID-based check was disabled regardless of what the caller
// configured).
func TestWithCognito_SingleClientID_StillEnforced(t *testing.T) {
	ctx := context.Background()
	server, privateKey, kid := mockOIDCServer(t)

	b := NewBuilder().WithCognito(ctx, CognitoOptions{
		IssuerURL: server.URL,
		ClientID:  "the-expected-client",
	})
	auth, err := b.Build()
	if err != nil {
		t.Fatalf("unexpected error building authenticator: %v", err)
	}

	signToken := func(aud string) string {
		now := time.Now()
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": server.URL,
			"sub": "cognito-user-1",
			"aud": aud,
			"iat": now.Unix(),
			"exp": now.Add(time.Hour).Unix(),
		})
		token.Header["kid"] = kid
		s, err := token.SignedString(privateKey)
		if err != nil {
			t.Fatalf("failed signing token: %v", err)
		}
		return s
	}

	r := gin.New()
	r.Use(New(auth))
	r.GET("/me", func(c *gin.Context) {
		p, exists := ginprincipal.GetPrincipal(c)
		if !exists {
			c.String(http.StatusUnauthorized, "no principal")
			return
		}
		c.String(http.StatusOK, p.Subject)
	})

	t.Run("token with a mismatched single ClientID audience is rejected", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/me", nil)
		req.Header.Set("Authorization", "Bearer "+signToken("some-other-client"))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 for a token whose audience doesn't match ClientID, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("token matching the configured ClientID is accepted", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/me", nil)
		req.Header.Set("Authorization", "Bearer "+signToken("the-expected-client"))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected 200 for a token matching ClientID, got %d: %s", w.Code, w.Body.String())
		}
	})
}

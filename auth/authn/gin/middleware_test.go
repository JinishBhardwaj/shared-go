package gin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JinishBhardwaj/shared-go/auth/authn"
	"github.com/JinishBhardwaj/shared-go/auth/authtest"
	"github.com/JinishBhardwaj/shared-go/auth/principal"
	ginprincipal "github.com/JinishBhardwaj/shared-go/auth/principal/gin"
	"github.com/gin-gonic/gin"
)

func setupTestRouter(t *testing.T) (*gin.Engine, *authtest.MockOAuthProvider, *authn.MemoryAPIKeyStore, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	provider, err := authtest.NewMockOAuthProvider("https://auth.example.com", "https://api.example.com")
	if err != nil {
		t.Fatalf("failed creating oauth provider: %v", err)
	}

	keyStore := authn.NewMemoryAPIKeyStore()
	sampleAPIKey, _, err := keyStore.CreateKey("dev_owner_1", "dev-cli", "Developer Key", []string{"read:reports"}, []string{"admin"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("failed creating api key: %v", err)
	}

	jwtVal, err := authn.NewJWTValidator(authn.JWTValidatorConfig{
		KeyFunc:          provider.KeyFunc(),
		ExpectedIssuer:   "https://auth.example.com",
		ExpectedAudience: "https://api.example.com",
	})
	if err != nil {
		t.Fatalf("failed creating jwt validator: %v", err)
	}

	apiKeyVal, err := authn.NewAPIKeyValidator(keyStore)
	if err != nil {
		t.Fatalf("failed creating apikey validator: %v", err)
	}

	composite := NewCompositeAuthenticator(CompositeAuthenticatorConfig{
		ExtractorConfig: DefaultExtractorConfig(),
		JWTValidator:    jwtVal,
		APIKeyValidator: apiKeyVal,
	})

	r := gin.New()
	r.Use(gin.Recovery())

	// Protected group
	api := r.Group("/api")
	api.Use(New(composite))
	{
		api.GET("/me", func(c *gin.Context) {
			id := ginprincipal.MustUser(c)
			c.JSON(http.StatusOK, gin.H{
				"subject":   id.Subject,
				"client_id": id.ClientID,
				"method":    id.Method,
				"scopes":    id.Scopes,
			})
		})
		// Scope/role/method route guards (RequireUser, RequireM2M, RequireScope,
		// RequireRole, ...) moved to auth/authz/gin (gap-analysis-final.md §3.8
		// step 6); their behavior is exercised there, not here. This package's
		// own concern -- that authentication correctly derives Subject/Method/
		// Scopes per OAuth flow -- is covered by the /me assertions below.
	}

	return r, provider, keyStore, sampleAPIKey
}

func TestMiddleware_Unauthenticated(t *testing.T) {
	r, _, _, _ := setupTestRouter(t)

	req, _ := http.NewRequest(http.MethodGet, "/api/me", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", w.Code)
	}
	if authHdr := w.Header().Get("WWW-Authenticate"); authHdr == "" {
		t.Error("expected WWW-Authenticate header, got empty")
	}
}

func TestMiddleware_ConflictingCredentials(t *testing.T) {
	r, _, _, apiKey := setupTestRouter(t)

	req, _ := http.NewRequest(http.MethodGet, "/api/me", nil)
	req.Header.Set("Authorization", "Bearer fake-token")
	req.Header.Set("X-API-Key", apiKey)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", w.Code)
	}
}

func TestMiddleware_OAuthFlows(t *testing.T) {
	r, provider, _, _ := setupTestRouter(t)

	// 1. Test AuthCode + PKCE Flow
	t.Run("AuthCode+PKCE Token", func(t *testing.T) {
		verifier, challenge, err := authtest.GeneratePKCEVerifierAndChallenge()
		if err != nil {
			t.Fatalf("failed generating pkce verifier: %v", err)
		}
		code, err := provider.AuthorizePKCE("spa-client", "user-pkce-456", challenge, "S256", []string{"read:reports", "user:profile"})
		if err != nil {
			t.Fatalf("failed to authorize pkce: %v", err)
		}
		token, err := provider.ExchangeAuthCode("spa-client", code, verifier)
		if err != nil {
			t.Fatalf("failed to exchange auth code: %v", err)
		}

		req, _ := http.NewRequest(http.MethodGet, "/api/me", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d. Body: %s", w.Code, w.Body.String())
		}

		var resp map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["method"] != string(principal.AuthMethodAuthCodePKCE) {
			t.Errorf("expected method %s, got %v", principal.AuthMethodAuthCodePKCE, resp["method"])
		}
		if resp["subject"] != "user-pkce-456" {
			t.Errorf("expected subject user-pkce-456, got %v", resp["subject"])
		}
	})

	// 2. Test Client Credentials Flow
	t.Run("Client Credentials Token", func(t *testing.T) {
		provider.RegisterClient("service-daemon", "daemon-secret")
		token, err := provider.IssueClientCredentialsToken("service-daemon", "daemon-secret", []string{"sync:data"})
		if err != nil {
			t.Fatalf("failed to issue client credentials token: %v", err)
		}

		req, _ := http.NewRequest(http.MethodGet, "/api/me", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d. Body: %s", w.Code, w.Body.String())
		}

		var resp map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["method"] != string(principal.AuthMethodClientCredentials) {
			t.Errorf("expected method %s, got %v", principal.AuthMethodClientCredentials, resp["method"])
		}
	})

	// 3. Test Device Authorization Flow
	t.Run("Device Flow Token", func(t *testing.T) {
		deviceResp, err := provider.RequestDeviceCode("cli-tool", []string{"read:reports"})
		if err != nil {
			t.Fatalf("failed requesting device code: %v", err)
		}

		// Polling before approval returns pending
		_, err = provider.PollDeviceToken("cli-tool", deviceResp.DeviceCode)
		if err != authtest.ErrDeviceAuthPending {
			t.Errorf("expected ErrDeviceAuthPending, got %v", err)
		}

		// User approves device code
		if err := provider.ApproveDeviceCode(deviceResp.UserCode, "device-user-777"); err != nil {
			t.Fatalf("failed approving device code: %v", err)
		}

		// Polling after approval returns token
		token, err := provider.PollDeviceToken("cli-tool", deviceResp.DeviceCode)
		if err != nil {
			t.Fatalf("failed polling device token: %v", err)
		}

		req, _ := http.NewRequest(http.MethodGet, "/api/me", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d. Body: %s", w.Code, w.Body.String())
		}

		var resp map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["method"] != string(principal.AuthMethodDeviceFlow) {
			t.Errorf("expected method %s, got %v", principal.AuthMethodDeviceFlow, resp["method"])
		}
	})
}

func TestMiddleware_APIKeyFlow(t *testing.T) {
	r, _, _, sampleKey := setupTestRouter(t)

	// 1. Header X-API-Key
	t.Run("X-API-Key Header", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/api/me", nil)
		req.Header.Set("X-API-Key", sampleKey)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d. Body: %s", w.Code, w.Body.String())
		}

		var resp map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["method"] != string(principal.AuthMethodAPIKey) {
			t.Errorf("expected method %s, got %v", principal.AuthMethodAPIKey, resp["method"])
		}
	})

	// 2. Header Authorization: ApiKey <key>
	t.Run("Authorization ApiKey Header", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/api/me", nil)
		req.Header.Set("Authorization", "ApiKey "+sampleKey)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d. Body: %s", w.Code, w.Body.String())
		}
	})
}

func TestMiddleware_ClaimsTransformer(t *testing.T) {
	keyStore := authn.NewMemoryAPIKeyStore()
	sampleKey, _, err := keyStore.CreateKey("owner-1", "client-1", "TestKey", []string{"read"}, []string{"user"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	apiKeyVal, _ := authn.NewAPIKeyValidator(keyStore)
	composite := NewCompositeAuthenticator(CompositeAuthenticatorConfig{
		APIKeyValidator: apiKeyVal,
	})

	// Transformer that simulates enriching user with DB tenant_id and local_user_id
	transformer := principal.ClaimsTransformerFunc(func(ctx context.Context, p *principal.Principal) (*principal.Principal, error) {
		p.Metadata["tenant_id"] = "ten_enterprise_99"
		p.Metadata["local_user_id"] = "usr_db_123"
		return p, nil
	})

	r := gin.New()
	r.Use(New(composite, WithClaimsTransformer(transformer)))
	r.GET("/profile", func(c *gin.Context) {
		user := ginprincipal.User(c) // Mirrors HttpContext.User
		if user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "nil user"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"subject":       user.Subject,
			"tenant_id":     user.Metadata["tenant_id"],
			"local_user_id": user.Metadata["local_user_id"],
		})
	})

	req, _ := http.NewRequest(http.MethodGet, "/profile", nil)
	req.Header.Set("X-API-Key", sampleKey)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}
}


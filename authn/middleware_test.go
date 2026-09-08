package authn

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JinishBhardwaj/shared-go/authn/oauthprovider"
	"github.com/gin-gonic/gin"
)

func setupTestRouter(t *testing.T) (*gin.Engine, *oauthprovider.MockOAuthProvider, *MemoryAPIKeyStore, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	provider, err := oauthprovider.NewMockOAuthProvider("https://auth.example.com", "https://api.example.com")
	if err != nil {
		t.Fatalf("failed creating oauth provider: %v", err)
	}

	keyStore := NewMemoryAPIKeyStore()
	sampleAPIKey, _, err := keyStore.CreateKey("dev_owner_1", "dev-cli", "Developer Key", []string{"read:reports"}, []string{"admin"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("failed creating api key: %v", err)
	}

	jwtVal, err := NewJWTValidator(JWTValidatorConfig{
		KeyFunc:          provider.KeyFunc(),
		ExpectedIssuer:   "https://auth.example.com",
		ExpectedAudience: "https://api.example.com",
	})
	if err != nil {
		t.Fatalf("failed creating jwt validator: %v", err)
	}

	apiKeyVal, err := NewAPIKeyValidator(keyStore)
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
			id := MustUser(c)
			c.JSON(http.StatusOK, gin.H{
				"subject":   id.Subject,
				"client_id": id.ClientID,
				"method":    id.Method,
				"scopes":    id.Scopes,
			})
		})

		api.GET("/user-only", RequireUser(), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"access": "granted"})
		})

		api.GET("/m2m-only", RequireM2M(), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"access": "granted"})
		})

		api.GET("/reports", RequireScope("read:reports"), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"reports": []string{"rep1"}})
		})

		api.GET("/admin", RequireRole("admin"), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"admin": true})
		})
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
		verifier, challenge, err := oauthprovider.GeneratePKCEVerifierAndChallenge()
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
		if resp["method"] != string(AuthMethodAuthCodePKCE) {
			t.Errorf("expected method %s, got %v", AuthMethodAuthCodePKCE, resp["method"])
		}
		if resp["subject"] != "user-pkce-456" {
			t.Errorf("expected subject user-pkce-456, got %v", resp["subject"])
		}

		// Verify RequireUser succeeds
		reqUser, _ := http.NewRequest(http.MethodGet, "/api/user-only", nil)
		reqUser.Header.Set("Authorization", "Bearer "+token)
		wUser := httptest.NewRecorder()
		r.ServeHTTP(wUser, reqUser)
		if wUser.Code != http.StatusOK {
			t.Errorf("expected 200 for user-only with PKCE token, got %d", wUser.Code)
		}

		// Verify RequireM2M is blocked
		reqM2M, _ := http.NewRequest(http.MethodGet, "/api/m2m-only", nil)
		reqM2M.Header.Set("Authorization", "Bearer "+token)
		wM2M := httptest.NewRecorder()
		r.ServeHTTP(wM2M, reqM2M)
		if wM2M.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for m2m-only with PKCE token, got %d", wM2M.Code)
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
		if resp["method"] != string(AuthMethodClientCredentials) {
			t.Errorf("expected method %s, got %v", AuthMethodClientCredentials, resp["method"])
		}

		// Verify RequireM2M succeeds
		reqM2M, _ := http.NewRequest(http.MethodGet, "/api/m2m-only", nil)
		reqM2M.Header.Set("Authorization", "Bearer "+token)
		wM2M := httptest.NewRecorder()
		r.ServeHTTP(wM2M, reqM2M)
		if wM2M.Code != http.StatusOK {
			t.Errorf("expected 200 for m2m-only with client credentials token, got %d", wM2M.Code)
		}

		// Verify RequireUser is blocked
		reqUser, _ := http.NewRequest(http.MethodGet, "/api/user-only", nil)
		reqUser.Header.Set("Authorization", "Bearer "+token)
		wUser := httptest.NewRecorder()
		r.ServeHTTP(wUser, reqUser)
		if wUser.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for user-only with client credentials token, got %d", wUser.Code)
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
		if err != oauthprovider.ErrDeviceAuthPending {
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
		if resp["method"] != string(AuthMethodDeviceFlow) {
			t.Errorf("expected method %s, got %v", AuthMethodDeviceFlow, resp["method"])
		}

		// RequireUser should succeed because device flow represents an end user
		reqUser, _ := http.NewRequest(http.MethodGet, "/api/user-only", nil)
		reqUser.Header.Set("Authorization", "Bearer "+token)
		wUser := httptest.NewRecorder()
		r.ServeHTTP(wUser, reqUser)
		if wUser.Code != http.StatusOK {
			t.Errorf("expected 200 for user-only with device flow token, got %d", wUser.Code)
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
		if resp["method"] != string(AuthMethodAPIKey) {
			t.Errorf("expected method %s, got %v", AuthMethodAPIKey, resp["method"])
		}

		// RequireScope test
		reqRep, _ := http.NewRequest(http.MethodGet, "/api/reports", nil)
		reqRep.Header.Set("X-API-Key", sampleKey)
		wRep := httptest.NewRecorder()
		r.ServeHTTP(wRep, reqRep)
		if wRep.Code != http.StatusOK {
			t.Errorf("expected 200 OK for /api/reports, got %d", wRep.Code)
		}

		// RequireRole test
		reqAdmin, _ := http.NewRequest(http.MethodGet, "/api/admin", nil)
		reqAdmin.Header.Set("X-API-Key", sampleKey)
		wAdmin := httptest.NewRecorder()
		r.ServeHTTP(wAdmin, reqAdmin)
		if wAdmin.Code != http.StatusOK {
			t.Errorf("expected 200 OK for /api/admin, got %d", wAdmin.Code)
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
	keyStore := NewMemoryAPIKeyStore()
	sampleKey, _, err := keyStore.CreateKey("owner-1", "client-1", "TestKey", []string{"read"}, []string{"user"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	apiKeyVal, _ := NewAPIKeyValidator(keyStore)
	composite := NewCompositeAuthenticator(CompositeAuthenticatorConfig{
		APIKeyValidator: apiKeyVal,
	})

	// Transformer that simulates enriching user with DB tenant_id and local_user_id
	transformer := ClaimsTransformerFunc(func(ctx context.Context, p *Principal) (*Principal, error) {
		p.Metadata["tenant_id"] = "ten_enterprise_99"
		p.Metadata["local_user_id"] = "usr_db_123"
		return p, nil
	})

	r := gin.New()
	r.Use(New(composite, WithClaimsTransformer(transformer)))
	r.GET("/profile", func(c *gin.Context) {
		user := User(c) // Mirrors HttpContext.User
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


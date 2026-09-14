package gin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
	ginprincipal "github.com/JinishBhardwaj/shared-go/auth/principal/gin"
	"github.com/gin-gonic/gin"
)

// withPrincipal builds a minimal router that seeds the gin context with a
// fixed Principal (standing in for real authn middleware) ahead of a single
// guard-decorated route.
func withPrincipal(p *principal.Principal, guard gin.HandlerFunc) *gin.Engine {
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if p != nil {
			ginprincipal.Set(c, p)
		}
		c.Next()
	})
	r.GET("/protected", guard, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"access": "granted"})
	})
	return r
}

func doGet(t *testing.T, r *gin.Engine) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func TestRequireScope(t *testing.T) {
	granted := &principal.Principal{Subject: "u1", Scopes: []string{"read:reports", "write:orders"}}
	partial := &principal.Principal{Subject: "u2", Scopes: []string{"read:reports"}}

	// G8-5: authz never emits 401 -- a missing principal is a 403, same as
	// any other authorization failure (authn owns the 401 challenge).
	if code := doGet(t, withPrincipal(nil, Require(WithScopes("read:reports")))); code != http.StatusForbidden {
		t.Errorf("no principal: expected 403, got %d", code)
	}
	if code := doGet(t, withPrincipal(partial, Require(WithScopes("read:reports", "write:orders")))); code != http.StatusForbidden {
		t.Errorf("missing one of two required scopes: expected 403, got %d", code)
	}
	if code := doGet(t, withPrincipal(granted, Require(WithScopes("read:reports", "write:orders")))); code != http.StatusOK {
		t.Errorf("all scopes present: expected 200, got %d", code)
	}
}

func TestRequireAnyScope(t *testing.T) {
	partial := &principal.Principal{Subject: "u1", Scopes: []string{"read:reports"}}
	none := &principal.Principal{Subject: "u2", Scopes: []string{"delete:orders"}}

	if code := doGet(t, withPrincipal(partial, Require(WithAnyScope("read:reports", "write:orders")))); code != http.StatusOK {
		t.Errorf("one of the candidate scopes present: expected 200, got %d", code)
	}
	if code := doGet(t, withPrincipal(none, Require(WithAnyScope("read:reports", "write:orders")))); code != http.StatusForbidden {
		t.Errorf("no candidate scope present: expected 403, got %d", code)
	}

	// Tier 0 #6: an empty candidate list must fail closed, never allow everyone.
	if code := doGet(t, withPrincipal(none, Require(WithAnyScope()))); code != http.StatusForbidden {
		t.Errorf("empty candidate list must fail closed: expected 403, got %d", code)
	}
}

func TestRequireRole(t *testing.T) {
	admin := &principal.Principal{Subject: "u1", Roles: []string{"admin", "viewer"}}
	viewer := &principal.Principal{Subject: "u2", Roles: []string{"viewer"}}

	if code := doGet(t, withPrincipal(viewer, Require(WithRoles("admin")))); code != http.StatusForbidden {
		t.Errorf("missing required role: expected 403, got %d", code)
	}
	if code := doGet(t, withPrincipal(admin, Require(WithRoles("admin")))); code != http.StatusOK {
		t.Errorf("has required role: expected 200, got %d", code)
	}
}

func TestRequireAnyRole(t *testing.T) {
	viewer := &principal.Principal{Subject: "u1", Roles: []string{"viewer"}}
	none := &principal.Principal{Subject: "u2", Roles: []string{"guest"}}

	if code := doGet(t, withPrincipal(viewer, Require(WithAnyRole("admin", "viewer")))); code != http.StatusOK {
		t.Errorf("one of the candidate roles present: expected 200, got %d", code)
	}
	if code := doGet(t, withPrincipal(none, Require(WithAnyRole("admin", "viewer")))); code != http.StatusForbidden {
		t.Errorf("no candidate role present: expected 403, got %d", code)
	}

	// Tier 0 #6: an empty candidate list must fail closed, never allow everyone.
	if code := doGet(t, withPrincipal(none, Require(WithAnyRole()))); code != http.StatusForbidden {
		t.Errorf("empty candidate list must fail closed: expected 403, got %d", code)
	}
}

func TestRequireMethod_RequireUser_RequireM2M(t *testing.T) {
	pkce := &principal.Principal{Subject: "u1", Method: principal.AuthMethodAuthCodePKCE}
	device := &principal.Principal{Subject: "u2", Method: principal.AuthMethodDeviceFlow}
	clientCreds := &principal.Principal{Subject: "svc1", Method: principal.AuthMethodClientCredentials}
	apiKey := &principal.Principal{Subject: "svc2", Method: principal.AuthMethodAPIKey}

	if code := doGet(t, withPrincipal(pkce, Require(WithUserPresent()))); code != http.StatusOK {
		t.Errorf("RequireUser with AuthCode+PKCE: expected 200, got %d", code)
	}
	if code := doGet(t, withPrincipal(device, Require(WithUserPresent()))); code != http.StatusOK {
		t.Errorf("RequireUser with device flow: expected 200, got %d", code)
	}
	if code := doGet(t, withPrincipal(clientCreds, Require(WithUserPresent()))); code != http.StatusForbidden {
		t.Errorf("RequireUser with client credentials: expected 403, got %d", code)
	}

	if code := doGet(t, withPrincipal(clientCreds, Require(WithM2M()))); code != http.StatusOK {
		t.Errorf("RequireM2M with client credentials: expected 200, got %d", code)
	}
	if code := doGet(t, withPrincipal(apiKey, Require(WithM2M()))); code != http.StatusOK {
		t.Errorf("RequireM2M with API key: expected 200, got %d", code)
	}
	if code := doGet(t, withPrincipal(pkce, Require(WithM2M()))); code != http.StatusForbidden {
		t.Errorf("RequireM2M with AuthCode+PKCE: expected 403, got %d", code)
	}
}

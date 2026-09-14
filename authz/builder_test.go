package authz

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/JinishBhardwaj/shared-go/authn"
)

func TestAuthorizationBuilder(t *testing.T) {
	gin.SetMode(gin.TestMode)

	middleware, err := NewBuilder().
		AddPolicy("AdminOnly", NewPolicyBuilder().RequireRole("admin").Build()).
		WithMemoryPARC(30 * time.Second).
		BuildMiddleware()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r := gin.New()
	r.Use(func(c *gin.Context) {
		// Mock authn principal
		p := &authn.Principal{
			Subject: "user_admin",
			Roles:   []string{"admin"},
		}
		c.Set(authn.DefaultContextKeyPrincipal, p)
		c.Next()
	})
	r.Use(middleware)

	r.GET("/admin", Authorize("AdminOnly"), func(c *gin.Context) {
		c.String(http.StatusOK, "admin granted")
	})

	req, _ := http.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != "admin granted" {
		t.Errorf("unexpected body: %s", w.Body.String())
	}
}

func TestAuthorizationBuilderForbidden(t *testing.T) {
	gin.SetMode(gin.TestMode)

	middleware, err := NewBuilder().
		AddPolicy("AdminOnly", NewPolicyBuilder().RequireRole("admin").Build()).
		BuildMiddleware()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r := gin.New()
	r.Use(func(c *gin.Context) {
		p := &authn.Principal{
			Subject: "user_regular",
			Roles:   []string{"user"},
		}
		c.Set(authn.DefaultContextKeyPrincipal, p)
		c.Next()
	})
	r.Use(middleware)

	r.GET("/admin", Authorize("AdminOnly"), func(c *gin.Context) {
		c.String(http.StatusOK, "admin granted")
	})

	req, _ := http.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", w.Code)
	}
}

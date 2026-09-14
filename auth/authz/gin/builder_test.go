package gin

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JinishBhardwaj/shared-go/auth/authz"
	"github.com/JinishBhardwaj/shared-go/auth/principal"
	ginprincipal "github.com/JinishBhardwaj/shared-go/auth/principal/gin"
	"github.com/gin-gonic/gin"
)

func TestAuthorizationBuilder(t *testing.T) {
	gin.SetMode(gin.TestMode)

	middleware, err := NewBuilder().
		AddPolicy("AdminOnly", authz.NewPolicyBuilder().RequireRole("admin").Build()).
		WithMemoryPARC(30 * time.Second).
		BuildMiddleware()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r := gin.New()
	r.Use(func(c *gin.Context) {
		// Mock authn principal
		p := &principal.Principal{
			Subject: "user_admin",
			Roles:   []string{"admin"},
		}
		ginprincipal.Set(c, p)
		c.Next()
	})
	r.Use(middleware)

	r.GET("/admin", Require(WithPolicyName("AdminOnly")), func(c *gin.Context) {
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
		AddPolicy("AdminOnly", authz.NewPolicyBuilder().RequireRole("admin").Build()).
		BuildMiddleware()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r := gin.New()
	r.Use(func(c *gin.Context) {
		p := &principal.Principal{
			Subject: "user_regular",
			Roles:   []string{"user"},
		}
		ginprincipal.Set(c, p)
		c.Next()
	})
	r.Use(middleware)

	r.GET("/admin", Require(WithPolicyName("AdminOnly")), func(c *gin.Context) {
		c.String(http.StatusOK, "admin granted")
	})

	req, _ := http.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", w.Code)
	}
}

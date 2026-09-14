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

	builder := NewBuilder().
		AddPolicy("AdminOnly", authz.NewPolicyBuilder().RequireRole("admin").Build()).
		WithMemoryPARC(30 * time.Second)

	engine, err := builder.Build()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	middleware := UseAuthorization(engine, builder.middlewareOptions...)

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

	// WithEngine(...) is now mandatory for the WithPolicyName mode
	// (gap-analysis-final.md Tier 1 line 100, authz half -- "fail at wire
	// time, not request time"): Require(...) panics at construction time if
	// omitted, so this test's engine is supplied explicitly rather than
	// relying on the middleware's context registration.
	r.GET("/admin", Require(WithEngine(engine), WithPolicyName("AdminOnly")), func(c *gin.Context) {
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

	builder := NewBuilder().
		AddPolicy("AdminOnly", authz.NewPolicyBuilder().RequireRole("admin").Build())

	engine, err := builder.Build()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	middleware := UseAuthorization(engine, builder.middlewareOptions...)

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

	// WithEngine(...) is now mandatory for the WithPolicyName mode -- see
	// the identical note in TestAuthorizationBuilder above.
	r.GET("/admin", Require(WithEngine(engine), WithPolicyName("AdminOnly")), func(c *gin.Context) {
		c.String(http.StatusOK, "admin granted")
	})

	req, _ := http.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", w.Code)
	}
}

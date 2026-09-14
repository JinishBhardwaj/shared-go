package authz

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JinishBhardwaj/shared-go/authn"
	"github.com/gin-gonic/gin"
)

func setupMiddlewareTestRouter(t *testing.T) (*gin.Engine, *PolicyEngine) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	engine := NewPolicyEngine()
	engine.RegisterPolicy(NewPolicy("AdminPolicy").RequireRole("admin").Build())
	engine.RegisterPolicy(NewPolicy("UserPolicy").RequireUser().Build())

	r := gin.New()
	r.Use(gin.Recovery())

	// Fake authn middleware injecting user
	r.Use(func(c *gin.Context) {
		roleHeader := c.GetHeader("X-Role")
		userHeader := c.GetHeader("X-User")
		if userHeader != "" {
			c.Set(authn.DefaultContextKeyPrincipal, &authn.Principal{
				Subject: userHeader,
				Method:  authn.AuthMethodAuthCodePKCE,
				Roles:   []string{roleHeader},
			})
		}
		c.Next()
	})

	return r, engine
}

func TestUseAuthorizationMiddleware(t *testing.T) {
	r, engine := setupMiddlewareTestRouter(t)

	// Attach UseAuthorization pipeline middleware
	r.Use(UseAuthorization(engine,
		WithFallbackPolicy(NewPolicy("Fallback").RequireUser().Build()),
	))

	// Routes
	r.GET("/public", AllowAnonymous(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "public"})
	})

	r.GET("/profile", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "profile"})
	})

	r.GET("/admin", Authorize("AdminPolicy"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "admin"})
	})

	t.Run("AllowAnonymous succeeds without auth", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/public", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w.Code)
		}
	})

	t.Run("FallbackPolicy blocks unauthenticated request to /profile", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/profile", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", w.Code)
		}
	})

	t.Run("FallbackPolicy allows authenticated request to /profile", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/profile", nil)
		req.Header.Set("X-User", "user_123")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w.Code)
		}
	})

	t.Run("Authorize policy blocks user lacking admin role", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/admin", nil)
		req.Header.Set("X-User", "user_123")
		req.Header.Set("X-Role", "viewer")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden, got %d", w.Code)
		}
	})

	t.Run("Authorize policy allows admin user", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/admin", nil)
		req.Header.Set("X-User", "admin_999")
		req.Header.Set("X-Role", "admin")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w.Code)
		}
	})
}

func TestImperativeAuthorizeResource(t *testing.T) {
	r, engine := setupMiddlewareTestRouter(t)
	r.Use(UseAuthorization(engine))

	engine.RegisterPolicy(NewPolicy("EditPolicy").RequireRole("editor").Build())

	r.POST("/items/:id", func(c *gin.Context) {
		result := AuthorizeResource(c, Resource{Type: "item", ID: c.Param("id")}, "EditPolicy")
		if !result.Succeeded {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": result.FailureReason})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "updated"})
	})

	t.Run("Fails when lacking editor role", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, "/items/123", nil)
		req.Header.Set("X-User", "user_1")
		req.Header.Set("X-Role", "viewer")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})

	t.Run("Succeeds when possessing editor role", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, "/items/123", nil)
		req.Header.Set("X-User", "user_1")
		req.Header.Set("X-Role", "editor")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})
}

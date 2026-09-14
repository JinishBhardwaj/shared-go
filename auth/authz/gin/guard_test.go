package gin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JinishBhardwaj/shared-go/auth/authz"
	"github.com/JinishBhardwaj/shared-go/auth/principal"
	ginprincipal "github.com/JinishBhardwaj/shared-go/auth/principal/gin"
	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestGinGuard_RequirePolicyAndPARC(t *testing.T) {
	repo := authz.NewMemoryPermissionRepository()
	ctx := context.Background()

	_ = repo.GrantPermission(ctx, "john_doe", authz.PermissionRule{
		ActionPattern:     "read",
		ResourceType:      "report",
		ResourceIDPattern: "rep_public_*",
		Effect:            authz.EffectPermit,
	})

	parcHandler, _ := authz.NewPARCHandler(authz.PARCHandlerConfig{
		Repository: repo,
	})
	engine := authz.NewPolicyEngine(parcHandler)

	r := gin.New()

	// Simulate AuthN middleware attaching Principal
	r.Use(func(c *gin.Context) {
		caller := c.GetHeader("X-Test-User")
		if caller != "" {
			ginprincipal.Set(c, &principal.Principal{
				Subject: caller,
				Roles:   []string{"user"},
				Method:  principal.AuthMethodAuthCodePKCE,
			})
		}
		c.Next()
	})

	// Protected route using RequirePARC with route param extraction
	r.GET("/reports/:reportId",
		RequirePARC(engine, "read", "report", ExtractResourceFromParam("reportId", "report")),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok", "report": c.Param("reportId")})
		},
	)

	// 1. Unauthenticated request -> 401
	reqUnauth, _ := http.NewRequest("GET", "/reports/rep_public_1", nil)
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, reqUnauth)
	if w1.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w1.Code)
	}

	// 2. Authenticated user accessing allowed report -> 200 OK
	reqAllowed, _ := http.NewRequest("GET", "/reports/rep_public_1", nil)
	reqAllowed.Header.Set("X-Test-User", "john_doe")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, reqAllowed)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	// 3. Authenticated user accessing restricted report -> 403 Forbidden
	reqForbidden, _ := http.NewRequest("GET", "/reports/rep_classified_99", nil)
	reqForbidden.Header.Set("X-Test-User", "john_doe")
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, reqForbidden)
	if w3.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", w3.Code, w3.Body.String())
	}
}

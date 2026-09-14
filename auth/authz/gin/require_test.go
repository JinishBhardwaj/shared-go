package gin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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
		Require(WithEngine(engine), WithPARC("read", "report"), WithResource(ExtractResourceFromParam("reportId", "report"))),
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

// leakyPermissionRepository is a PermissionRepository stub whose
// GetPermissions always fails with an error carrying content that must
// never reach a caller: a fake DB credential-looking string, an embedded
// double-quote, and a CRLF sequence attempting header injection.
type leakyPermissionRepository struct{}

func (leakyPermissionRepository) GetPermissions(ctx context.Context, principalID string) (*authz.PrincipalPermissions, error) {
	return nil, errors.New(`pq: password authentication failed for user "svc_role" secret=hunter2` + "\r\nX-Injected: evil")
}
func (leakyPermissionRepository) GrantPermission(ctx context.Context, principalID string, rule authz.PermissionRule) error {
	return nil
}
func (leakyPermissionRepository) RevokeAll(ctx context.Context, principalID string) error {
	return nil
}

// TestRequirePARC_NeverLeaksRawInternalErrorText is the Tier 0 #7
// regression test for the guard.go RequirePARC call site
// (gap-analysis-final.md: "internal error text interpolated into the
// WWW-Authenticate header and body ... leaks DB/IdP messages; quotes or
// CRLF in an error break the quoted-string -> header injection"). A
// PermissionRepository failure surfaces through PARCHandler.Handle and
// PolicyEngine.Evaluate as a wrapped error whose text ends up in
// Decision.Reason -- that text must never reach the response header or
// body verbatim, and the header must never contain an embedded CRLF.
func TestRequirePARC_NeverLeaksRawInternalErrorText(t *testing.T) {
	parcHandler, err := authz.NewPARCHandler(authz.PARCHandlerConfig{
		Repository: leakyPermissionRepository{},
	})
	if err != nil {
		t.Fatalf("failed to create PARCHandler: %v", err)
	}
	engine := authz.NewPolicyEngine(parcHandler)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		ginprincipal.Set(c, &principal.Principal{Subject: "user_1", Method: principal.AuthMethodAuthCodePKCE})
		c.Next()
	})
	r.GET("/reports/:reportId",
		Require(WithEngine(engine), WithPARC("read", "report"), WithResource(ExtractResourceFromParam("reportId", "report"))),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		},
	)

	req, _ := http.NewRequest(http.MethodGet, "/reports/rep_1", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}

	hdr := w.Header().Get("WWW-Authenticate")
	body := w.Body.String()

	for _, leaked := range []string{"hunter2", "password authentication failed", "svc_role", "X-Injected"} {
		if strings.Contains(hdr, leaked) {
			t.Errorf("WWW-Authenticate header leaked internal error text %q: %s", leaked, hdr)
		}
		if strings.Contains(body, leaked) {
			t.Errorf("response body leaked internal error text %q: %s", leaked, body)
		}
	}

	if strings.Contains(hdr, "\r") || strings.Contains(hdr, "\n") {
		t.Errorf("WWW-Authenticate header contains an embedded CR/LF (header injection): %q", hdr)
	}
}

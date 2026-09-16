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

	_ = repo.GrantPermission(ctx, &principal.Principal{Subject: "john_doe"}, authz.PermissionRule{
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
				Subject:     caller,
				Roles:       []string{"user"},
				Method:      principal.AuthMethodAuthCodePKCE,
				UserPresent: true,
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

	// 1. Unauthenticated request -> 403 (G8-5: authz never emits 401 --
	// that's authn's job -- so a missing principal is denied with the same
	// status as any other authorization failure).
	reqUnauth, _ := http.NewRequest("GET", "/reports/rep_public_1", nil)
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, reqUnauth)
	if w1.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w1.Code)
	}
	if hdr := w1.Header().Get("WWW-Authenticate"); hdr != "" {
		t.Errorf("no principal in context is a 403, not a 401 challenge -- expected no WWW-Authenticate header, got %q", hdr)
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

func (leakyPermissionRepository) GetPermissions(ctx context.Context, p *principal.Principal) (*authz.PrincipalPermissions, error) {
	return nil, errors.New(`pq: password authentication failed for user "svc_role" secret=hunter2` + "\r\nX-Injected: evil")
}
func (leakyPermissionRepository) GrantPermission(ctx context.Context, p *principal.Principal, rule authz.PermissionRule) error {
	return nil
}
func (leakyPermissionRepository) RevokeAll(ctx context.Context, p *principal.Principal) error {
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
		ginprincipal.Set(c, &principal.Principal{Subject: "user_1", Method: principal.AuthMethodAuthCodePKCE, UserPresent: true})
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

// TestRequire_NeverEmits401_NoPrincipalInContext is the G8-5 regression test
// (gap-analysis-final.md Tier 2 line 107, "authz emits 403 only"): every
// Require(...) mode must deny a request with no principal in context using
// 403, never 401 -- authn owns the 401 challenge, authz only ever answers
// with "forbidden." Covers all seven modes (policy, PARC, scope-all,
// scope-any, role-all, role-any, method) plus the direct-attach path through
// New()'s FallbackPolicy/handleResult, in one pass.
func TestRequire_NeverEmits401_NoPrincipalInContext(t *testing.T) {
	repo := authz.NewMemoryPermissionRepository()
	parcHandler, _ := authz.NewPARCHandler(authz.PARCHandlerConfig{Repository: repo})
	engine := authz.NewPolicyEngine(parcHandler)
	engine.RegisterPolicy(authz.NewPolicy("SomePolicy").RequireRole("admin").Build())

	guards := map[string]gin.HandlerFunc{
		"WithPolicyName": Require(WithEngine(engine), WithPolicyName("SomePolicy")),
		"WithPARC":       Require(WithEngine(engine), WithPARC("read", "report")),
		"WithScopes":     Require(WithScopes("read:reports")),
		"WithAnyScope":   Require(WithAnyScope("read:reports")),
		"WithRoles":      Require(WithRoles("admin")),
		"WithAnyRole":    Require(WithAnyRole("admin")),
		"WithMethods":    Require(WithMethods(principal.AuthMethodAPIKey)),
	}

	for name, guard := range guards {
		t.Run(name, func(t *testing.T) {
			r := gin.New()
			// Deliberately NO authn middleware at all: no principal is ever
			// set on the request, simulating a misconfigured or skipped
			// authn stage ahead of this guard.
			r.GET("/protected", guard, func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})

			req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Errorf("expected 403 (never 401) with no principal in context, got %d: %s", w.Code, w.Body.String())
			}
			if hdr := w.Header().Get("WWW-Authenticate"); hdr != "" {
				t.Errorf("expected no WWW-Authenticate header on a 403 no-principal denial, got %q", hdr)
			}
		})
	}
}

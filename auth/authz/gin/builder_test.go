package gin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
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
		WithMemoryPARC(30*time.Second, nil)

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

// TestAuthorizationBuilder_WithOnDecision_FiresOnRealEvaluate is the Tier 4
// builder-wiring regression test: WithOnDecision must fire with the correct
// Allowed/RequirementType on a real Evaluate call through a built
// AuthorizationService, not just in a unit test of the hook signature
// itself.
func TestAuthorizationBuilder_WithOnDecision_FiresOnRealEvaluate(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var mu sync.Mutex
	var events []authz.DecisionEvent

	builder := NewBuilder().
		AddPolicy("AdminOnly", authz.NewPolicyBuilder().RequireRole("admin").Build()).
		WithOnDecision(func(_ context.Context, e authz.DecisionEvent) {
			mu.Lock()
			defer mu.Unlock()
			events = append(events, e)
		})

	engine, err := builder.Build()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	middleware := UseAuthorization(engine, builder.middlewareOptions...)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		p := &principal.Principal{Subject: "user_regular", Roles: []string{"user"}}
		ginprincipal.Set(c, p)
		c.Next()
	})
	r.Use(middleware)
	r.GET("/admin", Require(WithEngine(engine), WithPolicyName("AdminOnly")), func(c *gin.Context) {
		c.String(http.StatusOK, "admin granted")
	})

	req, _ := http.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", w.Code)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 1 {
		t.Fatalf("expected exactly 1 reported DecisionEvent, got %d: %+v", len(events), events)
	}
	if events[0].Allowed {
		t.Errorf("expected a denied DecisionEvent, got Allowed=true")
	}
	if events[0].RequirementType != "RoleRequirement" {
		t.Errorf("expected RequirementType %q, got %q", "RoleRequirement", events[0].RequirementType)
	}
}

// TestAuthorizationBuilder_WithCacheOutcomeHook_FiresOnRealPARCHandle is the
// Tier 4 builder-wiring regression test for WithCacheOutcomeHook: it must
// fire on a real PARCHandler.Handle call reached through WithMemoryPARC, not
// just in a unit test of PARCHandlerConfig.OnCacheOutcome itself.
func TestAuthorizationBuilder_WithCacheOutcomeHook_FiresOnRealPARCHandle(t *testing.T) {
	gin.SetMode(gin.TestMode)

	repo := authz.NewMemoryPermissionRepository()
	ctx := context.Background()
	if err := repo.GrantPermission(ctx, "john_doe", authz.PermissionRule{
		ActionPattern:     "read",
		ResourceType:      "report",
		ResourceIDPattern: "rep_public_*",
		Effect:            authz.EffectPermit,
	}); err != nil {
		t.Fatalf("GrantPermission: %v", err)
	}

	var mu sync.Mutex
	var outcomes []authz.CacheOutcome

	engine, err := NewBuilder().
		WithMemoryPARC(time.Minute, repo, WithCacheOutcomeHook(func(o authz.CacheOutcome) {
			mu.Lock()
			defer mu.Unlock()
			outcomes = append(outcomes, o)
		})).
		Build()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r := gin.New()
	r.Use(func(c *gin.Context) {
		caller := c.GetHeader("X-Test-User")
		if caller != "" {
			ginprincipal.Set(c, &principal.Principal{Subject: caller, Roles: []string{"user"}})
		}
		c.Next()
	})
	r.GET("/reports/:reportId",
		Require(WithEngine(engine), WithPARC("read", "report"), WithResource(ExtractResourceFromParam("reportId", "report"))),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		},
	)

	req, _ := http.NewRequest(http.MethodGet, "/reports/rep_public_1", nil)
	req.Header.Set("X-Test-User", "john_doe")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	mu.Lock()
	defer mu.Unlock()
	if len(outcomes) != 1 {
		t.Fatalf("expected exactly 1 reported CacheOutcome, got %d: %v", len(outcomes), outcomes)
	}
}

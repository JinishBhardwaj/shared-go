package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JinishBhardwaj/shared-go/authn"
	"github.com/JinishBhardwaj/shared-go/authz/cache"
	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestPARC_RuleMatching(t *testing.T) {
	rule := PermissionRule{
		ActionPattern:     "read",
		ResourceType:      "report",
		ResourceIDPattern: "rep_*",
		Effect:            EffectPermit,
	}

	reqMatch := Request{
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "report", ID: "rep_100"},
	}
	if !rule.Matches(reqMatch) {
		t.Errorf("expected rule to match reqMatch")
	}

	reqMismatchAction := Request{
		Action:   Action{Name: "delete"},
		Resource: Resource{Type: "report", ID: "rep_100"},
	}
	if rule.Matches(reqMismatchAction) {
		t.Errorf("expected rule to not match delete action")
	}

	reqMismatchID := Request{
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "report", ID: "doc_100"},
	}
	if rule.Matches(reqMismatchID) {
		t.Errorf("expected rule to not match doc_100 ID")
	}
}

func TestPARC_DenyOverrides(t *testing.T) {
	perms := &PrincipalPermissions{
		PrincipalID: "usr_1",
		Rules: []PermissionRule{
			{ActionPattern: "*", ResourceType: "report", ResourceIDPattern: "*", Effect: EffectPermit},
			{ActionPattern: "delete", ResourceType: "report", ResourceIDPattern: "rep_secret", Effect: EffectDeny},
		},
	}

	// 1. Read normal report -> Allowed
	d1 := perms.Evaluate(Request{
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "report", ID: "rep_normal"},
	})
	if !d1.Allowed {
		t.Errorf("expected read rep_normal to be allowed")
	}

	// 2. Delete secret report -> Denied
	d2 := perms.Evaluate(Request{
		Action:   Action{Name: "delete"},
		Resource: Resource{Type: "report", ID: "rep_secret"},
	})
	if d2.Allowed {
		t.Errorf("expected delete rep_secret to be denied by deny rule")
	}
}

func TestPolicyEngine_Requirements(t *testing.T) {
	ctx := context.Background()
	engine := NewPolicyEngine(nil)

	// Policy requiring scope 'read:users' AND role 'admin'
	policy := NewPolicy("AdminUsers").
		RequireScope("read:users").
		RequireRole("admin").
		Build()
	engine.RegisterPolicy(policy)

	// 1. Principal missing admin role -> Denied
	idNoRole := &authn.Principal{
		Subject: "user1",
		Scopes:  []string{"read:users"},
		Roles:   []string{"viewer"},
	}
	d1, err := engine.EvaluatePolicy(ctx, "AdminUsers", idNoRole, nil)
	if err != nil || d1.Allowed {
		t.Errorf("expected denial when missing role, got allowed=%v, err=%v", d1.Allowed, err)
	}

	// 2. Principal with all requirements -> Allowed
	idAdmin := &authn.Principal{
		Subject: "admin1",
		Scopes:  []string{"read:users", "write:users"},
		Roles:   []string{"admin"},
	}
	d2, err := engine.EvaluatePolicy(ctx, "AdminUsers", idAdmin, nil)
	if err != nil || !d2.Allowed {
		t.Errorf("expected permit for admin, got allowed=%v, err=%v", d2.Allowed, err)
	}
}

func TestPARCHandler_CachingAndInstantRevocation(t *testing.T) {
	ctx := context.Background()

	// Setup memory cache with invalidation bus
	memCache, err := cache.NewMemoryCacheProvider()
	if err != nil {
		t.Fatalf("failed to create MemoryCacheProvider: %v", err)
	}
	defer memCache.Close()

	repo := NewMemoryPermissionRepository()

	// Grant permission in repo
	principalID := "user_42"
	_ = repo.GrantPermission(ctx, principalID, PermissionRule{
		ActionPattern:     "read",
		ResourceType:      "order",
		ResourceIDPattern: "*",
		Effect:            EffectPermit,
	})

	parcHandler, err := NewPARCHandler(PARCHandlerConfig{
		Repository: repo,
		Cache:      memCache,
		GrantTTL:   60 * time.Second, // 60s grant propagation window
	})
	if err != nil {
		t.Fatalf("failed to create PARCHandler: %v", err)
	}

	engine := NewPolicyEngine(parcHandler)
	policy := NewPolicy("ReadOrder").RequirePARC("read", "order").Build()
	engine.RegisterPolicy(policy)

	id := &authn.Principal{Subject: principalID}
	evalCtx := &EvaluationContext{
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "order", ID: "ord_101"},
	}

	// 1. First evaluation: cache miss -> fetch from repo -> allowed
	d1, err := engine.EvaluatePolicy(ctx, "ReadOrder", id, evalCtx)
	if err != nil || !d1.Allowed {
		t.Fatalf("expected allowed on first check, got allowed=%v, err=%v", d1.Allowed, err)
	}

	// Wait for Ristretto asynchronous write buffer
	time.Sleep(50 * time.Millisecond)

	// Verify key is now cached
	cacheKey := "perm:" + principalID
	if _, err := memCache.Get(ctx, cacheKey); err != nil {
		t.Fatalf("expected permissions to be cached in memCache")
	}

	// 2. Revoke permissions in DB AND publish instant revocation event
	_ = repo.RevokeAll(ctx, principalID)
	_ = memCache.Delete(ctx, cacheKey) // Immediate cache eviction!
	time.Sleep(20 * time.Millisecond)

	// 3. Immediately evaluate again: cache miss -> queries DB (which now has 0 perms) -> Denied immediately!
	d2, err := engine.EvaluatePolicy(ctx, "ReadOrder", id, evalCtx)
	if err != nil {
		t.Fatalf("unexpected evaluation error: %v", err)
	}
	if d2.Allowed {
		t.Fatalf("expected permission check to be immediately denied after revocation, but was allowed!")
	}
}

func TestGinGuard_RequirePolicyAndPARC(t *testing.T) {
	repo := NewMemoryPermissionRepository()
	ctx := context.Background()

	_ = repo.GrantPermission(ctx, "john_doe", PermissionRule{
		ActionPattern:     "read",
		ResourceType:      "report",
		ResourceIDPattern: "rep_public_*",
		Effect:            EffectPermit,
	})

	parcHandler, _ := NewPARCHandler(PARCHandlerConfig{
		Repository: repo,
	})
	engine := NewPolicyEngine(parcHandler)

	r := gin.New()

	// Simulate AuthN middleware attaching Principal
	r.Use(func(c *gin.Context) {
		caller := c.GetHeader("X-Test-User")
		if caller != "" {
			c.Set(authn.DefaultContextKeyPrincipal, &authn.Principal{
				Subject: caller,
				Roles:   []string{"user"},
				Method:  authn.AuthMethodAuthCodePKCE,
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

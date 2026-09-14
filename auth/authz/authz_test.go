package authz

import (
	"context"
	"testing"
	"time"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
	"github.com/JinishBhardwaj/shared-go/cache/memory"
)

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
	idNoRole := &principal.Principal{
		Subject: "user1",
		Scopes:  []string{"read:users"},
		Roles:   []string{"viewer"},
	}
	d1, err := engine.EvaluatePolicy(ctx, "AdminUsers", idNoRole, nil)
	if err != nil || d1.Allowed {
		t.Errorf("expected denial when missing role, got allowed=%v, err=%v", d1.Allowed, err)
	}

	// 2. Principal with all requirements -> Allowed
	idAdmin := &principal.Principal{
		Subject: "admin1",
		Scopes:  []string{"read:users", "write:users"},
		Roles:   []string{"admin"},
	}
	d2, err := engine.EvaluatePolicy(ctx, "AdminUsers", idAdmin, nil)
	if err != nil || !d2.Allowed {
		t.Errorf("expected permit for admin, got allowed=%v, err=%v", d2.Allowed, err)
	}
}

// TestPolicyEngine_MethodAndAnyRoleRequirements exercises the requirement
// types carried over from the former authn/guards.go (gap-analysis-final.md
// §3.8 step 6): MethodRequirement (backing RequireMethod/RequireUser/RequireM2M)
// and RoleRequirement{RequireAll:false} via the RequireAnyRole builder method.
func TestPolicyEngine_MethodAndAnyRoleRequirements(t *testing.T) {
	ctx := context.Background()
	engine := NewPolicyEngine(nil)

	policy := NewPolicy("InteractiveEditors").
		RequireMethod(principal.AuthMethodAuthCodePKCE, principal.AuthMethodDeviceFlow).
		RequireAnyRole("editor", "admin").
		Build()
	engine.RegisterPolicy(policy)

	// 1. M2M principal with a matching role -> denied (wrong auth method).
	m2m := &principal.Principal{
		Subject: "svc1",
		Method:  principal.AuthMethodClientCredentials,
		Roles:   []string{"editor"},
	}
	d1, err := engine.EvaluatePolicy(ctx, "InteractiveEditors", m2m, nil)
	if err != nil || d1.Allowed {
		t.Errorf("expected denial for client-credentials principal, got allowed=%v, err=%v", d1.Allowed, err)
	}

	// 2. Interactive principal with neither candidate role -> denied.
	noRole := &principal.Principal{
		Subject: "user1",
		Method:  principal.AuthMethodAuthCodePKCE,
		Roles:   []string{"viewer"},
	}
	d2, err := engine.EvaluatePolicy(ctx, "InteractiveEditors", noRole, nil)
	if err != nil || d2.Allowed {
		t.Errorf("expected denial for principal missing both candidate roles, got allowed=%v, err=%v", d2.Allowed, err)
	}

	// 3. Interactive principal with one of the candidate roles -> allowed.
	editor := &principal.Principal{
		Subject: "user2",
		Method:  principal.AuthMethodDeviceFlow,
		Roles:   []string{"editor"},
	}
	d3, err := engine.EvaluatePolicy(ctx, "InteractiveEditors", editor, nil)
	if err != nil || !d3.Allowed {
		t.Errorf("expected permit for device-flow editor, got allowed=%v, err=%v", d3.Allowed, err)
	}
}

// TestRoleRequirementHandler_RequireAllFlag is the Tier 0 #8 regression test
// (gap-analysis-final.md: "RoleRequirement.RequireAll is declared but ignored --
// handler always ANDs. Silent misconfiguration"). RequireAll:false must be OR
// (at least one candidate role), not silently upgraded to AND (all roles).
func TestRoleRequirementHandler_RequireAllFlag(t *testing.T) {
	ctx := context.Background()
	handler := &RoleRequirementHandler{}

	viewer := &principal.Principal{Subject: "user1", Roles: []string{"viewer"}}

	// RequireAll:false ("any of admin, viewer") -- principal has only "viewer",
	// so this must be ALLOWED. Under the ignored-flag bug this is denied,
	// because the handler ANDs unconditionally and the principal lacks "admin".
	anyReq := RoleRequirement{Roles: []string{"admin", "viewer"}, RequireAll: false}
	allowed, err := handler.Handle(ctx, viewer, anyReq, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Errorf("RoleRequirement{RequireAll:false} with one matching role = denied, want allowed (OR semantics)")
	}

	// RequireAll:false with NO matching candidate role must still deny.
	noneReq := RoleRequirement{Roles: []string{"admin", "editor"}, RequireAll: false}
	allowed, err = handler.Handle(ctx, viewer, noneReq, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Errorf("RoleRequirement{RequireAll:false} with no matching role = allowed, want denied")
	}

	// RequireAll:true ("all of admin, viewer") -- principal only has "viewer",
	// so this must remain DENIED (AND semantics, unchanged).
	allReq := RoleRequirement{Roles: []string{"admin", "viewer"}, RequireAll: true}
	allowed, err = handler.Handle(ctx, viewer, allReq, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Errorf("RoleRequirement{RequireAll:true} missing one role = allowed, want denied (AND semantics)")
	}

	// RequireAll:true with every role present must allow.
	admin := &principal.Principal{Subject: "user2", Roles: []string{"admin", "viewer"}}
	allowed, err = handler.Handle(ctx, admin, allReq, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Errorf("RoleRequirement{RequireAll:true} with every role present = denied, want allowed")
	}
}

func TestPARCHandler_CachingAndInstantRevocation(t *testing.T) {
	ctx := context.Background()

	// Setup a typed in-process cache for the permission bundle.
	memCache := memory.New[*PrincipalPermissions](0)
	defer memCache.Dispose()

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

	id := &principal.Principal{Subject: principalID}
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
	if _, found, err := memCache.Get(ctx, cacheKey); err != nil || !found {
		t.Fatalf("expected permissions to be cached in memCache, found=%v err=%v", found, err)
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

// TestMapPARCPrincipal_ComputedOnceAndReused is the G4 / Tier 2 "map the
// principal once" regression test (gap-analysis-final.md line 106).
// PARCHandler.Handle and CustomRequirementHandler.Handle used to allocate a
// fresh PARC-shaped Principal{...} on every single call instead of once per
// request; mapPARCPrincipal must compute it once per EvaluationContext and
// reuse the cached value on every subsequent call against the same
// evalCtx/principal pair, while still recomputing (never returning a stale
// mapping) if the principal pointer genuinely changes.
func TestMapPARCPrincipal_ComputedOnceAndReused(t *testing.T) {
	p := &principal.Principal{
		Subject:  "user-1",
		ClientID: "client-1",
		Roles:    []string{"admin"},
		Scopes:   []string{"read"},
		Method:   principal.AuthMethodClientCredentials,
		Metadata: map[string]any{"tenant": "acme"},
	}
	evalCtx := &EvaluationContext{}

	first := mapPARCPrincipal(evalCtx, p)
	if first.ID != p.Subject || first.ClientID != p.ClientID || first.AuthMethod != string(p.Method) {
		t.Fatalf("mapped fields mismatch: %+v", first)
	}
	if evalCtx.mappedPrincipal == nil {
		t.Fatalf("expected evalCtx to cache the mapped Principal after the first call")
	}
	cached := evalCtx.mappedPrincipal

	second := mapPARCPrincipal(evalCtx, p)
	if evalCtx.mappedPrincipal != cached {
		t.Errorf("second call against the same evalCtx/principal reallocated the mapped Principal instead of reusing the cache -- Tier 2 'map the principal once' regression")
	}
	if second.ID != first.ID || second.ClientID != first.ClientID || second.AuthMethod != first.AuthMethod {
		t.Errorf("cached mapping differs from the original: got %+v, want %+v", second, first)
	}

	// A different principal pointer must recompute rather than return a
	// stale cached mapping (defensive correctness, not the perf claim).
	p2 := &principal.Principal{Subject: "user-2"}
	third := mapPARCPrincipal(evalCtx, p2)
	if third.ID != "user-2" {
		t.Errorf("expected recompute for a different principal, got stale mapping %+v", third)
	}
}

// TestPolicyEngine_StackedPARCAndCustomRequirement_MapsPrincipalOnce covers
// the realistic stacking case the gap doc calls out: a policy combining
// RequireAuthenticatedUser() (a CustomRequirement) with RequirePARC(...)
// evaluates both a CustomRequirementHandler and a PARCHandler against the
// same EvaluationContext for one request. Before this fix each handler
// independently rebuilt the PARC-shaped Principal; now the second handler to
// run must reuse the mapping the first one computed.
func TestPolicyEngine_StackedPARCAndCustomRequirement_MapsPrincipalOnce(t *testing.T) {
	ctx := context.Background()
	memCache := memory.New[*PrincipalPermissions](0)
	defer memCache.Dispose()

	repo := NewMemoryPermissionRepository()
	principalID := "user_stack"
	_ = repo.GrantPermission(ctx, principalID, PermissionRule{
		ActionPattern:     "read",
		ResourceType:      "order",
		ResourceIDPattern: "*",
		Effect:            EffectPermit,
	})

	parcHandler, err := NewPARCHandler(PARCHandlerConfig{Repository: repo, Cache: memCache})
	if err != nil {
		t.Fatalf("failed to create PARCHandler: %v", err)
	}

	engine := NewPolicyEngine(parcHandler)
	policy := NewPolicy("StackedReadOrder").RequireAuthenticatedUser().RequirePARC("read", "order").Build()
	engine.RegisterPolicy(policy)

	p := &principal.Principal{Subject: principalID}
	evalCtx := &EvaluationContext{
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "order", ID: "ord_1"},
	}

	d, err := engine.EvaluatePolicy(ctx, "StackedReadOrder", p, evalCtx)
	if err != nil || !d.Allowed {
		t.Fatalf("expected allowed, got allowed=%v err=%v", d.Allowed, err)
	}
	if evalCtx.mappedPrincipal == nil {
		t.Fatalf("expected the mapped principal to be cached on evalCtx after evaluating a policy with both a CustomRequirement and a PARCRequirement")
	}
	if evalCtx.mappedPrincipalFor != p {
		t.Errorf("cached mapping is not keyed to the evaluated principal")
	}
}

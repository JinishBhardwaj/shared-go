package authz

import (
	"context"
	"testing"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
)

// BenchmarkPolicyEngine_Evaluate is the Tier 3 baseline benchmark for
// PolicyEngine.Evaluate (gap-analysis-final.md: "Benchmarks for
// Authenticate, PolicyEngine.Authorize and PARC evaluation -- establish
// baselines before optimizing, and to prove the claims above"). The policy
// combines a ScopeRequirement and a RoleRequirement, both satisfied by the
// benchmark principal, so every iteration exercises the full requirements
// loop (including both built-in handlers) down the allow path.
func BenchmarkPolicyEngine_Evaluate(b *testing.B) {
	engine := NewAuthorizationService(nil)

	policy := NewPolicy("BenchPolicy").
		RequireScope("read:reports").
		RequireRole("viewer").
		Build()

	p := &principal.Principal{
		Subject: "bench-user",
		Scopes:  []string{"read:reports"},
		Roles:   []string{"viewer"},
	}

	ctx := context.Background()
	evalCtx := &EvaluationContext{
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "report", ID: "rep_1"},
	}

	// Sanity check once before timing.
	d, err := engine.Evaluate(ctx, policy, p, evalCtx)
	if err != nil || !d.Allowed {
		b.Fatalf("sanity Evaluate call failed: allowed=%v err=%v", d.Allowed, err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := engine.Evaluate(ctx, policy, p, evalCtx); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPARCHandler_Handle_WarmCache is the Tier 3 baseline benchmark for
// PARC evaluation on the steady-state, cache-hit path: the repository is
// seeded with a single permit rule for the benchmark principal, Handle is
// called once before b.ResetTimer() to warm the L1 cache, and every timed
// iteration then hits that warm cache instead of the repository (see
// PARCHandler.Handle's "L1 in-memory check takes ~30-50 nanoseconds"
// comment -- this benchmark measures that path directly).
func BenchmarkPARCHandler_Handle_WarmCache(b *testing.B) {
	ctx := context.Background()
	repo := NewMemoryPermissionRepository()

	principalID := "bench-principal"
	if err := repo.GrantPermission(ctx, &principal.Principal{Subject: principalID}, PermissionRule{
		ActionPattern:     "read",
		ResourceType:      "report",
		ResourceIDPattern: "*",
		Effect:            EffectPermit,
	}); err != nil {
		b.Fatalf("failed to seed benchmark permission rule: %v", err)
	}

	handler, err := NewPARCHandler(PARCHandlerConfig{Repository: repo})
	if err != nil {
		b.Fatalf("failed to create PARCHandler: %v", err)
	}

	p := &principal.Principal{Subject: principalID}
	req := PARCRequirement{Action: "read", ResourceType: "report"}
	evalCtx := &EvaluationContext{
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "report", ID: "rep_1"},
	}

	// Warm-up call: populates the L1 cache so the timed loop measures the
	// cache-hit path, not the cold miss.
	allowed, err := handler.Handle(ctx, p, req, evalCtx)
	if err != nil || !allowed {
		b.Fatalf("warm-up Handle call failed: allowed=%v err=%v", allowed, err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := handler.Handle(ctx, p, req, evalCtx); err != nil {
			b.Fatal(err)
		}
	}
}

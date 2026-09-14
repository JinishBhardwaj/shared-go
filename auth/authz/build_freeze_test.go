package authz

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
)

// TestPolicyEngine_RegisterPolicyAfterBuildPanics verifies Tier 1 line 99:
// once Build() has been called, RegisterPolicy must panic rather than
// silently accept post-serve registration.
func TestPolicyEngine_RegisterPolicyAfterBuildPanics(t *testing.T) {
	e := NewPolicyEngine()
	e.Build()

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected RegisterPolicy to panic after Build(), it did not")
		}
	}()

	e.RegisterPolicy(NewPolicy("late").Build())
}

// TestPolicyEngine_RegisterHandlerAfterBuildPanics mirrors
// TestPolicyEngine_RegisterPolicyAfterBuildPanics for RegisterHandler.
func TestPolicyEngine_RegisterHandlerAfterBuildPanics(t *testing.T) {
	e := NewPolicyEngine()
	e.Build()

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected RegisterHandler to panic after Build(), it did not")
		}
	}()

	e.RegisterHandler("LateRequirement", &ScopeRequirementHandler{})
}

// TestPolicyEngine_UsableWithoutEverCallingBuild proves Build() is opt-in:
// an engine that never calls it behaves exactly as before, with
// RegisterPolicy/EvaluatePolicy working unchanged.
func TestPolicyEngine_UsableWithoutEverCallingBuild(t *testing.T) {
	e := NewPolicyEngine()
	e.RegisterPolicy(NewPolicy("allow-anyone").
		RequireAuthenticatedUser().
		Build())

	p := &principal.Principal{Subject: "user-1"}
	evalCtx := &EvaluationContext{}

	d, err := e.EvaluatePolicy(context.Background(), "allow-anyone", p, evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !d.Allowed {
		t.Fatalf("expected allowed, got denied: %s", d.Reason)
	}
}

// TestPolicyEngine_ConcurrentRegisterAndEvaluateBeforeBuildIsRaceFree proves
// the "no unguarded map writes" half of Tier 1 line 99: one goroutine
// registering distinct policies concurrently with other goroutines
// evaluating already-registered policies, all before Build() is ever called,
// must be race-free under -race.
func TestPolicyEngine_ConcurrentRegisterAndEvaluateBeforeBuildIsRaceFree(t *testing.T) {
	e := NewPolicyEngine()

	const iterations = 50
	const readers = 4

	// Seed one policy up front so readers always have something to evaluate.
	seedName := "seed-policy"
	e.RegisterPolicy(NewPolicy(seedName).
		RequireAuthenticatedUser().
		Build())

	p := &principal.Principal{Subject: "user-1"}

	var wg sync.WaitGroup

	// Writer: registers a freshly-named policy each iteration.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			e.RegisterPolicy(NewPolicy(fmt.Sprintf("policy-%d", i)).
				RequireAuthenticatedUser().
				Build())
		}
	}()

	// Readers: repeatedly evaluate the seeded policy concurrently with the
	// writer above.
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			evalCtx := &EvaluationContext{}
			for i := 0; i < iterations; i++ {
				if _, err := e.EvaluatePolicy(context.Background(), seedName, p, evalCtx); err != nil {
					t.Errorf("unexpected error evaluating seeded policy: %v", err)
				}
			}
		}()
	}

	wg.Wait()
}

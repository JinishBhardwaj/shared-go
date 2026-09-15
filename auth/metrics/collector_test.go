package metrics

import (
	"context"
	"sync"
	"testing"
	"time"

	authngin "github.com/JinishBhardwaj/shared-go/auth/authn/gin"
	"github.com/JinishBhardwaj/shared-go/auth/authz"
)

// TestCollector_OnDecision_DenyReasonBucketing confirms deny reasons are
// bucketed by DecisionEvent.RequirementType, and that an empty
// RequirementType on a denied event -- meaning the policy itself was not
// found, per DecisionEvent's own doc comment -- is bucketed under the
// literal key "policy_not_found" rather than left empty.
func TestCollector_OnDecision_DenyReasonBucketing(t *testing.T) {
	c := NewCollector()
	ctx := context.Background()

	c.OnDecision(ctx, authz.DecisionEvent{Allowed: true})
	c.OnDecision(ctx, authz.DecisionEvent{Allowed: false, RequirementType: "RoleRequirement"})
	c.OnDecision(ctx, authz.DecisionEvent{Allowed: false, RequirementType: "RoleRequirement"})
	c.OnDecision(ctx, authz.DecisionEvent{Allowed: false, RequirementType: "ScopeRequirement"})
	c.OnDecision(ctx, authz.DecisionEvent{Allowed: false, RequirementType: ""})

	snap := c.Snapshot()

	if snap.TotalDecisions != 5 {
		t.Fatalf("expected 5 total decisions, got %d", snap.TotalDecisions)
	}
	if snap.AllowedDecisions != 1 {
		t.Fatalf("expected 1 allowed decision, got %d", snap.AllowedDecisions)
	}
	if snap.DeniedDecisions != 4 {
		t.Fatalf("expected 4 denied decisions, got %d", snap.DeniedDecisions)
	}
	if got := snap.DenyReasons["RoleRequirement"]; got != 2 {
		t.Errorf("expected 2 RoleRequirement denials, got %d", got)
	}
	if got := snap.DenyReasons["ScopeRequirement"]; got != 1 {
		t.Errorf("expected 1 ScopeRequirement denial, got %d", got)
	}
	if got := snap.DenyReasons["policy_not_found"]; got != 1 {
		t.Errorf("expected 1 policy_not_found denial (empty RequirementType), got %d", got)
	}
	if _, present := snap.DenyReasons[""]; present {
		t.Errorf("empty RequirementType must not be left as a literal empty-string key, got entry: %v", snap.DenyReasons)
	}
}

// TestCollector_Snapshot_IsDefensiveCopy confirms mutating a returned
// Snapshot's maps cannot corrupt the Collector's internal state.
func TestCollector_Snapshot_IsDefensiveCopy(t *testing.T) {
	c := NewCollector()
	ctx := context.Background()
	c.OnDecision(ctx, authz.DecisionEvent{Allowed: false, RequirementType: "RoleRequirement"})

	snap := c.Snapshot()
	snap.DenyReasons["RoleRequirement"] = 999
	snap.DenyReasons["Injected"] = 1

	snap2 := c.Snapshot()
	if got := snap2.DenyReasons["RoleRequirement"]; got != 1 {
		t.Fatalf("mutating a returned Snapshot's map corrupted the collector: got %d, want 1", got)
	}
	if _, present := snap2.DenyReasons["Injected"]; present {
		t.Fatalf("mutating a returned Snapshot's map leaked into the collector's internal state")
	}
}

// TestCollector_OnCacheOutcome_HitRatio covers cache-hit-ratio arithmetic,
// including the zero-samples case, which must be exactly 0.0 -- never NaN,
// never a panic.
func TestCollector_OnCacheOutcome_HitRatio(t *testing.T) {
	c := NewCollector()

	snap := c.Snapshot()
	if snap.CacheHitRatio != 0 {
		t.Fatalf("expected 0 cache hit ratio with no samples, got %v", snap.CacheHitRatio)
	}

	c.OnCacheOutcome(authz.CacheHit)
	c.OnCacheOutcome(authz.CacheHit)
	c.OnCacheOutcome(authz.CacheHit)
	c.OnCacheOutcome(authz.CacheMiss)
	c.OnCacheOutcome(authz.CacheRefreshed)
	c.OnCacheOutcome(authz.CacheStale)

	snap = c.Snapshot()
	// 3 hits out of 6 total observations = 0.5.
	if snap.CacheHitRatio != 0.5 {
		t.Fatalf("expected cache hit ratio 0.5, got %v", snap.CacheHitRatio)
	}
	if snap.CacheOutcomes["hit"] != 3 {
		t.Errorf("expected 3 hit outcomes, got %d", snap.CacheOutcomes["hit"])
	}
	if snap.CacheOutcomes["miss"] != 1 {
		t.Errorf("expected 1 miss outcome, got %d", snap.CacheOutcomes["miss"])
	}
	if snap.CacheOutcomes["refreshed"] != 1 {
		t.Errorf("expected 1 refreshed outcome, got %d", snap.CacheOutcomes["refreshed"])
	}
	if snap.CacheOutcomes["stale"] != 1 {
		t.Errorf("expected 1 stale outcome, got %d", snap.CacheOutcomes["stale"])
	}
}

// TestCollector_OnAuthenticate_SuccessAndFailureByCredentialType confirms
// success/failure counts are tracked separately per credential type, and
// that the authenticate-latency histogram is kept distinct from the
// decision-latency histogram.
func TestCollector_OnAuthenticate_SuccessAndFailureByCredentialType(t *testing.T) {
	c := NewCollector()
	ctx := context.Background()

	c.OnAuthenticate(ctx, authngin.AuthEvent{CredentialType: "bearer", Success: true, Duration: 10 * time.Millisecond})
	c.OnAuthenticate(ctx, authngin.AuthEvent{CredentialType: "bearer", Success: false, Duration: 20 * time.Millisecond})
	c.OnAuthenticate(ctx, authngin.AuthEvent{CredentialType: "apikey", Success: true, Duration: 5 * time.Millisecond})
	c.OnAuthenticate(ctx, authngin.AuthEvent{CredentialType: "", Success: false, Duration: 1 * time.Millisecond})

	c.OnDecision(ctx, authz.DecisionEvent{Allowed: true, Duration: time.Hour})

	snap := c.Snapshot()

	if got := snap.AuthSuccessByCredentialType["bearer"]; got != 1 {
		t.Errorf("expected 1 bearer success, got %d", got)
	}
	if got := snap.AuthFailureByCredentialType["bearer"]; got != 1 {
		t.Errorf("expected 1 bearer failure, got %d", got)
	}
	if got := snap.AuthSuccessByCredentialType["apikey"]; got != 1 {
		t.Errorf("expected 1 apikey success, got %d", got)
	}
	if got := snap.AuthFailureByCredentialType[""]; got != 1 {
		t.Errorf("expected 1 no-credential failure, got %d", got)
	}

	// The decision-latency histogram was fed a 1-hour sample; if the
	// authenticate histogram were blended with it, AuthenticateP99 would
	// reflect that hour-long outlier instead of staying in the
	// millisecond range of the actual authenticate samples.
	if snap.AuthenticateP99 >= time.Second {
		t.Fatalf("authenticate-latency histogram appears blended with decision-latency histogram: AuthenticateP99=%v", snap.AuthenticateP99)
	}
}

// TestCollector_Percentiles_KnownDistribution feeds 100 samples of known,
// evenly distributed durations (1ms, 2ms, ..., 100ms) and asserts p50/p90/p99
// land at the expected indices.
func TestCollector_Percentiles_KnownDistribution(t *testing.T) {
	c := NewCollector()
	ctx := context.Background()

	for i := 1; i <= 100; i++ {
		c.OnDecision(ctx, authz.DecisionEvent{Allowed: true, Duration: time.Duration(i) * time.Millisecond})
	}

	snap := c.Snapshot()

	// n=100, sorted samples are 1ms..100ms (already sorted, index i holds
	// (i+1)ms). index = int(99*q).
	n := 99
	idx := func(q float64) time.Duration {
		return time.Duration(int(float64(n)*q)+1) * time.Millisecond
	}
	wantP50 := idx(0.50)
	wantP90 := idx(0.90)
	wantP99 := idx(0.99)

	if snap.DecisionP50 != wantP50 {
		t.Errorf("expected DecisionP50=%v, got %v", wantP50, snap.DecisionP50)
	}
	if snap.DecisionP90 != wantP90 {
		t.Errorf("expected DecisionP90=%v, got %v", wantP90, snap.DecisionP90)
	}
	if snap.DecisionP99 != wantP99 {
		t.Errorf("expected DecisionP99=%v, got %v", wantP99, snap.DecisionP99)
	}
}

// TestCollector_Percentiles_EmptyIsZero confirms an empty histogram reports
// zero percentiles rather than panicking.
func TestCollector_Percentiles_EmptyIsZero(t *testing.T) {
	c := NewCollector()
	snap := c.Snapshot()
	if snap.DecisionP50 != 0 || snap.DecisionP90 != 0 || snap.DecisionP99 != 0 {
		t.Fatalf("expected zero decision percentiles with no samples, got p50=%v p90=%v p99=%v", snap.DecisionP50, snap.DecisionP90, snap.DecisionP99)
	}
	if snap.AuthenticateP50 != 0 || snap.AuthenticateP90 != 0 || snap.AuthenticateP99 != 0 {
		t.Fatalf("expected zero authenticate percentiles with no samples, got p50=%v p90=%v p99=%v", snap.AuthenticateP50, snap.AuthenticateP90, snap.AuthenticateP99)
	}
}

// TestCollector_Concurrent hammers OnDecision/OnCacheOutcome/OnAuthenticate
// from multiple goroutines simultaneously, with Snapshot() calls
// interleaved, under -race.
func TestCollector_Concurrent(t *testing.T) {
	c := NewCollector()
	ctx := context.Background()

	const goroutines = 10
	const perGoroutine = 200
	const snapshotsPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(goroutines * 4)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				c.OnDecision(ctx, authz.DecisionEvent{
					Allowed:         i%2 == 0,
					RequirementType: "RoleRequirement",
					Duration:        time.Duration(i) * time.Microsecond,
				})
			}
		}(g)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				c.OnCacheOutcome(authz.CacheOutcome(i % 4))
			}
		}(g)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				c.OnAuthenticate(ctx, authngin.AuthEvent{
					CredentialType: "bearer",
					Success:        i%3 == 0,
					Duration:       time.Duration(i) * time.Microsecond,
				})
			}
		}(g)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < snapshotsPerGoroutine; i++ {
				_ = c.Snapshot()
			}
		}(g)
	}

	wg.Wait()

	snap := c.Snapshot()
	wantTotal := int64(goroutines * perGoroutine)
	if snap.TotalDecisions != wantTotal {
		t.Fatalf("expected %d total decisions, got %d", wantTotal, snap.TotalDecisions)
	}
}

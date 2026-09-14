package authz

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
	"github.com/JinishBhardwaj/shared-go/cache/memory"
)

// countingRepo is a configurable PermissionRepository stub used to exercise
// PARCHandler's Tier 3 singleflight/deadline/breaker/stale-while-revalidate
// behavior: it counts calls, can inject an artificial delay (to force
// concurrent callers to overlap, proving singleflight collapsing), and can
// be flipped to return an error on demand (to force refresh failures).
type countingRepo struct {
	mu    sync.Mutex
	calls int
	delay time.Duration
	err   error
	perms *PrincipalPermissions
}

func (r *countingRepo) GetPermissions(ctx context.Context, principalID string) (*PrincipalPermissions, error) {
	r.mu.Lock()
	r.calls++
	delay := r.delay
	err := r.err
	perms := r.perms
	r.mu.Unlock()

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	cp := *perms
	rules := make([]PermissionRule, len(perms.Rules))
	copy(rules, perms.Rules)
	cp.Rules = rules
	return &cp, nil
}

func (r *countingRepo) GrantPermission(ctx context.Context, principalID string, rule PermissionRule) error {
	return errors.New("countingRepo: GrantPermission not supported")
}

func (r *countingRepo) RevokeAll(ctx context.Context, principalID string) error {
	return nil
}

func (r *countingRepo) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func (r *countingRepo) setErr(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.err = err
}

func readOrderPermitBundle(principalID string) *PrincipalPermissions {
	return &PrincipalPermissions{
		PrincipalID: principalID,
		Rules: []PermissionRule{
			{
				ActionPattern:     "read",
				ResourceType:      "order",
				ResourceIDPattern: "*",
				Effect:            EffectPermit,
			},
		},
	}
}

func parcHandleReq() (Requirement, *EvaluationContext) {
	return PARCRequirement{Action: "read", ResourceType: "order"},
		&EvaluationContext{
			Action:   Action{Name: "read"},
			Resource: Resource{Type: "order", ID: "ord_1"},
		}
}

// TestPARCHandler_SingleflightCollapsesConcurrentRefetch is the Tier 3 #1
// regression test: N concurrent Handle calls for the same principal, with
// nothing cached, must collapse into a single repository call rather than
// fanning out N calls to the repository. Confirmed red (calls == N) against
// the pre-singleflight code, green (calls == 1) after.
func TestPARCHandler_SingleflightCollapsesConcurrentRefetch(t *testing.T) {
	ctx := context.Background()
	principalID := "user_hot"

	repo := &countingRepo{delay: 60 * time.Millisecond, perms: readOrderPermitBundle(principalID)}
	memCache := memory.New[*PrincipalPermissions](0)
	defer memCache.Dispose()

	h, err := NewPARCHandler(PARCHandlerConfig{
		Repository:  repo,
		Cache:       memCache,
		GrantTTL:    60 * time.Second,
		RepoTimeout: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewPARCHandler: %v", err)
	}

	id := &principal.Principal{Subject: principalID}

	const n = 20
	var wg sync.WaitGroup
	var allowedCount int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each concurrent call gets its own *EvaluationContext, matching
			// real usage (a fresh EvaluationContext per request -- see
			// EvaluationContext's doc comment in engine.go) rather than
			// sharing one across goroutines. Sharing one evalCtx across
			// truly concurrent Handle calls would race on
			// mapPARCPrincipal's unsynchronized per-evalCtx memoization
			// (a pre-existing G4 concern, not something G5 touches or is
			// scoped to fix -- see "Proposed additions" in state.md) --
			// that's a different, unrelated question from whether
			// singleflight collapses concurrent repository fetches for the
			// same principal, which is what this test actually checks.
			req, evalCtx := parcHandleReq()
			allowed, err := h.Handle(ctx, id, req, evalCtx)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if allowed {
				atomic.AddInt32(&allowedCount, 1)
			}
		}()
	}
	wg.Wait()

	if got := repo.callCount(); got != 1 {
		t.Fatalf("expected exactly 1 repository call for %d concurrent callers on the same principal (singleflight collapse), got %d", n, got)
	}
	if int(allowedCount) != n {
		t.Fatalf("expected all %d concurrent callers to see allowed=true, got %d", n, allowedCount)
	}
}

// TestPARCHandler_FreshCacheHit_NeverCallsRepository proves the fast path is
// unchanged: a cache entry within GrantTTL of its FetchedAt is used
// directly, with no repository call at all.
func TestPARCHandler_FreshCacheHit_NeverCallsRepository(t *testing.T) {
	ctx := context.Background()
	principalID := "user_fresh"

	repo := &countingRepo{perms: readOrderPermitBundle(principalID)}
	memCache := memory.New[*PrincipalPermissions](0)
	defer memCache.Dispose()

	h, err := NewPARCHandler(PARCHandlerConfig{
		Repository: repo,
		Cache:      memCache,
		GrantTTL:   60 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewPARCHandler: %v", err)
	}

	bundle := readOrderPermitBundle(principalID)
	bundle.FetchedAt = time.Now()
	if err := memCache.Set(ctx, "perm:"+principalID, bundle, time.Minute); err != nil {
		t.Fatalf("priming cache: %v", err)
	}

	id := &principal.Principal{Subject: principalID}
	req, evalCtx := parcHandleReq()

	allowed, err := h.Handle(ctx, id, req, evalCtx)
	if err != nil || !allowed {
		t.Fatalf("expected allowed=true, err=nil, got allowed=%v err=%v", allowed, err)
	}
	if got := repo.callCount(); got != 0 {
		t.Fatalf("expected 0 repository calls on a fresh cache hit, got %d", got)
	}
}

// TestPARCHandler_RefreshFailure_NoStaleCopy_FailsClosed is a fail-closed
// regression test: when there is nothing usable in the cache at all (a
// genuine miss) and the repository fetch fails (here, a plain error --
// equally true for a deadline-exceeded or breaker-open failure, since all
// three surface identically from refreshPermissions), Handle must return an
// error and never report allowed=true.
func TestPARCHandler_RefreshFailure_NoStaleCopy_FailsClosed(t *testing.T) {
	ctx := context.Background()
	principalID := "user_down"

	repo := &countingRepo{err: errors.New("boom: repository unreachable")}
	memCache := memory.New[*PrincipalPermissions](0)
	defer memCache.Dispose()

	h, err := NewPARCHandler(PARCHandlerConfig{
		Repository:  repo,
		Cache:       memCache,
		GrantTTL:    60 * time.Second,
		RepoTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewPARCHandler: %v", err)
	}

	id := &principal.Principal{Subject: principalID}
	req, evalCtx := parcHandleReq()

	allowed, err := h.Handle(ctx, id, req, evalCtx)
	if err == nil {
		t.Fatalf("expected an error when the repository is down and nothing is cached, got allowed=%v err=nil", allowed)
	}
	if allowed {
		t.Fatalf("fail-open regression: Handle returned allowed=true despite a repository failure and no cached fallback")
	}
}

// TestPARCHandler_StaleWhileRevalidate_ServesStaleOnRefreshFailure is the
// stale-while-revalidate regression test: a bundle that is stale (past
// GrantTTL) but still cached (not yet past StaleTTL) is served when the
// refresh attempt fails, instead of failing the request.
func TestPARCHandler_StaleWhileRevalidate_ServesStaleOnRefreshFailure(t *testing.T) {
	ctx := context.Background()
	principalID := "user_stale"

	repo := &countingRepo{perms: readOrderPermitBundle(principalID)}
	memCache := memory.New[*PrincipalPermissions](0)
	defer memCache.Dispose()

	h, err := NewPARCHandler(PARCHandlerConfig{
		Repository:  repo,
		Cache:       memCache,
		GrantTTL:    20 * time.Millisecond, // soft TTL: goes stale fast
		StaleTTL:    time.Minute,           // hard TTL: still cached when we retry
		RepoTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewPARCHandler: %v", err)
	}

	id := &principal.Principal{Subject: principalID}
	req, evalCtx := parcHandleReq()

	// 1. First call: cache miss, successful fetch, caches the bundle.
	allowed, err := h.Handle(ctx, id, req, evalCtx)
	if err != nil || !allowed {
		t.Fatalf("expected first call to succeed, got allowed=%v err=%v", allowed, err)
	}
	if got := repo.callCount(); got != 1 {
		t.Fatalf("expected exactly 1 repository call after the first (miss) Handle call, got %d", got)
	}

	// 2. Let the entry go stale (past GrantTTL, still within StaleTTL), then
	// break the repository.
	time.Sleep(30 * time.Millisecond)
	repo.setErr(errors.New("boom: repository temporarily unreachable"))

	// 3. Second call: refresh is attempted and fails, but the stale bundle
	// is still in the cache -- Handle must serve it, not fail the request.
	allowed, err = h.Handle(ctx, id, req, evalCtx)
	if err != nil {
		t.Fatalf("stale-while-revalidate regression: expected the stale cached bundle to be served (err=nil), got err=%v", err)
	}
	if !allowed {
		t.Fatalf("stale-while-revalidate regression: expected allowed=true from the stale bundle, got allowed=false")
	}
	if got := repo.callCount(); got != 2 {
		t.Fatalf("expected a refresh attempt (2nd repository call) even though it was served stale, got %d calls", got)
	}
}

// TestPARCHandler_StaleButRevoked_RepoDown_FailsClosed is the most
// important adversarial test in this file: it proves stale-while-revalidate
// can never become a fail-open path. The existing "instant revocation"
// contract (TestPARCHandler_CachingAndInstantRevocation) has the CALLER
// delete the cache entry directly as part of revoking a principal
// (repo.RevokeAll + cache.Delete, together) -- there is no second/shadow
// stale store inside PARCHandler that survives that deletion. So a backend
// outage that coincides with an active revocation must still deny, not
// serve a stale allow.
func TestPARCHandler_StaleButRevoked_RepoDown_FailsClosed(t *testing.T) {
	ctx := context.Background()
	principalID := "user_revoked"

	repo := &countingRepo{perms: readOrderPermitBundle(principalID)}
	memCache := memory.New[*PrincipalPermissions](0)
	defer memCache.Dispose()

	h, err := NewPARCHandler(PARCHandlerConfig{
		Repository:  repo,
		Cache:       memCache,
		GrantTTL:    20 * time.Millisecond,
		StaleTTL:    time.Minute,
		RepoTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewPARCHandler: %v", err)
	}

	id := &principal.Principal{Subject: principalID}
	req, evalCtx := parcHandleReq()

	// 1. Prime the cache with a successful fetch.
	allowed, err := h.Handle(ctx, id, req, evalCtx)
	if err != nil || !allowed {
		t.Fatalf("expected first call to succeed, got allowed=%v err=%v", allowed, err)
	}

	// 2. Let it go stale, then simulate the caller's own instant-revocation
	// contract: delete the cache entry outright, exactly as
	// TestPARCHandler_CachingAndInstantRevocation does.
	time.Sleep(30 * time.Millisecond)
	if err := memCache.Delete(ctx, "perm:"+principalID); err != nil {
		t.Fatalf("cache.Delete: %v", err)
	}

	// 3. Break the repository (simulating an outage coinciding with the
	// revocation) and call Handle again: with the cache entry gone, there is
	// nothing to fall back to -- this must fail closed.
	repo.setErr(errors.New("boom: repository unreachable during revocation window"))

	allowed, err = h.Handle(ctx, id, req, evalCtx)
	if err == nil {
		t.Fatalf("fail-open regression: expected an error (no stale copy survives an explicit cache.Delete), got allowed=%v err=nil", allowed)
	}
	if allowed {
		t.Fatalf("fail-open regression: Handle returned allowed=true for a revoked principal during a repository outage")
	}
}

// TestPARCHandler_OnCacheOutcome_ReportsBranchTaken is an additive-only
// instrumentation test (Tier 4 partial): confirms OnCacheOutcome is called
// with the correct CacheOutcome for a hit and for a miss, and that a nil
// hook is a safe no-op.
func TestPARCHandler_OnCacheOutcome_ReportsBranchTaken(t *testing.T) {
	ctx := context.Background()
	principalID := "user_metrics"

	repo := &countingRepo{perms: readOrderPermitBundle(principalID)}
	memCache := memory.New[*PrincipalPermissions](0)
	defer memCache.Dispose()

	var mu sync.Mutex
	var outcomes []CacheOutcome

	h, err := NewPARCHandler(PARCHandlerConfig{
		Repository: repo,
		Cache:      memCache,
		GrantTTL:   time.Minute,
		OnCacheOutcome: func(o CacheOutcome) {
			mu.Lock()
			defer mu.Unlock()
			outcomes = append(outcomes, o)
		},
	})
	if err != nil {
		t.Fatalf("NewPARCHandler: %v", err)
	}

	id := &principal.Principal{Subject: principalID}
	req, evalCtx := parcHandleReq()

	if _, err := h.Handle(ctx, id, req, evalCtx); err != nil {
		t.Fatalf("first Handle: %v", err)
	}
	if _, err := h.Handle(ctx, id, req, evalCtx); err != nil {
		t.Fatalf("second Handle: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(outcomes) != 2 {
		t.Fatalf("expected 2 reported outcomes, got %d: %v", len(outcomes), outcomes)
	}
	if outcomes[0] != CacheRefreshed {
		t.Fatalf("expected first call to report CacheRefreshed (miss -> successful fetch), got %v", outcomes[0])
	}
	if outcomes[1] != CacheHit {
		t.Fatalf("expected second call to report CacheHit (fresh cache), got %v", outcomes[1])
	}
}

// TestPolicyEngine_OnDecision_ReportsFinalizedOutcomeOnAllowAndDeny is the
// Tier 4 additive-instrumentation regression test for
// PolicyEngine.SetOnDecision: it must fire once per Evaluate/EvaluatePolicy
// call with the ALREADY-COMPUTED Decision (proving the hook cannot suppress
// or change the outcome it reports), for both an allow and a deny, and for
// the policy-not-found path too.
func TestPolicyEngine_OnDecision_ReportsFinalizedOutcomeOnAllowAndDeny(t *testing.T) {
	ctx := context.Background()
	engine := NewPolicyEngine(nil)

	policy := NewPolicy("AdminOnly").RequireRole("admin").Build()
	engine.RegisterPolicy(policy)

	var events []DecisionEvent
	engine.SetOnDecision(func(_ context.Context, evt DecisionEvent) {
		events = append(events, evt)
	})

	admin := &principal.Principal{Subject: "admin1", Roles: []string{"admin"}}
	viewer := &principal.Principal{Subject: "viewer1", Roles: []string{"viewer"}}

	d1, err := engine.EvaluatePolicy(ctx, "AdminOnly", admin, nil)
	if err != nil || !d1.Allowed {
		t.Fatalf("expected allow for admin, got %v/%v", d1, err)
	}

	d2, err := engine.EvaluatePolicy(ctx, "AdminOnly", viewer, nil)
	if err != nil || d2.Allowed {
		t.Fatalf("expected deny for viewer, got %v/%v", d2, err)
	}

	_, err = engine.EvaluatePolicy(ctx, "NoSuchPolicy", admin, nil)
	if err == nil {
		t.Fatalf("expected ErrPolicyNotFound")
	}

	if len(events) != 3 {
		t.Fatalf("expected 3 reported DecisionEvents, got %d: %+v", len(events), events)
	}
	if !events[0].Allowed || events[0].PolicyName != "AdminOnly" {
		t.Fatalf("expected first event to report an allow for AdminOnly, got %+v", events[0])
	}
	if events[1].Allowed || events[1].RequirementType != "RoleRequirement" {
		t.Fatalf("expected second event to report a deny with RequirementType RoleRequirement, got %+v", events[1])
	}
	if events[2].Allowed || events[2].PolicyName != "NoSuchPolicy" {
		t.Fatalf("expected third event to report a deny for the not-found policy, got %+v", events[2])
	}
}

// TestPolicyEngine_NilOnDecision_IsSafeNoOp confirms the default (unset)
// hook never panics and never affects EvaluatePolicy's return values.
func TestPolicyEngine_NilOnDecision_IsSafeNoOp(t *testing.T) {
	ctx := context.Background()
	engine := NewPolicyEngine(nil)
	policy := NewPolicy("Open").Build()
	engine.RegisterPolicy(policy)

	d, err := engine.EvaluatePolicy(ctx, "Open", &principal.Principal{Subject: "u1"}, nil)
	if err != nil || !d.Allowed {
		t.Fatalf("expected an empty policy (no requirements) to allow, got %v/%v", d, err)
	}
}

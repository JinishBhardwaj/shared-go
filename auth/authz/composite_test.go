package authz

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
)

// fixedRequirement/fixedResultHandler let tests register a synthetic
// requirement type whose Handle result (allowed, err) is dictated exactly
// by the test, including combinations no real built-in handler would ever
// produce (e.g. allowed=true alongside a non-nil error) -- deliberately,
// so these tests can prove the composite handlers' error-propagation rules
// hold even against an adversarial/misbehaving nested handler, not just
// against the well-behaved ones already in this package.
type fixedRequirement struct{ typ string }

func (r fixedRequirement) RequirementType() string { return r.typ }

type fixedResultHandler struct {
	typ     string
	allowed bool
	err     error

	mu    sync.Mutex
	calls int
}

func (h *fixedResultHandler) RequirementType() string { return h.typ }

func (h *fixedResultHandler) Handle(_ context.Context, _ *principal.Principal, _ Requirement, _ *EvaluationContext) (bool, error) {
	h.mu.Lock()
	h.calls++
	h.mu.Unlock()
	return h.allowed, h.err
}

func (h *fixedResultHandler) callCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls
}

func testPrincipal() *principal.Principal {
	return &principal.Principal{Subject: "u1"}
}

// --- NotRequirement -------------------------------------------------------

func TestNotRequirement_InvertsCleanResults(t *testing.T) {
	engine := NewPolicyEngine(nil)
	engine.RegisterHandler("AlwaysAllow", &fixedResultHandler{typ: "AlwaysAllow", allowed: true, err: nil})
	engine.RegisterHandler("AlwaysDeny", &fixedResultHandler{typ: "AlwaysDeny", allowed: false, err: nil})
	ctx := context.Background()
	p := testPrincipal()

	allowed, _, err := engine.evaluateRequirement(ctx, p, NotRequirement{Requirement: fixedRequirement{"AlwaysAllow"}}, &EvaluationContext{})
	if err != nil || allowed {
		t.Errorf("Not(AlwaysAllow) = (%v, %v), want (false, nil)", allowed, err)
	}

	allowed, _, err = engine.evaluateRequirement(ctx, p, NotRequirement{Requirement: fixedRequirement{"AlwaysDeny"}}, &EvaluationContext{})
	if err != nil || !allowed {
		t.Errorf("Not(AlwaysDeny) = (%v, %v), want (true, nil)", allowed, err)
	}
}

// TestNotRequirement_ErrorNeverInvertsToAllow is the critical fail-closed
// adversarial test for NotRequirement. The nested handler is deliberately
// configured with (allowed=false, err=someErr) -- the REALISTIC shape a
// real failing handler produces (PARCHandler.Handle, for example, always
// returns (false, err) on a repository/breaker failure, never (true, err))
// so this reproduces the actual bug this task's design guards against, not
// a shape that can't occur in practice.
//
// Confirmed red against the naive/buggy alternative implementation
// `return !allowed, err` (invert unconditionally, no early error check):
// for this exact input (allowed=false, err=someErr), that mutant computes
// !false = true and returns (true, someErr) -- a NotRequirement wrapping a
// failing/erroring inner check would report itself SATISFIED (allowed=true)
// purely because the inner check happened to deny-with-error rather than
// permit-with-error. The correct implementation must return (false,
// someErr) instead: the error propagates unchanged, and is never inverted
// into an allow.
func TestNotRequirement_ErrorNeverInvertsToAllow(t *testing.T) {
	backendErr := errors.New("backend: repository timeout")
	engine := NewPolicyEngine(nil)
	engine.RegisterHandler("Adversarial", &fixedResultHandler{typ: "Adversarial", allowed: false, err: backendErr})
	ctx := context.Background()
	p := testPrincipal()

	allowed, _, err := engine.evaluateRequirement(ctx, p, NotRequirement{Requirement: fixedRequirement{"Adversarial"}}, &EvaluationContext{})
	if allowed {
		t.Errorf("Not(erroring-and-denying requirement) allowed=true -- an error must NEVER invert to an allow, got (%v, %v)", allowed, err)
	}
	if !errors.Is(err, backendErr) {
		t.Errorf("expected the backend error to propagate unchanged from Not, got %v", err)
	}
}

func TestNotRequirement_NilNestedRequirementFailsClosed(t *testing.T) {
	engine := NewPolicyEngine(nil)
	ctx := context.Background()
	p := testPrincipal()

	allowed, _, err := engine.evaluateRequirement(ctx, p, NotRequirement{Requirement: nil}, &EvaluationContext{})
	if allowed || err != nil {
		t.Errorf("Not(nil) = (%v, %v), want (false, nil) -- a misconfigured Not must deny, never be vacuously satisfied", allowed, err)
	}
}

// --- AnyOfRequirement ------------------------------------------------------

func TestAnyOfRequirement_AllowsIfAnyBranchCleanlySucceeds(t *testing.T) {
	engine := NewPolicyEngine(nil)
	engine.RegisterHandler("AlwaysAllow", &fixedResultHandler{typ: "AlwaysAllow", allowed: true, err: nil})
	engine.RegisterHandler("AlwaysDeny", &fixedResultHandler{typ: "AlwaysDeny", allowed: false, err: nil})
	ctx := context.Background()
	p := testPrincipal()

	allowed, _, err := engine.evaluateRequirement(ctx, p, AnyOfRequirement{Requirements: []Requirement{
		fixedRequirement{"AlwaysDeny"},
		fixedRequirement{"AlwaysAllow"},
	}}, &EvaluationContext{})
	if err != nil || !allowed {
		t.Errorf("AnyOf(deny, allow) = (%v, %v), want (true, nil)", allowed, err)
	}
}

func TestAnyOfRequirement_DeniesIfAllBranchesDeny(t *testing.T) {
	engine := NewPolicyEngine(nil)
	engine.RegisterHandler("AlwaysDeny", &fixedResultHandler{typ: "AlwaysDeny", allowed: false, err: nil})
	ctx := context.Background()
	p := testPrincipal()

	allowed, _, err := engine.evaluateRequirement(ctx, p, AnyOfRequirement{Requirements: []Requirement{
		fixedRequirement{"AlwaysDeny"},
		fixedRequirement{"AlwaysDeny"},
	}}, &EvaluationContext{})
	if err != nil || allowed {
		t.Errorf("AnyOf(deny, deny) = (%v, %v), want (false, nil)", allowed, err)
	}
}

// TestAnyOfRequirement_ErroringBranchDoesNotBlockAGenuineSiblingSuccess
// proves one broken branch cannot prevent a genuinely succeeding sibling
// branch from granting access -- an error in one OR-branch must not be
// treated as if it poisoned the whole AnyOf.
func TestAnyOfRequirement_ErroringBranchDoesNotBlockAGenuineSiblingSuccess(t *testing.T) {
	backendErr := errors.New("backend: down")
	engine := NewPolicyEngine(nil)
	engine.RegisterHandler("Erroring", &fixedResultHandler{typ: "Erroring", allowed: false, err: backendErr})
	engine.RegisterHandler("AlwaysAllow", &fixedResultHandler{typ: "AlwaysAllow", allowed: true, err: nil})
	ctx := context.Background()
	p := testPrincipal()

	allowed, _, err := engine.evaluateRequirement(ctx, p, AnyOfRequirement{Requirements: []Requirement{
		fixedRequirement{"Erroring"},
		fixedRequirement{"AlwaysAllow"},
	}}, &EvaluationContext{})
	if err != nil || !allowed {
		t.Errorf("AnyOf(erroring, allow) = (%v, %v), want (true, nil) -- a broken branch must not block a genuine sibling success", allowed, err)
	}
}

// TestAnyOfRequirement_AllBranchesErrorFailsClosed is the critical
// fail-closed adversarial test for AnyOfRequirement: every branch errors
// (none cleanly succeeds), so the overall result MUST deny, never allow --
// confirmed against a deliberately adversarial nested handler that sets
// allowed=true alongside its error (simulating a misbehaving/buggy
// handler), proving evaluateAnyOf only ever inspects `allowed` for a
// branch whose err is nil, never using a mis-set allowed=true from an
// erroring branch as if it were a genuine permit.
func TestAnyOfRequirement_AllBranchesErrorFailsClosed(t *testing.T) {
	err1 := errors.New("branch 1 down")
	err2 := errors.New("branch 2 down")
	engine := NewPolicyEngine(nil)
	// Adversarial: this branch claims allowed=true WHILE ALSO erroring --
	// a real handler should never do this, but evaluateAnyOf must not
	// trust it regardless.
	engine.RegisterHandler("ErroringButClaimsAllowed", &fixedResultHandler{typ: "ErroringButClaimsAllowed", allowed: true, err: err1})
	engine.RegisterHandler("ErroringDenies", &fixedResultHandler{typ: "ErroringDenies", allowed: false, err: err2})
	ctx := context.Background()
	p := testPrincipal()

	allowed, _, err := engine.evaluateRequirement(ctx, p, AnyOfRequirement{Requirements: []Requirement{
		fixedRequirement{"ErroringButClaimsAllowed"},
		fixedRequirement{"ErroringDenies"},
	}}, &EvaluationContext{})
	if allowed {
		t.Errorf("AnyOf(all branches erroring, one adversarially claiming allowed=true) must deny, got allowed=true (err=%v)", err)
	}
	if err == nil {
		t.Errorf("expected a non-nil error to be reported when every branch errored, got nil")
	}
}

// --- AllOfRequirement ------------------------------------------------------

func TestAllOfRequirement_RequiresEveryBranch(t *testing.T) {
	engine := NewPolicyEngine(nil)
	engine.RegisterHandler("AlwaysAllow", &fixedResultHandler{typ: "AlwaysAllow", allowed: true, err: nil})
	ctx := context.Background()
	p := testPrincipal()

	allowed, _, err := engine.evaluateRequirement(ctx, p, AllOfRequirement{Requirements: []Requirement{
		fixedRequirement{"AlwaysAllow"},
		fixedRequirement{"AlwaysAllow"},
	}}, &EvaluationContext{})
	if err != nil || !allowed {
		t.Errorf("AllOf(allow, allow) = (%v, %v), want (true, nil)", allowed, err)
	}
}

func TestAllOfRequirement_ShortCircuitsOnFirstFailure(t *testing.T) {
	engine := NewPolicyEngine(nil)
	deny := &fixedResultHandler{typ: "AlwaysDeny", allowed: false, err: nil}
	neverReached := &fixedResultHandler{typ: "NeverReached", allowed: true, err: nil}
	engine.RegisterHandler("AlwaysDeny", deny)
	engine.RegisterHandler("NeverReached", neverReached)
	ctx := context.Background()
	p := testPrincipal()

	allowed, _, err := engine.evaluateRequirement(ctx, p, AllOfRequirement{Requirements: []Requirement{
		fixedRequirement{"AlwaysDeny"},
		fixedRequirement{"NeverReached"},
	}}, &EvaluationContext{})
	if err != nil || allowed {
		t.Errorf("AllOf(deny, allow) = (%v, %v), want (false, nil)", allowed, err)
	}
	if got := neverReached.callCount(); got != 0 {
		t.Errorf("expected AllOf to short-circuit on the first failure and never evaluate the second branch, but it was called %d times", got)
	}
}

func TestAllOfRequirement_ShortCircuitsOnFirstError(t *testing.T) {
	backendErr := errors.New("backend: down")
	engine := NewPolicyEngine(nil)
	erroring := &fixedResultHandler{typ: "Erroring", allowed: false, err: backendErr}
	neverReached := &fixedResultHandler{typ: "NeverReached", allowed: true, err: nil}
	engine.RegisterHandler("Erroring", erroring)
	engine.RegisterHandler("NeverReached", neverReached)
	ctx := context.Background()
	p := testPrincipal()

	allowed, _, err := engine.evaluateRequirement(ctx, p, AllOfRequirement{Requirements: []Requirement{
		fixedRequirement{"Erroring"},
		fixedRequirement{"NeverReached"},
	}}, &EvaluationContext{})
	if allowed {
		t.Errorf("AllOf(erroring, allow) must never allow, got allowed=true (err=%v)", err)
	}
	if !errors.Is(err, backendErr) {
		t.Errorf("expected the backend error to propagate from AllOf, got %v", err)
	}
	if got := neverReached.callCount(); got != 0 {
		t.Errorf("expected AllOf to short-circuit on the first error and never evaluate the second branch, but it was called %d times", got)
	}
}

// --- nesting ---------------------------------------------------------------

// TestCompositeRequirements_ArbitraryNesting proves AnyOf/AllOf/Not nest
// through ordinary recursion via evaluateRequirement, with no special
// casing needed: AnyOf(AllOf(deny, allow), Not(deny)) should evaluate as
// AnyOf(false, true) = true.
func TestCompositeRequirements_ArbitraryNesting(t *testing.T) {
	engine := NewPolicyEngine(nil)
	engine.RegisterHandler("AlwaysAllow", &fixedResultHandler{typ: "AlwaysAllow", allowed: true, err: nil})
	engine.RegisterHandler("AlwaysDeny", &fixedResultHandler{typ: "AlwaysDeny", allowed: false, err: nil})
	ctx := context.Background()
	p := testPrincipal()

	nested := AnyOfRequirement{Requirements: []Requirement{
		AllOfRequirement{Requirements: []Requirement{
			fixedRequirement{"AlwaysDeny"},
			fixedRequirement{"AlwaysAllow"},
		}}, // AllOf(deny, allow) = false
		NotRequirement{Requirement: fixedRequirement{"AlwaysDeny"}}, // Not(deny) = true
	}}

	allowed, _, err := engine.evaluateRequirement(ctx, p, nested, &EvaluationContext{})
	if err != nil || !allowed {
		t.Errorf("AnyOf(AllOf(deny,allow), Not(deny)) = (%v, %v), want (true, nil)", allowed, err)
	}
}

// TestPolicyBuilder_CompositeHelpers exercises the PolicyBuilder
// convenience methods end-to-end through PolicyEngine.EvaluatePolicy (not
// just evaluateRequirement directly), confirming the composite handlers
// are reachable via the normal named-policy path a real caller would use.
func TestPolicyBuilder_CompositeHelpers(t *testing.T) {
	engine := NewPolicyEngine(nil)
	engine.RegisterHandler("AlwaysAllow", &fixedResultHandler{typ: "AlwaysAllow", allowed: true, err: nil})
	engine.RegisterHandler("AlwaysDeny", &fixedResultHandler{typ: "AlwaysDeny", allowed: false, err: nil})

	policy := NewPolicy("EitherOr").
		RequireAnyOf(fixedRequirement{"AlwaysDeny"}, fixedRequirement{"AlwaysAllow"}).
		Build()
	engine.RegisterPolicy(policy)

	ctx := context.Background()
	p := testPrincipal()
	d, err := engine.EvaluatePolicy(ctx, "EitherOr", p, &EvaluationContext{})
	if err != nil || !d.Allowed {
		t.Errorf("EvaluatePolicy(EitherOr) = (%+v, %v), want Allowed=true, nil", d, err)
	}
}

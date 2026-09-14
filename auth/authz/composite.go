package authz

import (
	"context"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
)

// AllOfRequirement requires every nested Requirement to be satisfied (AND).
// Useful for composing requirements inside an AnyOfRequirement or a
// NotRequirement, where a Policy's own top-level AND semantics (every
// Requirement in Policy.Requirements must pass) aren't reachable as a
// single nested Requirement value.
type AllOfRequirement struct {
	Requirements []Requirement
}

func (r AllOfRequirement) RequirementType() string { return "AllOfRequirement" }

// AnyOfRequirement requires at least one nested Requirement to be
// satisfied (OR). Tier 4 gap-analysis-final.md line 129: "Composite
// requirements — AnyOf/AllOf/Not, recursing into the engine. OR is
// inexpressible today; highest-value pattern addition."
type AnyOfRequirement struct {
	Requirements []Requirement
}

func (r AnyOfRequirement) RequirementType() string { return "AnyOfRequirement" }

// NotRequirement is satisfied iff the nested Requirement is NOT satisfied.
//
// Security-critical inversion rule, enforced by NotRequirementHandler
// below and covered by adversarial tests: a nested Requirement whose
// evaluation ERRORS (e.g. a PARCHandler repository timeout) is never
// treated as "not satisfied" for the purpose of the inversion. Inverting
// an error into an allow would turn any transient backend failure behind
// a Not(...) into a silent bypass -- exactly the fail-open shape Tier 0
// exists to eliminate elsewhere in this package. An error always
// propagates unchanged; only a clean (bool, nil) result is ever inverted.
type NotRequirement struct {
	Requirement Requirement
}

func (r NotRequirement) RequirementType() string { return "NotRequirement" }

// registerCompositeHandlers registers the three built-in composite
// handlers (AllOf/AnyOf/Not) on engine, referencing engine itself so they
// can recurse back into it via evaluateRequirement. Called from both
// NewAuthorizationService and NewPolicyEngine, after engine has already
// been allocated -- a self-referential registration is safe here because
// Go allows a struct to hold a pointer to itself once it exists; nothing
// dereferences engine until a real Evaluate/EvaluatePolicy call happens,
// long after construction completes.
func registerCompositeHandlers(engine *PolicyEngine) {
	engine.handlers["AllOfRequirement"] = &compositeHandler{engine: engine, mode: compositeAllOf}
	engine.handlers["AnyOfRequirement"] = &compositeHandler{engine: engine, mode: compositeAnyOf}
	engine.handlers["NotRequirement"] = &compositeHandler{engine: engine, mode: compositeNot}
}

// compositeHandler implements RequirementHandler for AllOf/AnyOf/Not. It
// holds a pointer back to the *PolicyEngine it was registered on so nested
// Requirements can be dispatched through the exact same handler-lookup +
// named-CustomRequirement-fallback logic PolicyEngine.Evaluate's own loop
// uses (see PolicyEngine.evaluateRequirement) -- this is what lets
// composite requirements nest arbitrarily deep (AnyOf containing AllOf
// containing Not, etc.) via ordinary recursion, with no special-casing.
type compositeHandler struct {
	engine *PolicyEngine
	mode   compositeMode
}

type compositeMode int

const (
	compositeAllOf compositeMode = iota
	compositeAnyOf
	compositeNot
)

func (h *compositeHandler) RequirementType() string {
	switch h.mode {
	case compositeAllOf:
		return "AllOfRequirement"
	case compositeAnyOf:
		return "AnyOfRequirement"
	default:
		return "NotRequirement"
	}
}

func (h *compositeHandler) Handle(ctx context.Context, p *principal.Principal, req Requirement, evalCtx *EvaluationContext) (bool, error) {
	switch h.mode {
	case compositeAllOf:
		ar, ok := req.(AllOfRequirement)
		if !ok {
			return false, nil
		}
		return h.evaluateAllOf(ctx, p, ar.Requirements, evalCtx)

	case compositeAnyOf:
		ar, ok := req.(AnyOfRequirement)
		if !ok {
			return false, nil
		}
		return h.evaluateAnyOf(ctx, p, ar.Requirements, evalCtx)

	default: // compositeNot
		nr, ok := req.(NotRequirement)
		if !ok {
			return false, nil
		}
		if nr.Requirement == nil {
			// A Not with nothing to invert can never be satisfied --
			// fail closed rather than treat a misconfigured/nil nested
			// requirement as vacuously true.
			return false, nil
		}
		allowed, _, err := h.engine.evaluateRequirement(ctx, p, nr.Requirement, evalCtx)
		if err != nil {
			// THE load-bearing rule (see NotRequirement's doc comment):
			// an error from the nested requirement propagates UNCHANGED.
			// It is never inverted into an allow, regardless of what
			// `allowed` happens to hold alongside it.
			return false, err
		}
		return !allowed, nil
	}
}

// evaluateAllOf mirrors PolicyEngine.Evaluate's own top-level AND loop
// exactly: short-circuits on the first requirement that denies OR errors.
func (h *compositeHandler) evaluateAllOf(ctx context.Context, p *principal.Principal, reqs []Requirement, evalCtx *EvaluationContext) (bool, error) {
	for _, nested := range reqs {
		allowed, _, err := h.engine.evaluateRequirement(ctx, p, nested, evalCtx)
		if err != nil {
			return false, err
		}
		if !allowed {
			return false, nil
		}
	}
	return true, nil
}

// evaluateAnyOf requires at least one nested requirement to cleanly
// succeed. A requirement that ERRORS is skipped -- its error is
// remembered only so it can be returned if every branch either errors or
// denies, never treated as a permit. This is deliberate and load-bearing:
// `allowed` is only ever inspected for branches where `err == nil`, so a
// branch that errored can never be the one whose (mis-set) `allowed`
// value causes an incorrect permit, and one broken branch can never
// prevent a genuinely succeeding sibling branch from granting access.
func (h *compositeHandler) evaluateAnyOf(ctx context.Context, p *principal.Principal, reqs []Requirement, evalCtx *EvaluationContext) (bool, error) {
	var lastErr error
	for _, nested := range reqs {
		allowed, _, err := h.engine.evaluateRequirement(ctx, p, nested, evalCtx)
		if err != nil {
			lastErr = err
			continue
		}
		if allowed {
			return true, nil
		}
	}
	return false, lastErr
}

package authz

import (
	"context"
	"testing"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
)

// G7 / Tier1 line 95 -- "Generic handler registry": NewAuthorizationService
// used to type-switch on *PARCHandler and silently discard every other
// caller-supplied RequirementHandler, so a custom, non-PARC handler passed
// through the variadic never actually governed any decision -- any Policy
// requiring it would deny via "no handler registered for requirement type",
// never via the handler's own logic. This test proves a caller-supplied
// handler for a brand-new requirement type is genuinely reachable and its
// result genuinely governs the decision (both directions: grant and deny),
// not just silently dropped.
type alwaysDenyRequirement struct{}

func (alwaysDenyRequirement) RequirementType() string { return "AlwaysDenyRequirement" }

type toggleHandler struct{ allow bool }

func (h *toggleHandler) RequirementType() string { return "AlwaysDenyRequirement" }
func (h *toggleHandler) Handle(ctx context.Context, p *principal.Principal, req Requirement, evalCtx *EvaluationContext) (bool, error) {
	return h.allow, nil
}

func TestNewAuthorizationService_RegistersNonPARCCustomHandler(t *testing.T) {
	opts := NewAuthorizationOptions()
	opts.AddPolicy("CustomGate", Policy{Requirements: []Requirement{alwaysDenyRequirement{}}})

	deny := &toggleHandler{allow: false}
	engine := NewAuthorizationService(opts, deny)

	p := &principal.Principal{Subject: "u1"}
	d, err := engine.EvaluatePolicy(context.Background(), "CustomGate", p, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Allowed {
		t.Fatalf("expected deny (handler.allow=false) to actually govern the decision, got allowed")
	}
	if d.Reason == `no handler registered for requirement type 'AlwaysDenyRequirement'` {
		t.Fatalf("handler was silently discarded -- decision fell through to the no-handler-registered path, not the handler's own logic")
	}

	allow := &toggleHandler{allow: true}
	engine2 := NewAuthorizationService(opts, allow)
	d2, err := engine2.EvaluatePolicy(context.Background(), "CustomGate", p, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !d2.Allowed {
		t.Fatalf("expected allow (handler.allow=true) to actually govern the decision, got denied: %s", d2.Reason)
	}
}

// TestEvaluate_NamedCustomRequirementResolvesToHandler is the fail-closed
// regression proof for the second half of Tier 1 line 95: a *named*
// CustomRequirement's own RequirementType() returns its Name (e.g. "MustOwnResource"),
// which never equals the "CustomRequirement" key any handler is registered
// under -- before Evaluate's fallback, every named CustomRequirement denied
// unconditionally regardless of what its Func returned, silently. This test
// proves the Func is now genuinely reached, in both directions.
func TestEvaluate_NamedCustomRequirementResolvesToHandler(t *testing.T) {
	engine := NewPolicyEngine()

	allowPolicy := Policy{
		Name: "NamedAllow",
		Requirements: []Requirement{
			CustomRequirement{
				Name: "MustBeAdmin",
				Func: func(ctx context.Context, req Request) bool {
					return req.Principal.ID == "admin_user"
				},
			},
		},
	}
	engine.RegisterPolicy(allowPolicy)

	admin := &principal.Principal{Subject: "admin_user"}
	nonAdmin := &principal.Principal{Subject: "regular_user"}

	d, err := engine.EvaluatePolicy(context.Background(), "NamedAllow", admin, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !d.Allowed {
		t.Fatalf("expected named CustomRequirement's Func(admin_user)=true to allow, got denied: %s", d.Reason)
	}

	d2, err := engine.EvaluatePolicy(context.Background(), "NamedAllow", nonAdmin, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d2.Allowed {
		t.Fatalf("expected named CustomRequirement's Func(regular_user)=false to deny, got allowed")
	}
	if d2.Reason == `no handler registered for requirement type 'MustBeAdmin'` {
		t.Fatalf("named CustomRequirement fell through to the no-handler-registered path instead of its own Func's result")
	}
}

package authz

import (
	"context"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
)

// Requirement represents a single authorization condition or assertion, mirroring ASP.NET Core IAuthorizationRequirement.
type Requirement interface {
	RequirementType() string
}

// AuthorizationRequirement is an ASP.NET Core naming alias for Requirement.
type AuthorizationRequirement = Requirement

// PARCRequirement enforces that the principal has permission to perform an Action on a ResourceType.
type PARCRequirement struct {
	Action       string
	ResourceType string
}

func (r PARCRequirement) RequirementType() string { return "PARCRequirement" }

// ScopeRequirement enforces required OAuth scopes.
type ScopeRequirement struct {
	Scopes     []string
	RequireAll bool
}

func (r ScopeRequirement) RequirementType() string { return "ScopeRequirement" }

// RoleRequirement enforces required roles.
type RoleRequirement struct {
	Roles      []string
	RequireAll bool
}

func (r RoleRequirement) RequirementType() string { return "RoleRequirement" }

// UserPresentRequirement requires an interactive user flow (PKCE or Device Flow).
type UserPresentRequirement struct{}

func (r UserPresentRequirement) RequirementType() string { return "UserPresentRequirement" }

// M2MRequirement requires a Machine-to-Machine flow (Client Credentials or API Key).
type M2MRequirement struct{}

func (r M2MRequirement) RequirementType() string { return "M2MRequirement" }

// MethodRequirement enforces that the principal authenticated via one of the
// allowed authentication methods / OAuth flows. Moved from the former
// authn/guards.go (gap-analysis-final.md §3.8 step 6) so scope/role/method
// gating has exactly one implementation instead of a second copy living in
// authn as raw gin middleware.
type MethodRequirement struct {
	Methods []principal.AuthMethod
}

func (r MethodRequirement) RequirementType() string { return "MethodRequirement" }

// CustomRequirement allows inline functional assertions.
type CustomRequirement struct {
	Name string
	Func func(ctx context.Context, req Request) bool
}

func (r CustomRequirement) RequirementType() string {
	if r.Name != "" {
		return r.Name
	}
	return "CustomRequirement"
}

// Policy combines one or more requirements that must all succeed (AND logic), mirroring ASP.NET Core AuthorizationPolicy.
type Policy struct {
	Name         string
	Requirements []Requirement
}

// AuthorizationPolicy is an ASP.NET Core naming alias for Policy.
type AuthorizationPolicy = Policy

// PolicyBuilder provides a fluent API for building policies, mirroring ASP.NET Core AuthorizationPolicyBuilder.
type PolicyBuilder struct {
	policy Policy
}

// AuthorizationPolicyBuilder is an ASP.NET Core naming alias for PolicyBuilder.
type AuthorizationPolicyBuilder = PolicyBuilder

// NewPolicy starts building a named authorization policy.
func NewPolicy(name string) *PolicyBuilder {
	return &PolicyBuilder{
		policy: Policy{
			Name:         name,
			Requirements: nil,
		},
	}
}

// NewPolicyBuilder creates an AuthorizationPolicyBuilder (mirrors ASP.NET Core AuthorizationPolicyBuilder).
func NewPolicyBuilder(name ...string) *PolicyBuilder {
	policyName := ""
	if len(name) > 0 {
		policyName = name[0]
	}
	return NewPolicy(policyName)
}

// RequireAuthenticatedUser asserts that the request has an authenticated caller.
func (b *PolicyBuilder) RequireAuthenticatedUser() *PolicyBuilder {
	return b.AddRequirement(CustomRequirement{
		Func: func(ctx context.Context, req Request) bool {
			return req.Principal.ID != ""
		},
	})
}

// RequirePARC asserts that the caller has PARC permission for the given action and resource type.
func (b *PolicyBuilder) RequirePARC(action, resourceType string) *PolicyBuilder {
	b.policy.Requirements = append(b.policy.Requirements, PARCRequirement{
		Action:       action,
		ResourceType: resourceType,
	})
	return b
}

// RequireScope asserts that the caller has ALL specified scopes.
func (b *PolicyBuilder) RequireScope(scopes ...string) *PolicyBuilder {
	b.policy.Requirements = append(b.policy.Requirements, ScopeRequirement{
		Scopes:     scopes,
		RequireAll: true,
	})
	return b
}

// RequireAnyScope asserts that the caller has AT LEAST ONE of the candidate scopes.
func (b *PolicyBuilder) RequireAnyScope(scopes ...string) *PolicyBuilder {
	b.policy.Requirements = append(b.policy.Requirements, ScopeRequirement{
		Scopes:     scopes,
		RequireAll: false,
	})
	return b
}

// RequireRole asserts that the caller has ALL the specified role(s).
func (b *PolicyBuilder) RequireRole(roles ...string) *PolicyBuilder {
	b.policy.Requirements = append(b.policy.Requirements, RoleRequirement{
		Roles:      roles,
		RequireAll: true,
	})
	return b
}

// RequireAnyRole asserts that the caller has AT LEAST ONE of the candidate roles.
func (b *PolicyBuilder) RequireAnyRole(roles ...string) *PolicyBuilder {
	b.policy.Requirements = append(b.policy.Requirements, RoleRequirement{
		Roles:      roles,
		RequireAll: false,
	})
	return b
}

// RequireUser asserts that an interactive end user is present.
func (b *PolicyBuilder) RequireUser() *PolicyBuilder {
	b.policy.Requirements = append(b.policy.Requirements, UserPresentRequirement{})
	return b
}

// RequireM2M asserts that the caller is an automated M2M client.
func (b *PolicyBuilder) RequireM2M() *PolicyBuilder {
	b.policy.Requirements = append(b.policy.Requirements, M2MRequirement{})
	return b
}

// RequireMethod asserts that the caller authenticated via one of the allowed
// authentication methods / OAuth flows.
func (b *PolicyBuilder) RequireMethod(methods ...principal.AuthMethod) *PolicyBuilder {
	b.policy.Requirements = append(b.policy.Requirements, MethodRequirement{
		Methods: methods,
	})
	return b
}

// RequireAnyOf asserts that at least one of the given requirements is
// satisfied (OR). See AnyOfRequirement.
func (b *PolicyBuilder) RequireAnyOf(reqs ...Requirement) *PolicyBuilder {
	b.policy.Requirements = append(b.policy.Requirements, AnyOfRequirement{Requirements: reqs})
	return b
}

// RequireAllOf asserts that every one of the given requirements is
// satisfied (AND). See AllOfRequirement -- mainly useful nested inside
// RequireAnyOf/RequireNot, since Policy's own top-level Requirements are
// already ANDed.
func (b *PolicyBuilder) RequireAllOf(reqs ...Requirement) *PolicyBuilder {
	b.policy.Requirements = append(b.policy.Requirements, AllOfRequirement{Requirements: reqs})
	return b
}

// RequireNot asserts that the given requirement is NOT satisfied. See
// NotRequirement's doc comment for the error-propagation rule that keeps
// this fail-closed.
func (b *PolicyBuilder) RequireNot(req Requirement) *PolicyBuilder {
	b.policy.Requirements = append(b.policy.Requirements, NotRequirement{Requirement: req})
	return b
}

// AddRequirement adds an arbitrary requirement to the policy.
func (b *PolicyBuilder) AddRequirement(req Requirement) *PolicyBuilder {
	b.policy.Requirements = append(b.policy.Requirements, req)
	return b
}

// Build finalizes and returns the Policy.
func (b *PolicyBuilder) Build() Policy {
	return b.policy
}

package authz

import (
	"context"
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

// RequireRole asserts that the caller has the specified role(s).
func (b *PolicyBuilder) RequireRole(roles ...string) *PolicyBuilder {
	b.policy.Requirements = append(b.policy.Requirements, RoleRequirement{
		Roles:      roles,
		RequireAll: true,
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

// AddRequirement adds an arbitrary requirement to the policy.
func (b *PolicyBuilder) AddRequirement(req Requirement) *PolicyBuilder {
	b.policy.Requirements = append(b.policy.Requirements, req)
	return b
}

// Build finalizes and returns the Policy.
func (b *PolicyBuilder) Build() Policy {
	return b.policy
}

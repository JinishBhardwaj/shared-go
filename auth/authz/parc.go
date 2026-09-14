package authz

import (
	"path"
	"strings"
	"time"
)

// Effect defines whether a rule permits or denies access.
type Effect string

const (
	EffectPermit Effect = "permit"
	EffectDeny   Effect = "deny"
)

// Principal represents the authenticated security principal attempting the action.
type Principal struct {
	ID         string         `json:"id"`
	ClientID   string         `json:"client_id,omitempty"`
	Roles      []string       `json:"roles,omitempty"`
	Scopes     []string       `json:"scopes,omitempty"`
	AuthMethod string         `json:"auth_method,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// Action represents the verb or operation being attempted.
type Action struct {
	Name       string `json:"name"`        // Logical action name: "read", "create", "delete", "approve"
	HTTPMethod string `json:"http_method"` // HTTP verb: "GET", "POST", etc.
}

// Resource represents the domain entity being accessed.
type Resource struct {
	Type       string         `json:"type"`                 // e.g. "report", "user", "billing", "document"
	ID         string         `json:"id"`                   // e.g. "rep_1234", "usr_999", or "*"
	TenantID   string         `json:"tenant_id,omitempty"`  // multi-tenant isolation ID
	Attributes map[string]any `json:"attributes,omitempty"` // entity attributes for ABAC rules
}

// Context represents runtime environmental and ambient metadata.
type Context struct {
	ClientIP  string            `json:"client_ip,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
	Headers   map[string]string `json:"headers,omitempty"`
	Data      map[string]any    `json:"data,omitempty"`
}

// Request represents the complete PARC evaluation context.
type Request struct {
	Principal Principal `json:"principal"`
	Action    Action    `json:"action"`
	Resource  Resource  `json:"resource"`
	Context   Context   `json:"context"`
}

// Decision represents the outcome of a policy evaluation.
type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

// PermissionRule defines a fine-grained authorization rule stored in the local database.
type PermissionRule struct {
	ActionPattern     string `json:"action_pattern"`      // "read", "write", "reports:*", "*"
	ResourceType      string `json:"resource_type"`       // "report", "order", "*"
	ResourceIDPattern string `json:"resource_id_pattern"` // "rep_*", "123", "*"
	TenantID          string `json:"tenant_id,omitempty"` // empty or "*" means all tenants
	Effect            Effect `json:"effect"`              // "permit" or "deny"
}

// Matches evaluates whether this rule applies to the incoming PARC Request.
func (r *PermissionRule) Matches(req Request) bool {
	// 1. Check Action
	if !matchGlob(r.ActionPattern, req.Action.Name) && !matchGlob(r.ActionPattern, req.Action.HTTPMethod) {
		return false
	}

	// 2. Check Resource Type
	if !matchGlob(r.ResourceType, req.Resource.Type) {
		return false
	}

	// 3. Check Resource ID
	if !matchGlob(r.ResourceIDPattern, req.Resource.ID) {
		return false
	}

	// 4. Check Tenant ID if specified
	if r.TenantID != "" && r.TenantID != "*" && req.Resource.TenantID != "" {
		if r.TenantID != req.Resource.TenantID {
			return false
		}
	}

	return true
}

// PrincipalPermissions represents the bundle of permission rules assigned to a principal.
type PrincipalPermissions struct {
	PrincipalID string           `json:"principal_id"`
	Rules       []PermissionRule `json:"rules"`
}

// Evaluate applies deny-overrides logic across all rules for this principal.
func (p *PrincipalPermissions) Evaluate(req Request) Decision {
	if p == nil || len(p.Rules) == 0 {
		return Decision{Allowed: false, Reason: "no permissions found for principal"}
	}

	matchedPermit := false

	for _, rule := range p.Rules {
		if rule.Matches(req) {
			if rule.Effect == EffectDeny {
				return Decision{
					Allowed: false,
					Reason:  "explicitly denied by policy rule",
				}
			}
			if rule.Effect == EffectPermit {
				matchedPermit = true
			}
		}
	}

	if matchedPermit {
		return Decision{Allowed: true}
	}

	return Decision{
		Allowed: false,
		Reason:  "no matching permit rule found for action on resource",
	}
}

// matchGlob performs wildcard pattern matching supporting '*' syntax.
func matchGlob(pattern, val string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	if pattern == val {
		return true
	}
	matched, err := path.Match(pattern, val)
	if err != nil {
		return strings.EqualFold(pattern, val)
	}
	return matched
}

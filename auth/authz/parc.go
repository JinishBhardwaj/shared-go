package authz

import (
	"path"
	"strings"
	"sync"
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
	// 1. Check Action. Tier 1 line 98 ("Unify action semantics"): ActionPattern
	// is matched ONLY against the logical Action.Name -- never against
	// Action.HTTPMethod. Before this fix, a rule matched if EITHER field
	// matched, so a rule authored against the logical action vocabulary
	// ("read") also granted for the raw HTTP verb ("GET") and vice versa,
	// letting a rule written for one action model silently grant the other.
	// Action.HTTPMethod remains on the struct for logging/observability only.
	if !matchGlob(r.ActionPattern, req.Action.Name) {
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

	// 4. Check Tenant ID if the rule pins one. Tier 0 #1: an empty rule
	// TenantID (or the literal "*") means "any tenant", but once a rule DOES
	// pin a tenant, a request whose Resource.TenantID is empty must be
	// treated as "tenant unknown/omitted" -- never as "any tenant is fine".
	// Fail closed: only an exact tenant match satisfies a pinned rule.
	if r.TenantID != "" && r.TenantID != "*" {
		if req.Resource.TenantID != r.TenantID {
			return false
		}
	}

	return true
}

// PrincipalPermissions represents the bundle of permission rules assigned to a principal.
type PrincipalPermissions struct {
	PrincipalID string           `json:"principal_id"`
	Rules       []PermissionRule `json:"rules"`

	// FetchedAt records when this bundle was last fetched from the
	// PermissionRepository. Populated by PARCHandler.Handle, not by
	// PermissionRepository implementations themselves (MemoryPermissionRepository
	// leaves it zero-valued; PARCHandler stamps it on every successful
	// repository fetch). Used to distinguish a "fresh" cached bundle
	// (within GrantTTL of FetchedAt) from a "stale" one (past GrantTTL but
	// not yet evicted from the cache, whose hard TTL is PARCHandlerConfig.StaleTTL)
	// for the Tier 3 stale-while-revalidate behavior -- see PARCHandler.Handle.
	// Metadata only: never consulted by Matches/Evaluate, so it has no
	// effect on authorization outcomes by itself.
	FetchedAt time.Time `json:"fetched_at,omitempty"`

	// idxOnce/idx implement Tier 3 "precompile rule globs and index rules
	// by resource type at bundle load" (gap-analysis-final.md: "path.Match
	// currently runs per rule per request"). Built lazily, at most once per
	// *PrincipalPermissions instance (guarded by idxOnce), the first time
	// Evaluate is called against it -- which is effectively "at bundle
	// load" in practice, since PARCHandler caches and reuses this exact
	// pointer across every request that hits it within GrantTTL/StaleTTL,
	// so the one-time index-build cost amortizes across many requests.
	// Deliberately unexported and built from a private helper, never from
	// exported API: PrincipalPermissions is always constructed and passed
	// around by pointer everywhere in this codebase (confirmed by grep
	// before adding this field -- every existing construction site uses
	// &PrincipalPermissions{...}), so adding an unexported sync.Once here
	// carries no copylocks risk.
	//
	// This does NOT change PermissionRule.Matches or matchGlob at all --
	// both are left completely untouched, so every existing Tier 0 #1/#2
	// regression test (which calls them directly) continues to exercise
	// the exact same code, unmodified. Evaluate below is the only thing
	// that changes, and it is provably equivalent to the old exhaustive
	// per-request re-scan: see index()'s doc comment for why.
	idxOnce sync.Once
	idx     *ruleIndex
}

// patternKind classifies a glob pattern's shape once, so the hot path can
// skip path.Match entirely for the two dominant real-world cases (an exact
// literal, or the bare wildcard "*") instead of invoking it -- and
// re-parsing the pattern -- on every single request. This mirrors
// matchGlob's own fail-closed rules exactly (see matchGlob's doc comment):
// an empty pattern never matches (Tier 0 #2), "*" always matches, anything
// else is compared either as an exact literal (no glob metacharacters
// present) or via path.Match.
type patternKind int

const (
	patternEmpty patternKind = iota
	patternWildcard
	patternLiteral
	patternGlob
)

// compiledPattern is a pattern string plus its precomputed patternKind.
// compilePattern/match implement exactly the same fail-closed semantics as
// matchGlob (Tier 0 #2) -- they are a precompiled restatement of it, not a
// different rule. matchGlob itself is left untouched and remains the
// single source of truth for the actual matching semantics; the tests
// below cross-check compiledPattern.match against matchGlob directly so
// the two can never silently drift apart.
type compiledPattern struct {
	raw  string
	kind patternKind
}

func compilePattern(raw string) compiledPattern {
	switch {
	case raw == "":
		return compiledPattern{raw: raw, kind: patternEmpty}
	case raw == "*":
		return compiledPattern{raw: raw, kind: patternWildcard}
	case !strings.ContainsAny(raw, "*?["):
		return compiledPattern{raw: raw, kind: patternLiteral}
	default:
		return compiledPattern{raw: raw, kind: patternGlob}
	}
}

func (cp compiledPattern) match(val string) bool {
	switch cp.kind {
	case patternEmpty:
		return false
	case patternWildcard:
		return true
	case patternLiteral:
		return cp.raw == val
	default:
		matched, err := path.Match(cp.raw, val)
		if err != nil {
			return strings.EqualFold(cp.raw, val)
		}
		return matched
	}
}

// compiledRule pairs a *PermissionRule (a pointer into the owning
// PrincipalPermissions.Rules slice -- never copied) with its precompiled
// ActionPattern/ResourceIDPattern. ResourceType is deliberately NOT
// precompiled here: index() below only ever places a compiledRule into a
// bucket whose membership already guarantees the ResourceType comparison's
// outcome (see index()'s doc comment), except the fallback bucket, which
// still calls matchGlob directly on ResourceType exactly as Matches always
// has.
type compiledRule struct {
	rule              *PermissionRule
	actionPattern     compiledPattern
	resourceIDPattern compiledPattern
}

// matches reproduces PermissionRule.Matches's four checks exactly (action,
// resource type, resource ID, tenant), in a different but outcome-
// equivalent order, using the precompiled patterns for action/resource-ID
// and skipping the resource-type check when the caller (index-bucket
// iteration in Evaluate) has already guaranteed it via bucket membership.
func (cr *compiledRule) matches(req Request, resourceTypeConfirmed bool) bool {
	if !cr.actionPattern.match(req.Action.Name) {
		return false
	}
	if !resourceTypeConfirmed && !matchGlob(cr.rule.ResourceType, req.Resource.Type) {
		return false
	}
	if !cr.resourceIDPattern.match(req.Resource.ID) {
		return false
	}
	// Tier 0 #1: identical tenant fail-closed logic to PermissionRule.Matches.
	if cr.rule.TenantID != "" && cr.rule.TenantID != "*" {
		if req.Resource.TenantID != cr.rule.TenantID {
			return false
		}
	}
	return true
}

// ruleIndex partitions a PrincipalPermissions bundle's rules by
// ResourceType at build time (Tier 3 "index rules by resource type at
// bundle load"), so Evaluate only ever scans the rules that could possibly
// apply to the request's actual Resource.Type instead of the full rule set
// on every call.
//
// Three buckets, each exhaustive and non-overlapping:
//   - byType: rules whose ResourceType is an exact literal string (the
//     common case for a real rule set) -- keyed by that literal, so
//     Evaluate does a single map lookup for req.Resource.Type instead of a
//     per-rule comparison.
//   - wildcard: rules whose ResourceType is literally "*" -- these apply
//     to every request regardless of Resource.Type, so they are always
//     scanned in addition to whichever byType bucket matches.
//   - fallback: anything else -- an empty ResourceType (can never match
//     any request, per Tier 0 #2/matchGlob, but is kept here rather than
//     silently dropped, so a defensive future change to matchGlob's
//     semantics can't silently start missing rules this index used to
//     correctly exclude) or a ResourceType containing real glob
//     metacharacters (e.g. "rep*") -- scanned in full every time via the
//     exact same matchGlob call Matches itself would have made, so
//     correctness for this bucket is identical to the pre-index behavior,
//     never optimized, only ever exact.
type ruleIndex struct {
	byType   map[string][]*compiledRule
	wildcard []*compiledRule
	fallback []*compiledRule
}

// index lazily builds and caches p's ruleIndex, at most once per instance.
func (p *PrincipalPermissions) index() *ruleIndex {
	p.idxOnce.Do(func() {
		idx := &ruleIndex{byType: make(map[string][]*compiledRule)}
		for i := range p.Rules {
			r := &p.Rules[i]
			cr := &compiledRule{
				rule:              r,
				actionPattern:     compilePattern(r.ActionPattern),
				resourceIDPattern: compilePattern(r.ResourceIDPattern),
			}
			switch {
			case r.ResourceType == "*":
				idx.wildcard = append(idx.wildcard, cr)
			case r.ResourceType != "" && !strings.ContainsAny(r.ResourceType, "*?["):
				idx.byType[r.ResourceType] = append(idx.byType[r.ResourceType], cr)
			default:
				idx.fallback = append(idx.fallback, cr)
			}
		}
		p.idx = idx
	})
	return p.idx
}

// scanBucket applies deny-overrides logic across bucket, exactly as the
// pre-index Evaluate's single loop did: an explicit deny match returns
// immediately (deny=true); otherwise permit reports whether at least one
// permit rule in this bucket matched.
func scanBucket(bucket []*compiledRule, req Request, resourceTypeConfirmed bool) (deny bool, permit bool) {
	for _, cr := range bucket {
		if cr.matches(req, resourceTypeConfirmed) {
			if cr.rule.Effect == EffectDeny {
				return true, false
			}
			if cr.rule.Effect == EffectPermit {
				permit = true
			}
		}
	}
	return false, permit
}

// Evaluate applies deny-overrides logic across all rules for this principal.
//
// Tier 3 "precompile rule globs and index rules by resource type at bundle
// load": rather than re-scanning every rule in p.Rules and re-parsing every
// glob pattern on every single call (the pre-existing behavior, still
// exactly what PermissionRule.Matches/matchGlob do when called directly --
// neither was modified by this change), Evaluate now consults a lazily-
// built, per-instance index (see index()'s doc comment) that narrows the
// scan to only the rules that could possibly apply to req.Resource.Type,
// with each rule's Action/ResourceID patterns precompiled once instead of
// re-parsed per call.
//
// Outcome-equivalence to the old exhaustive scan: the old loop iterated
// p.Rules in slice order and returned as soon as it found an EffectDeny
// match, or (if none) reported Allowed:true iff at least one EffectPermit
// rule matched anywhere. Decision's Reason field is always one of three
// fixed strings, never rule-specific -- so the result is identical
// regardless of which bucket, or which rule within a bucket, happens to be
// the one that triggers a deny or permit; only the *order* of internal
// iteration differs (by-resource-type bucket, then wildcard, then
// fallback, instead of original slice order), never the outcome. Every
// rule in p.Rules ends up in exactly one bucket (index()'s three cases are
// exhaustive and mutually exclusive), so no rule is ever skipped or
// double-counted.
func (p *PrincipalPermissions) Evaluate(req Request) Decision {
	if p == nil || len(p.Rules) == 0 {
		return Decision{Allowed: false, Reason: "no permissions found for principal"}
	}

	idx := p.index()

	matchedPermit := false
	buckets := []struct {
		rules     []*compiledRule
		confirmed bool
	}{
		{idx.byType[req.Resource.Type], true},
		{idx.wildcard, true},
		{idx.fallback, false},
	}
	for _, b := range buckets {
		deny, permit := scanBucket(b.rules, req, b.confirmed)
		if deny {
			return Decision{
				Allowed: false,
				Reason:  "explicitly denied by policy rule",
			}
		}
		if permit {
			matchedPermit = true
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
// Tier 0 #2: only the literal "*" means wildcard. An empty pattern (e.g. a
// blank ActionPattern/ResourceIDPattern from a corrupted or zero-valued DB
// row) must never match anything -- treating "" as "*" silently turns a
// missing rule field into a universal grant.
func matchGlob(pattern, val string) bool {
	if pattern == "" {
		return false
	}
	if pattern == "*" {
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

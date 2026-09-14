package authz

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
	"github.com/JinishBhardwaj/shared-go/cache"
	"github.com/JinishBhardwaj/shared-go/cache/memory"
)

var (
	ErrPolicyNotFound = errors.New("authz: policy not found")
	ErrNilPrincipal   = errors.New("authz: principal is nil")
)

// EvaluationContext contains the runtime request context for authorization evaluation.
type EvaluationContext struct {
	Resource Resource
	Action   Action
	Context  Context

	// mappedPrincipal / mappedPrincipalFor cache the PARC-shaped Principal
	// (the struct defined below, distinct from principal.Principal) mapped
	// from the request's principal.Principal. Tier 2 "map the principal
	// once" (gap-analysis-final.md line 106): PARCHandler.Handle and
	// CustomRequirementHandler.Handle used to allocate a fresh Principal{...}
	// (two allocations plus a map reference copy) on every single call, i.e.
	// once per PARC/Custom requirement evaluated for a request rather than
	// once per request. mapPARCPrincipal below computes the mapping at most
	// once per EvaluationContext -- and a caller builds a fresh
	// EvaluationContext per request (see auth/authz/gin/middleware.go and
	// guard.go), so this is once per request in practice -- and every
	// subsequent handler call sharing this context and principal reuses the
	// cached value instead of rebuilding it. Deliberately unexported: the
	// PARC-shaped Principal type and this cache are both authz-internal and
	// are never constructed or read from outside the package.
	mappedPrincipal    *Principal
	mappedPrincipalFor *principal.Principal
}

// mapPARCPrincipal returns the PARC-shaped Principal for p against evalCtx,
// computing it at most once per evalCtx (i.e. once per request, not once per
// requirement/handler call -- see EvaluationContext.mappedPrincipal above).
// The cache is keyed on p's pointer identity: PolicyEngine.Evaluate passes a
// single *principal.Principal straight through to every handler for the
// whole requirements loop, so a stale mapping never happens; the pointer
// check is a defensive no-op today, not a workaround for an observed bug --
// if evalCtx were ever reused across principals it would recompute rather
// than silently return a mismatched cached copy.
func mapPARCPrincipal(evalCtx *EvaluationContext, p *principal.Principal) Principal {
	if evalCtx.mappedPrincipal != nil && evalCtx.mappedPrincipalFor == p {
		return *evalCtx.mappedPrincipal
	}
	mapped := Principal{
		ID:         p.Subject,
		ClientID:   p.ClientID,
		Roles:      p.Roles,
		Scopes:     p.Scopes,
		AuthMethod: string(p.Method),
		Attributes: p.Metadata,
	}
	evalCtx.mappedPrincipal = &mapped
	evalCtx.mappedPrincipalFor = p
	return mapped
}

// RequirementHandler evaluates a specific requirement type, mirroring ASP.NET Core AuthorizationHandler<T>.
type RequirementHandler interface {
	Handle(ctx context.Context, principal *principal.Principal, req Requirement, evalCtx *EvaluationContext) (bool, error)
}

// ScopeRequirementHandler evaluates ScopeRequirement.
type ScopeRequirementHandler struct{}

func (h *ScopeRequirementHandler) Handle(ctx context.Context, p *principal.Principal, req Requirement, evalCtx *EvaluationContext) (bool, error) {
	sr, ok := req.(ScopeRequirement)
	if !ok {
		return false, nil
	}
	if sr.RequireAll {
		return p.HasAllScopes(sr.Scopes...), nil
	}
	return p.HasAnyScope(sr.Scopes...), nil
}

// RoleRequirementHandler evaluates RoleRequirement.
type RoleRequirementHandler struct{}

func (h *RoleRequirementHandler) Handle(ctx context.Context, p *principal.Principal, req Requirement, evalCtx *EvaluationContext) (bool, error) {
	rr, ok := req.(RoleRequirement)
	if !ok {
		return false, nil
	}
	// Tier 0 #8: RequireAll was declared but ignored -- the handler always
	// ANDed. Honor it: true means every role is required, false means at
	// least one of them is (mirrors ScopeRequirementHandler's RequireAll).
	if rr.RequireAll {
		for _, r := range rr.Roles {
			if !p.HasRole(r) {
				return false, nil
			}
		}
		return true, nil
	}
	return p.HasAnyRole(rr.Roles...), nil
}

// UserPresentHandler evaluates UserPresentRequirement.
type UserPresentHandler struct{}

func (h *UserPresentHandler) Handle(ctx context.Context, p *principal.Principal, req Requirement, evalCtx *EvaluationContext) (bool, error) {
	return p.IsUserPresent(), nil
}

// M2MHandler evaluates M2MRequirement.
type M2MHandler struct{}

func (h *M2MHandler) Handle(ctx context.Context, p *principal.Principal, req Requirement, evalCtx *EvaluationContext) (bool, error) {
	return p.Method == principal.AuthMethodClientCredentials || p.Method == principal.AuthMethodAPIKey, nil
}

// MethodRequirementHandler evaluates MethodRequirement.
type MethodRequirementHandler struct{}

func (h *MethodRequirementHandler) Handle(ctx context.Context, p *principal.Principal, req Requirement, evalCtx *EvaluationContext) (bool, error) {
	mr, ok := req.(MethodRequirement)
	if !ok {
		return false, nil
	}
	for _, m := range mr.Methods {
		if p.Method == m {
			return true, nil
		}
	}
	return false, nil
}

// CustomRequirementHandler evaluates CustomRequirement.
type CustomRequirementHandler struct{}

func (h *CustomRequirementHandler) Handle(ctx context.Context, p *principal.Principal, req Requirement, evalCtx *EvaluationContext) (bool, error) {
	cr, ok := req.(CustomRequirement)
	if !ok || cr.Func == nil {
		return false, nil
	}

	parcReq := Request{
		Principal: mapPARCPrincipal(evalCtx, p),
		Action:    evalCtx.Action,
		Resource:  evalCtx.Resource,
		Context:   evalCtx.Context,
	}

	return cr.Func(ctx, parcReq), nil
}

// PARCHandlerConfig configures the PARC authorization handler.
type PARCHandlerConfig struct {
	// Repository is the application database containing permission records.
	Repository PermissionRepository

	// Cache is a typed cache.Cache[*PrincipalPermissions] (L1 memory,
	// L1+L2 tiered, or any other cache.Cache[T] implementation).
	// If nil, an in-process memory.Store is used.
	//
	// A miss is (nil, false, nil) -- never an error, per cache.Cache[T]
	// semantics. This replaces the old authz/cache.CacheProvider, whose
	// byte-oriented, error-as-miss shape let a real cache failure and a
	// plain miss reach Handle through the same branch.
	Cache cache.Cache[*PrincipalPermissions]

	// GrantTTL is the cache duration for permission bundles. Defaults to 60 seconds.
	GrantTTL time.Duration
}

// PARCHandler evaluates PARCRequirement with high-performance caching (10k+ RPS).
type PARCHandler struct {
	repo     PermissionRepository
	cache    cache.Cache[*PrincipalPermissions]
	grantTTL time.Duration
}

// NewPARCHandler creates an initialized PARC handler with caching.
func NewPARCHandler(cfg PARCHandlerConfig) (*PARCHandler, error) {
	if cfg.Repository == nil {
		return nil, errors.New("authz: repository cannot be nil")
	}
	c := cfg.Cache
	if c == nil {
		c = memory.New[*PrincipalPermissions](0)
	}
	ttl := cfg.GrantTTL
	if ttl <= 0 {
		ttl = 60 * time.Second
	}

	return &PARCHandler{
		repo:     cfg.Repository,
		cache:    c,
		grantTTL: ttl,
	}, nil
}

// Handle fetches the principal's permission bundle (from cache or DB) and evaluates the PARC request.
func (h *PARCHandler) Handle(ctx context.Context, p *principal.Principal, req Requirement, evalCtx *EvaluationContext) (bool, error) {
	parcReq, ok := req.(PARCRequirement)
	if !ok {
		return false, nil
	}

	cacheKey := "perm:" + p.Subject

	// 1. Check cache (L1 in-memory check takes ~30-50 nanoseconds). A miss
	// is (nil, false, nil), never an error; a non-nil error here is a real
	// cache failure, not a miss, and is deliberately NOT treated as fatal --
	// it falls through to the repository exactly like a miss does, so a
	// degraded cache does not take authorization down with it.
	perms, found, _ := h.cache.Get(ctx, cacheKey)

	// 2. Cache miss (or cache error): fetch from local database repository
	if !found || perms == nil {
		var err error
		perms, err = h.repo.GetPermissions(ctx, p.Subject)
		if err != nil {
			return false, fmt.Errorf("authz: failed fetching permissions: %w", err)
		}

		// Store in cache with 60-second grant propagation window
		_ = h.cache.Set(ctx, cacheKey, perms, h.grantTTL)
	}

	// 3. Assemble full PARC request
	action := evalCtx.Action
	if parcReq.Action != "" {
		action.Name = parcReq.Action
	}

	resource := evalCtx.Resource
	if parcReq.ResourceType != "" && resource.Type == "" {
		resource.Type = parcReq.ResourceType
	}

	pReq := Request{
		Principal: mapPARCPrincipal(evalCtx, p),
		Action:    action,
		Resource:  resource,
		Context:   evalCtx.Context,
	}

	decision := perms.Evaluate(pReq)
	return decision.Allowed, nil
}

// AuthorizationResult represents the outcome of an authorization evaluation (mirrors ASP.NET Core AuthorizationResult).
type AuthorizationResult struct {
	Succeeded     bool   `json:"succeeded"`
	FailureReason string `json:"failure_reason,omitempty"`
}

// Result is an alias for AuthorizationResult.
type Result = AuthorizationResult

// SuccessResult returns a successful authorization result.
func SuccessResult() AuthorizationResult {
	return AuthorizationResult{Succeeded: true}
}

// FailedResult returns a failed authorization result with the given reason.
func FailedResult(reason string) AuthorizationResult {
	return AuthorizationResult{Succeeded: false, FailureReason: reason}
}

// ToDecision converts an AuthorizationResult to a legacy Decision.
func (r AuthorizationResult) ToDecision() Decision {
	return Decision{Allowed: r.Succeeded, Reason: r.FailureReason}
}

// ToResult converts a Decision to an AuthorizationResult.
func (d Decision) ToResult() AuthorizationResult {
	return AuthorizationResult{Succeeded: d.Allowed, FailureReason: d.Reason}
}

// PolicyEngine is the Policy Decision Point (PDP) that coordinates policy evaluation.
// Mirrors ASP.NET Core IAuthorizationService.
type PolicyEngine struct {
	policies       map[string]Policy
	handlers       map[string]RequirementHandler
	defaultPolicy  *Policy
	fallbackPolicy *Policy
}

// AuthorizationService is an ASP.NET Core naming alias for PolicyEngine (IAuthorizationService).
type AuthorizationService = PolicyEngine

// Service is a convenient alias for AuthorizationService.
type Service = PolicyEngine

// AuthorizationHandler is an ASP.NET Core naming alias for RequirementHandler.
type AuthorizationHandler = RequirementHandler

// Handler is a convenient alias for RequirementHandler.
type Handler = RequirementHandler

// AuthorizationOptions configures the authorization service (mirrors ASP.NET Core AuthorizationOptions).
type AuthorizationOptions struct {
	policies       map[string]Policy
	DefaultPolicy  *Policy
	FallbackPolicy *Policy
}

// Options is an alias for AuthorizationOptions.
type Options = AuthorizationOptions

// NewAuthorizationOptions initializes an AuthorizationOptions builder.
func NewAuthorizationOptions() *AuthorizationOptions {
	return &AuthorizationOptions{
		policies: make(map[string]Policy),
	}
}

// NewOptions is an alias for NewAuthorizationOptions.
func NewOptions() *AuthorizationOptions {
	return NewAuthorizationOptions()
}

// AddPolicy registers a policy by name (mirrors options.AddPolicy in ASP.NET Core).
func (o *AuthorizationOptions) AddPolicy(name string, policy Policy) *AuthorizationOptions {
	policy.Name = name
	o.policies[name] = policy
	return o
}

// GetPolicy retrieves a registered policy by name.
func (o *AuthorizationOptions) GetPolicy(name string) (Policy, bool) {
	p, ok := o.policies[name]
	return p, ok
}

// NewAuthorizationService creates a Service using AuthorizationOptions.
func NewAuthorizationService(opts *AuthorizationOptions, handlers ...RequirementHandler) *AuthorizationService {
	engine := &PolicyEngine{
		policies: make(map[string]Policy),
		handlers: make(map[string]RequirementHandler),
	}
	engine.handlers["ScopeRequirement"] = &ScopeRequirementHandler{}
	engine.handlers["RoleRequirement"] = &RoleRequirementHandler{}
	engine.handlers["UserPresentRequirement"] = &UserPresentHandler{}
	engine.handlers["M2MRequirement"] = &M2MHandler{}
	engine.handlers["MethodRequirement"] = &MethodRequirementHandler{}
	engine.handlers["CustomRequirement"] = &CustomRequirementHandler{}

	if opts != nil {
		for _, p := range opts.policies {
			engine.RegisterPolicy(p)
		}
		engine.defaultPolicy = opts.DefaultPolicy
		engine.fallbackPolicy = opts.FallbackPolicy
	}

	for _, h := range handlers {
		if parc, ok := h.(*PARCHandler); ok {
			engine.handlers["PARCRequirement"] = parc
		}
	}

	return engine
}

// NewService is an alias for NewAuthorizationService.
func NewService(opts *AuthorizationOptions, handlers ...RequirementHandler) *AuthorizationService {
	return NewAuthorizationService(opts, handlers...)
}

// NewPolicyEngine creates a PolicyEngine with default requirement handlers registered.
func NewPolicyEngine(parcHandler ...*PARCHandler) *PolicyEngine {
	e := &PolicyEngine{
		policies: make(map[string]Policy),
		handlers: make(map[string]RequirementHandler),
	}

	// Register standard handlers
	e.handlers["ScopeRequirement"] = &ScopeRequirementHandler{}
	e.handlers["RoleRequirement"] = &RoleRequirementHandler{}
	e.handlers["UserPresentRequirement"] = &UserPresentHandler{}
	e.handlers["M2MRequirement"] = &M2MHandler{}
	e.handlers["MethodRequirement"] = &MethodRequirementHandler{}
	e.handlers["CustomRequirement"] = &CustomRequirementHandler{}

	if len(parcHandler) > 0 && parcHandler[0] != nil {
		e.handlers["PARCRequirement"] = parcHandler[0]
	}

	return e
}

// RegisterPolicy adds a policy to the engine.
func (e *PolicyEngine) RegisterPolicy(policy Policy) {
	e.policies[policy.Name] = policy
}

// RegisterHandler registers or overrides a handler for a requirement type.
func (e *PolicyEngine) RegisterHandler(requirementType string, handler RequirementHandler) {
	e.handlers[requirementType] = handler
}

// DefaultPolicy returns the configured default policy, if any.
func (e *PolicyEngine) DefaultPolicy() *Policy {
	return e.defaultPolicy
}

// FallbackPolicy returns the configured fallback policy, if any.
func (e *PolicyEngine) FallbackPolicy() *Policy {
	return e.fallbackPolicy
}

// Authorize evaluates a named policy against a Principal (mirrors ASP.NET Core IAuthorizationService.AuthorizeAsync).
func (e *PolicyEngine) Authorize(ctx context.Context, principal *principal.Principal, policyName string, evalCtx *EvaluationContext) (AuthorizationResult, error) {
	d, err := e.EvaluatePolicy(ctx, policyName, principal, evalCtx)
	return d.ToResult(), err
}

// EvaluatePolicy evaluates a named policy against a Principal.
func (e *PolicyEngine) EvaluatePolicy(ctx context.Context, policyName string, principal *principal.Principal, evalCtx *EvaluationContext) (Decision, error) {
	policy, exists := e.policies[policyName]
	if !exists {
		return Decision{Allowed: false, Reason: fmt.Sprintf("policy '%s' not found", policyName)}, ErrPolicyNotFound
	}
	return e.Evaluate(ctx, policy, principal, evalCtx)
}

// Evaluate runs all requirements in a Policy against the Principal (AND logic).
func (e *PolicyEngine) Evaluate(ctx context.Context, policy Policy, principal *principal.Principal, evalCtx *EvaluationContext) (Decision, error) {
	if principal == nil {
		return Decision{Allowed: false, Reason: "principal is nil"}, ErrNilPrincipal
	}

	if evalCtx == nil {
		evalCtx = &EvaluationContext{}
	}

	for _, req := range policy.Requirements {
		reqType := req.RequirementType()
		handler, exists := e.handlers[reqType]
		if !exists {
			return Decision{
				Allowed: false,
				Reason:  fmt.Sprintf("no handler registered for requirement type '%s'", reqType),
			}, nil
		}

		allowed, err := handler.Handle(ctx, principal, req, evalCtx)
		if err != nil {
			return Decision{Allowed: false, Reason: err.Error()}, err
		}
		if !allowed {
			return Decision{
				Allowed: false,
				Reason:  fmt.Sprintf("requirement '%s' failed", reqType),
			}, nil
		}
	}

	return Decision{Allowed: true}, nil
}

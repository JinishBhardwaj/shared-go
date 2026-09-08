package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/JinishBhardwaj/shared-go/authn"
	"github.com/JinishBhardwaj/shared-go/authz/cache"
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
}

// RequirementHandler evaluates a specific requirement type, mirroring ASP.NET Core AuthorizationHandler<T>.
type RequirementHandler interface {
	Handle(ctx context.Context, principal *authn.Principal, req Requirement, evalCtx *EvaluationContext) (bool, error)
}

// ScopeRequirementHandler evaluates ScopeRequirement.
type ScopeRequirementHandler struct{}

func (h *ScopeRequirementHandler) Handle(ctx context.Context, p *authn.Principal, req Requirement, evalCtx *EvaluationContext) (bool, error) {
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

func (h *RoleRequirementHandler) Handle(ctx context.Context, p *authn.Principal, req Requirement, evalCtx *EvaluationContext) (bool, error) {
	rr, ok := req.(RoleRequirement)
	if !ok {
		return false, nil
	}
	for _, r := range rr.Roles {
		if !p.HasRole(r) {
			return false, nil
		}
	}
	return true, nil
}

// UserPresentHandler evaluates UserPresentRequirement.
type UserPresentHandler struct{}

func (h *UserPresentHandler) Handle(ctx context.Context, p *authn.Principal, req Requirement, evalCtx *EvaluationContext) (bool, error) {
	return p.IsUserPresent(), nil
}

// M2MHandler evaluates M2MRequirement.
type M2MHandler struct{}

func (h *M2MHandler) Handle(ctx context.Context, p *authn.Principal, req Requirement, evalCtx *EvaluationContext) (bool, error) {
	return p.Method == authn.AuthMethodClientCredentials || p.Method == authn.AuthMethodAPIKey, nil
}

// CustomRequirementHandler evaluates CustomRequirement.
type CustomRequirementHandler struct{}

func (h *CustomRequirementHandler) Handle(ctx context.Context, p *authn.Principal, req Requirement, evalCtx *EvaluationContext) (bool, error) {
	cr, ok := req.(CustomRequirement)
	if !ok || cr.Func == nil {
		return false, nil
	}

	parcReq := Request{
		Principal: Principal{
			ID:         p.Subject,
			ClientID:   p.ClientID,
			Roles:      p.Roles,
			Scopes:     p.Scopes,
			AuthMethod: string(p.Method),
			Attributes: p.Metadata,
		},
		Action:   evalCtx.Action,
		Resource: evalCtx.Resource,
		Context:  evalCtx.Context,
	}

	return cr.Func(ctx, parcReq), nil
}

// PARCHandlerConfig configures the PARC authorization handler.
type PARCHandlerConfig struct {
	// Repository is the application database containing permission records.
	Repository PermissionRepository

	// Cache is the CacheProvider (L1 Memory or Tiered L1+L2 Redis).
	// If nil, NewMemoryCacheProvider will be used.
	Cache cache.CacheProvider

	// GrantTTL is the cache duration for permission bundles. Defaults to 60 seconds.
	GrantTTL time.Duration
}

// PARCHandler evaluates PARCRequirement with high-performance caching (10k+ RPS).
type PARCHandler struct {
	repo     PermissionRepository
	cache    cache.CacheProvider
	grantTTL time.Duration
}

// NewPARCHandler creates an initialized PARC handler with caching.
func NewPARCHandler(cfg PARCHandlerConfig) (*PARCHandler, error) {
	if cfg.Repository == nil {
		return nil, errors.New("authz: repository cannot be nil")
	}
	c := cfg.Cache
	if c == nil {
		var err error
		c, err = cache.NewMemoryCacheProvider()
		if err != nil {
			return nil, fmt.Errorf("authz: failed to initialize default memory cache: %w", err)
		}
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
func (h *PARCHandler) Handle(ctx context.Context, p *authn.Principal, req Requirement, evalCtx *EvaluationContext) (bool, error) {
	parcReq, ok := req.(PARCRequirement)
	if !ok {
		return false, nil
	}

	cacheKey := "perm:" + p.Subject

	var perms *PrincipalPermissions

	// 1. Check cache (L1 in-memory check takes ~30-50 nanoseconds)
	cachedBytes, err := h.cache.Get(ctx, cacheKey)
	if err == nil {
		var pRec PrincipalPermissions
		if jsonErr := json.Unmarshal(cachedBytes, &pRec); jsonErr == nil {
			perms = &pRec
		}
	}

	// 2. Cache miss: fetch from local database repository
	if perms == nil {
		perms, err = h.repo.GetPermissions(ctx, p.Subject)
		if err != nil {
			return false, fmt.Errorf("authz: failed fetching permissions: %w", err)
		}

		// Store in cache with 60-second grant propagation window
		if bytes, encErr := json.Marshal(perms); encErr == nil {
			_ = h.cache.Set(ctx, cacheKey, bytes, h.grantTTL)
		}
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
		Principal: Principal{
			ID:         p.Subject,
			ClientID:   p.ClientID,
			Roles:      p.Roles,
			Scopes:     p.Scopes,
			AuthMethod: string(p.Method),
			Attributes: p.Metadata,
		},
		Action:   action,
		Resource: resource,
		Context:  evalCtx.Context,
	}

	decision := perms.Evaluate(pReq)
	return decision.Allowed, nil
}

// PolicyEngine is the Policy Decision Point (PDP) that coordinates policy evaluation.
// Mirrors ASP.NET Core IAuthorizationService.
type PolicyEngine struct {
	policies map[string]Policy
	handlers map[string]RequirementHandler
}

// NewPolicyEngine creates a PolicyEngine with default requirement handlers registered.
func NewPolicyEngine(parcHandler *PARCHandler) *PolicyEngine {
	e := &PolicyEngine{
		policies: make(map[string]Policy),
		handlers: make(map[string]RequirementHandler),
	}

	// Register standard handlers
	e.handlers["ScopeRequirement"] = &ScopeRequirementHandler{}
	e.handlers["RoleRequirement"] = &RoleRequirementHandler{}
	e.handlers["UserPresentRequirement"] = &UserPresentHandler{}
	e.handlers["M2MRequirement"] = &M2MHandler{}
	e.handlers["CustomRequirement"] = &CustomRequirementHandler{}

	if parcHandler != nil {
		e.handlers["PARCRequirement"] = parcHandler
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

// EvaluatePolicy evaluates a named policy against a Principal.
func (e *PolicyEngine) EvaluatePolicy(ctx context.Context, policyName string, principal *authn.Principal, evalCtx *EvaluationContext) (Decision, error) {
	policy, exists := e.policies[policyName]
	if !exists {
		return Decision{Allowed: false, Reason: fmt.Sprintf("policy '%s' not found", policyName)}, ErrPolicyNotFound
	}
	return e.Evaluate(ctx, policy, principal, evalCtx)
}

// Evaluate runs all requirements in a Policy against the Principal (AND logic).
func (e *PolicyEngine) Evaluate(ctx context.Context, policy Policy, principal *authn.Principal, evalCtx *EvaluationContext) (Decision, error) {
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

package authz

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
	"github.com/JinishBhardwaj/shared-go/cache"
	"github.com/JinishBhardwaj/shared-go/cache/memory"
	"github.com/sony/gobreaker/v2"
	"golang.org/x/sync/singleflight"
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
	//
	// mu guards mappedPrincipal/mappedPrincipalFor. No current call site in
	// this codebase shares one EvaluationContext across concurrent
	// goroutines (every gin call site builds a fresh one per request), but
	// -race caught a genuine unsynchronized read/write race here while
	// testing G5's singleflight collapsing (which does call Handle
	// concurrently, just against per-goroutine EvaluationContexts in the
	// shipped code -- the race only showed up in a since-fixed test that
	// shared one across goroutines). Guarding it properly here removes the
	// latent hazard instead of leaving it to depend on every future caller
	// happening to build a fresh context too.
	mu                 sync.Mutex
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
//
// Guarded by evalCtx.mu so concurrent requirement-handler evaluation against
// the same EvaluationContext (e.g. a future caller that shares one across
// goroutines) is safe, not just safe-by-convention.
func mapPARCPrincipal(evalCtx *EvaluationContext, p *principal.Principal) Principal {
	evalCtx.mu.Lock()
	defer evalCtx.mu.Unlock()
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
//
// RequirementType identifies the Requirement.RequirementType() key this
// handler is registered under (gap-analysis-final.md Tier 1 line 95:
// "Generic handler registry" -- NewAuthorizationService used to type-switch
// for *PARCHandler and silently discard every other caller-supplied handler,
// so the variadic ...RequirementHandler parameter was a lie for anything but
// PARC). Built-in handlers return the same fixed string as their
// corresponding Requirement type's own RequirementType(); a caller-supplied
// handler for a named CustomRequirement (or any other custom Requirement
// type) declares its own key here, and NewAuthorizationService now registers
// every supplied handler generically by this value instead of discarding it.
type RequirementHandler interface {
	RequirementType() string
	Handle(ctx context.Context, principal *principal.Principal, req Requirement, evalCtx *EvaluationContext) (bool, error)
}

// ScopeRequirementHandler evaluates ScopeRequirement.
type ScopeRequirementHandler struct{}

func (h *ScopeRequirementHandler) RequirementType() string { return "ScopeRequirement" }

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

func (h *RoleRequirementHandler) RequirementType() string { return "RoleRequirement" }

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

func (h *UserPresentHandler) RequirementType() string { return "UserPresentRequirement" }

func (h *UserPresentHandler) Handle(ctx context.Context, p *principal.Principal, req Requirement, evalCtx *EvaluationContext) (bool, error) {
	return p.IsUserPresent(), nil
}

// M2MHandler evaluates M2MRequirement.
type M2MHandler struct{}

func (h *M2MHandler) RequirementType() string { return "M2MRequirement" }

func (h *M2MHandler) Handle(ctx context.Context, p *principal.Principal, req Requirement, evalCtx *EvaluationContext) (bool, error) {
	return p.Method == principal.AuthMethodClientCredentials || p.Method == principal.AuthMethodAPIKey, nil
}

// MethodRequirementHandler evaluates MethodRequirement.
type MethodRequirementHandler struct{}

func (h *MethodRequirementHandler) RequirementType() string { return "MethodRequirement" }

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

// RequirementType always returns the fixed key "CustomRequirement", never a
// specific CustomRequirement.Name value. This is deliberate: CustomRequirement's
// own RequirementType() returns r.Name when set (so DecisionEvent/deny-reason
// reporting stays specific and readable), but that means a *named*
// CustomRequirement's dispatch key in Policy.Evaluate never equals
// "CustomRequirement" and, before this fix, resolved to no handler at all --
// silently denying every named custom requirement regardless of its Func's
// actual result (gap-analysis-final.md Tier 1 line 95). Evaluate's dispatch
// now falls back to whatever handler is registered under this fixed key for
// any Requirement whose concrete type is CustomRequirement, so the Func is
// reached and its result actually governs the decision again, exactly as an
// unnamed CustomRequirement already worked.
func (h *CustomRequirementHandler) RequirementType() string { return "CustomRequirement" }

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

// CacheOutcome reports which branch PARCHandler.Handle's permission lookup
// took on a given call: purely observational, reported via
// PARCHandlerConfig.OnCacheOutcome for metrics/logging -- it never affects
// which branch is taken (that would make instrumentation a security-relevant
// change; this is the opposite, additive-only, by construction).
type CacheOutcome int

const (
	// CacheHit: the cached bundle was found and within GrantTTL of its
	// FetchedAt -- no repository call was made.
	CacheHit CacheOutcome = iota
	// CacheMiss: no cached bundle was found (or the cache errored) and no
	// stale bundle was available either; the repository was queried
	// synchronously and its result (success or failure) determines the
	// outcome directly.
	CacheMiss
	// CacheRefreshed: the cached bundle was stale (or missing), a
	// repository refresh was attempted, and it succeeded.
	CacheRefreshed
	// CacheStale: the cached bundle was stale, a repository refresh was
	// attempted and failed (breaker open, deadline exceeded, or a genuine
	// repository error), and the previously cached (stale) bundle was
	// served instead -- the stale-while-revalidate path.
	CacheStale
)

// String implements fmt.Stringer for use as a metrics/log label.
func (o CacheOutcome) String() string {
	switch o {
	case CacheHit:
		return "hit"
	case CacheMiss:
		return "miss"
	case CacheRefreshed:
		return "refreshed"
	case CacheStale:
		return "stale"
	default:
		return "unknown"
	}
}

// PARCHandlerConfig configures the PARC authorization handler.
type PARCHandlerConfig struct {
	// Repository is the application database containing permission records
	// (read-only -- the hot path never grants or revokes).
	Repository PermissionReader

	// Cache is a typed cache.Cache[*PrincipalPermissions] (L1 memory,
	// L1+L2 tiered, or any other cache.Cache[T] implementation).
	// If nil, an in-process memory.Store is used.
	//
	// A miss is (nil, false, nil) -- never an error, per cache.Cache[T]
	// semantics. This replaces the old authz/cache.CacheProvider, whose
	// byte-oriented, error-as-miss shape let a real cache failure and a
	// plain miss reach Handle through the same branch.
	Cache cache.Cache[*PrincipalPermissions]

	// GrantTTL is the soft-TTL freshness window for permission bundles:
	// how long a cached bundle is used directly, with no repository call
	// at all. Defaults to 60 seconds.
	GrantTTL time.Duration

	// StaleTTL is the hard TTL: the actual cache entry expiration passed to
	// Cache.Set. Once GrantTTL has elapsed but before StaleTTL has, a
	// cached bundle is "stale but present" -- Handle attempts a refresh and,
	// if that refresh fails (repository error, deadline exceeded, or the
	// internal circuit breaker is open), falls back to serving the stale
	// bundle rather than failing the request (Tier 3 stale-while-revalidate).
	// Once StaleTTL has elapsed the cache itself evicts the entry and no
	// stale fallback is available -- a failed refresh at that point fails
	// closed exactly as it always has. Defaults to 5 minutes, and is never
	// allowed to be smaller than GrantTTL (a hard TTL shorter than the soft
	// TTL would make "stale" unreachable).
	StaleTTL time.Duration

	// RepoTimeout bounds each individual repository fetch
	// (repo.GetPermissions) with a context deadline, decoupled from the
	// caller's own inbound context -- see Handle's refreshPermissions for
	// why. Defaults to 50ms per the gap analysis's explicit figure for
	// repo/Redis calls.
	RepoTimeout time.Duration

	// OnCacheOutcome, if set, is called once per Handle call reporting
	// which branch the permission lookup took (see CacheOutcome). Purely
	// observational -- see CacheOutcome's doc comment.
	OnCacheOutcome func(CacheOutcome)
}

// PARCHandler evaluates PARCRequirement with high-performance caching (10k+ RPS).
type PARCHandler struct {
	repo           PermissionReader
	cache          cache.Cache[*PrincipalPermissions]
	grantTTL       time.Duration
	staleTTL       time.Duration
	repoTimeout    time.Duration
	onCacheOutcome func(CacheOutcome)

	// breaker and group are internal (not exported in PARCHandlerConfig)
	// deliberately: exposing *gobreaker.CircuitBreaker[T] in authz's public
	// API would leak a third-party dependency's type into this package's
	// surface for no real caller benefit this gate -- same "no new exported
	// surface" discipline used for the PARC-shaped Principal type. breaker
	// and group are constructed with fixed, undocumented-as-tunable
	// defaults; only the time.Duration knobs above are exposed.
	breaker *gobreaker.CircuitBreaker[*PrincipalPermissions]
	group   singleflight.Group
}

// RequirementType returns "PARCRequirement" -- see RequirementHandler's doc
// comment. Registered generically by NewAuthorizationService/RegisterHandler
// like any other handler now (Tier 1 line 95); previously NewAuthorizationService
// special-cased *PARCHandler by type-switch instead of this mechanism.
func (h *PARCHandler) RequirementType() string { return "PARCRequirement" }

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
	staleTTL := cfg.StaleTTL
	if staleTTL <= 0 {
		staleTTL = 5 * time.Minute
	}
	if staleTTL < ttl {
		// A hard TTL shorter than the soft TTL would make the stale window
		// unreachable -- never silently accept a misconfiguration that
		// defeats the feature.
		staleTTL = ttl
	}
	repoTimeout := cfg.RepoTimeout
	if repoTimeout <= 0 {
		repoTimeout = 50 * time.Millisecond
	}

	return &PARCHandler{
		repo:           cfg.Repository,
		cache:          c,
		grantTTL:       ttl,
		staleTTL:       staleTTL,
		repoTimeout:    repoTimeout,
		onCacheOutcome: cfg.OnCacheOutcome,
		breaker:        gobreaker.NewCircuitBreaker[*PrincipalPermissions](gobreaker.Settings{Name: "authz-permission-repository"}),
	}, nil
}

// reportCacheOutcome calls the configured OnCacheOutcome hook, if any. Never
// called before the outcome it reports is already fully determined.
func (h *PARCHandler) reportCacheOutcome(o CacheOutcome) {
	if h.onCacheOutcome != nil {
		h.onCacheOutcome(o)
	}
}

// refreshPermissions fetches principalID's permission bundle from the
// repository, protected by a per-PARCHandler circuit breaker and a
// per-call context deadline (h.repoTimeout), and collapses concurrent
// refreshes for the same principalID into a single repository call
// (Tier 3 singleflight -- a cache miss/stale-refresh on a hot principal no
// longer fans every concurrent caller out to the repository individually).
//
// Deliberately uses context.Background() (bounded by h.repoTimeout), NOT the
// calling goroutine's own inbound ctx, as the base for the repository call:
// singleflight.Group.Do shares ONE execution of the function across every
// concurrent caller currently waiting on this principalID. If the repository
// call were tied to whichever individual caller happened to be the one
// selected to actually run it, that caller's own context being canceled
// (e.g. an HTTP client disconnecting) would abort the fetch for every other
// waiter too, even though their own requests are still live. This is a
// deliberate, accepted trade-off (the fetch is bounded by RepoTimeout
// regardless, so it cannot hang forever), not an oversight.
//
// On success, the bundle's FetchedAt is stamped and it is written back to
// the cache with h.staleTTL (the hard TTL) as its expiration. On failure
// (repository error, deadline exceeded, or the breaker is open -- all three
// surface identically as an error here, on purpose: none of them may ever
// be special-cased into treating the caller as authorized) the error is
// returned and the cache is left untouched.
func (h *PARCHandler) refreshPermissions(cacheKey, principalID string) (*PrincipalPermissions, error) {
	v, err, _ := h.group.Do(principalID, func() (any, error) {
		cctx, cancel := context.WithTimeout(context.Background(), h.repoTimeout)
		defer cancel()

		perms, err := h.breaker.Execute(func() (*PrincipalPermissions, error) {
			return h.repo.GetPermissions(cctx, principalID)
		})
		if err != nil {
			return nil, err
		}

		perms.FetchedAt = time.Now()
		_ = h.cache.Set(context.Background(), cacheKey, perms, h.staleTTL)
		return perms, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*PrincipalPermissions), nil
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
	perms, found, cacheErr := h.cache.Get(ctx, cacheKey)
	haveCached := found && cacheErr == nil && perms != nil

	fresh := haveCached && time.Since(perms.FetchedAt) <= h.grantTTL

	if !fresh {
		refreshed, err := h.refreshPermissions(cacheKey, p.Subject)
		switch {
		case err == nil:
			perms = refreshed
			h.reportCacheOutcome(CacheRefreshed)
		case haveCached:
			// Tier 3 stale-while-revalidate: the refresh failed (breaker
			// open, deadline exceeded, or a genuine repository error), but
			// a previously fetched bundle is still sitting in the cache
			// (not yet past StaleTTL) -- serve it rather than failing the
			// whole request. This can never become fail-open: an actively
			// revoked principal has no bundle left to fall back to, because
			// the existing instant-revocation contract deletes the cache
			// entry outright (repo.RevokeAll + cache.Delete, together, by
			// the caller) -- see TestPARCHandler_CachingAndInstantRevocation.
			// A backend outage that coincides with an active revocation
			// still resolves to !haveCached below, not to a stale allow.
			h.reportCacheOutcome(CacheStale)
			// perms already holds the stale cached value from step 1; reuse it.
		default:
			// No usable cached value at all (genuine miss, or the cached
			// entry already aged past StaleTTL and was evicted): fail
			// closed exactly as before this change.
			h.reportCacheOutcome(CacheMiss)
			return false, fmt.Errorf("authz: failed fetching permissions: %w", err)
		}
	} else {
		h.reportCacheOutcome(CacheHit)
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

// Authorizer is the decision-making contract extracted from PolicyEngine
// (gap-analysis-final.md Tier 2: "Extract Authorizer + PolicyRegistry
// interfaces from PolicyEngine. Two, not four."). It mirrors ASP.NET Core's
// IAuthorizationService: given a principal and a policy (by name or value),
// produce a decision. PolicyEngine implements this today; this interface
// exists so a future caller/decorator (e.g. the Tier 4 OnDecision/audit
// wrapper) can depend on the narrower contract instead of the full
// PolicyEngine concrete type.
type Authorizer interface {
	Authorize(ctx context.Context, principal *principal.Principal, policyName string, evalCtx *EvaluationContext) (AuthorizationResult, error)
	EvaluatePolicy(ctx context.Context, policyName string, principal *principal.Principal, evalCtx *EvaluationContext) (Decision, error)
	Evaluate(ctx context.Context, policy Policy, principal *principal.Principal, evalCtx *EvaluationContext) (Decision, error)
}

// PolicyRegistry is the registration/lookup contract extracted from
// PolicyEngine (same Tier 2 item as Authorizer above). It covers
// wiring-time policy and handler registration plus the two named-policy
// lookups (DefaultPolicy/FallbackPolicy) that the authz/gin middleware
// consults. PolicyEngine implements this today.
type PolicyRegistry interface {
	RegisterPolicy(policy Policy)
	RegisterHandler(requirementType string, handler RequirementHandler)
	DefaultPolicy() *Policy
	FallbackPolicy() *Policy
}

// PolicyEngine is the Policy Decision Point (PDP) that coordinates policy evaluation.
// Mirrors ASP.NET Core IAuthorizationService.
type PolicyEngine struct {
	// mu guards policies, handlers, and built. Tier 1 line 99: RegisterPolicy
	// and RegisterHandler used to mutate policies/handlers with no
	// synchronization at all, racing with the map reads in
	// EvaluatePolicy/Evaluate below if a caller registered after the engine
	// was already serving live traffic. mu is a plain RWMutex rather than a
	// sync.Map because reads (Evaluate/EvaluatePolicy, on the hot path) vastly
	// outnumber writes (RegisterPolicy/RegisterHandler, wiring-time only).
	mu             sync.RWMutex
	policies       map[string]Policy
	handlers       map[string]RequirementHandler
	defaultPolicy  *Policy
	fallbackPolicy *Policy
	onDecision     func(context.Context, DecisionEvent)
	// built is true once Build() has been called; see Build's doc comment.
	built bool
}

var (
	_ Authorizer     = (*PolicyEngine)(nil)
	_ PolicyRegistry = (*PolicyEngine)(nil)
)

// DecisionEvent describes the outcome of one PolicyEngine.Evaluate /
// EvaluatePolicy call, reported to the optional OnDecision hook (see
// PolicyEngine.SetOnDecision). Tier 4 audit-hook / metrics-decorator
// support: purely observational, built from an already-fully-computed
// Decision -- nothing about handling this event can change or suppress the
// Allowed/Reason values it describes.
type DecisionEvent struct {
	// PolicyName is the evaluated policy's name (empty if the policy
	// itself was not found).
	PolicyName string
	Allowed    bool
	Reason     string
	// RequirementType is the RequirementType() of the requirement that
	// caused a deny (empty if Allowed is true, or if the policy itself was
	// not found before any requirement ran).
	RequirementType string
	// Duration is the wall-clock time spent in this Evaluate/EvaluatePolicy
	// call, from entry to the point the Decision was finalized.
	Duration time.Duration
}

// SetOnDecision registers fn to be called once per Evaluate/EvaluatePolicy
// call, after the Decision has already been fully computed. fn must not
// block or panic: it is called synchronously on the evaluating goroutine,
// unguarded by recover() by design (mirrors Go stdlib callback-hook
// convention; a panicking caller-supplied hook is the caller's bug to fix,
// not something this package should paper over). Pass nil to disable.
func (e *PolicyEngine) SetOnDecision(fn func(context.Context, DecisionEvent)) {
	e.onDecision = fn
}

// emitDecision calls the configured OnDecision hook, if any, with an
// already-finalized Decision -- see DecisionEvent's doc comment for why this
// cannot influence the outcome it reports.
func (e *PolicyEngine) emitDecision(ctx context.Context, policyName string, d Decision, reqType string, start time.Time) {
	if e.onDecision == nil {
		return
	}
	e.onDecision(ctx, DecisionEvent{
		PolicyName:      policyName,
		Allowed:         d.Allowed,
		Reason:          d.Reason,
		RequirementType: reqType,
		Duration:        time.Since(start),
	})
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

	// Tier 1 line 95: register every supplied handler generically by its own
	// declared RequirementType(), instead of type-switching for *PARCHandler
	// and silently discarding anything else. A caller-supplied handler
	// overrides a built-in one registered under the same key, mirroring
	// RegisterHandler's own "registers or overrides" semantics below.
	for _, h := range handlers {
		if h == nil {
			continue
		}
		engine.handlers[h.RequirementType()] = h
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
//
// Panics if called after Build() (Tier 1 line 99: "Freeze PolicyEngine at
// Build() -- no post-serve registration, no unguarded map writes"). Calling
// Build() is optional; an engine that never calls it accepts
// RegisterPolicy calls for its entire lifetime, unchanged from before.
func (e *PolicyEngine) RegisterPolicy(policy Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.built {
		panic("authz: PolicyEngine: RegisterPolicy called after Build() -- policies must be registered before Build()")
	}
	e.policies[policy.Name] = policy
}

// RegisterHandler registers or overrides a handler for a requirement type.
//
// Panics if called after Build() -- see RegisterPolicy's doc comment.
func (e *PolicyEngine) RegisterHandler(requirementType string, handler RequirementHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.built {
		panic("authz: PolicyEngine: RegisterHandler called after Build() -- handlers must be registered before Build()")
	}
	e.handlers[requirementType] = handler
}

// Build freezes the PolicyEngine: no further RegisterPolicy/RegisterHandler
// calls are permitted afterward (they panic -- see each method's doc
// comment). Calling Build() is optional; an engine that never calls Build()
// behaves exactly as before (RegisterPolicy/RegisterHandler remain callable,
// still under the same lock as every read). Returns e for chaining.
func (e *PolicyEngine) Build() *PolicyEngine {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.built = true
	return e
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
	start := time.Now()
	e.mu.RLock()
	policy, exists := e.policies[policyName]
	e.mu.RUnlock()
	if !exists {
		d := Decision{Allowed: false, Reason: fmt.Sprintf("policy '%s' not found", policyName)}
		e.emitDecision(ctx, policyName, d, "", start)
		return d, ErrPolicyNotFound
	}
	return e.Evaluate(ctx, policy, principal, evalCtx)
}

// Evaluate runs all requirements in a Policy against the Principal (AND logic).
func (e *PolicyEngine) Evaluate(ctx context.Context, policy Policy, principal *principal.Principal, evalCtx *EvaluationContext) (Decision, error) {
	start := time.Now()

	if principal == nil {
		d := Decision{Allowed: false, Reason: "principal is nil"}
		e.emitDecision(ctx, policy.Name, d, "", start)
		return d, ErrNilPrincipal
	}

	if evalCtx == nil {
		evalCtx = &EvaluationContext{}
	}

	for _, req := range policy.Requirements {
		reqType := req.RequirementType()
		e.mu.RLock()
		handler, exists := e.handlers[reqType]
		if !exists {
			// Tier 1 line 95: a named CustomRequirement's own RequirementType()
			// returns its Name, not "CustomRequirement", so the lookup above
			// never finds a handler registered under the requirement's own
			// name -- before this fallback, that meant every named
			// CustomRequirement silently denied regardless of what its Func
			// actually returned. Fall back to whatever handler is registered
			// under the fixed "CustomRequirement" key (built-in
			// CustomRequirementHandler by default, or a caller override) for
			// any Requirement whose concrete type is CustomRequirement, so
			// the Func is reached and genuinely governs the decision again.
			if _, isCustom := req.(CustomRequirement); isCustom {
				handler, exists = e.handlers["CustomRequirement"]
			}
		}
		e.mu.RUnlock()
		if !exists {
			d := Decision{
				Allowed: false,
				Reason:  fmt.Sprintf("no handler registered for requirement type '%s'", reqType),
			}
			e.emitDecision(ctx, policy.Name, d, reqType, start)
			return d, nil
		}

		allowed, err := handler.Handle(ctx, principal, req, evalCtx)
		if err != nil {
			d := Decision{Allowed: false, Reason: err.Error()}
			e.emitDecision(ctx, policy.Name, d, reqType, start)
			return d, err
		}
		if !allowed {
			d := Decision{
				Allowed: false,
				Reason:  fmt.Sprintf("requirement '%s' failed", reqType),
			}
			e.emitDecision(ctx, policy.Name, d, reqType, start)
			return d, nil
		}
	}

	d := Decision{Allowed: true}
	e.emitDecision(ctx, policy.Name, d, "", start)
	return d, nil
}

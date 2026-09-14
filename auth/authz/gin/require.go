package gin

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/JinishBhardwaj/shared-go/auth/authz"
	"github.com/JinishBhardwaj/shared-go/auth/principal"
	ginprincipal "github.com/JinishBhardwaj/shared-go/auth/principal/gin"
	"github.com/gin-gonic/gin"
)

// This file consolidates the route-guard entry points named in
// gap-analysis-final.md Tier 4, line 131 ("Consolidate the five route-guard
// entry points (Authorize, WithPolicy, RequirePolicy, RequirePARC,
// authn.RequireScope) into one authz.Require(opts...); replace args ...any
// type switches ... and pseudo-optional variadics with typed options"),
// pulled forward into this gate (G6) per an explicit user decision recorded
// in .claude/authfix/state.md, because it is the same route-guard-entry-point
// surface as G6's item 1 (the route-detection hack in routes.go/
// middleware.go).
//
// Post-restructure, there were 11 such gin.HandlerFunc-returning
// constructors, not the doc's pre-restructure five: Authorize, WithPolicy
// (middleware.go), RequirePolicy, RequirePARC (former guard.go), RequireScope,
// RequireAnyScope, RequireMethod, RequireUser, RequireM2M, RequireRole,
// RequireAnyRole (former guards.go, rebuilt in G2 as authz-native guards).
// All eleven are replaced -- not wrapped -- by Require(opts...) below: every
// call site in this package's own tests is migrated, and each mode's
// request-handling logic (response status/body/header shape) is carried
// over verbatim from its predecessor, verified field-for-field against the
// pre-fix code before deletion.

// requireMode identifies which single requirement Require's returned guard
// evaluates. Exactly one mode-setting RequireOption must be supplied to
// Require; supplying zero or more than one is a static configuration error,
// panicked at construction time (not deferred to first request) since it
// can never depend on runtime/request state.
type requireMode int

const (
	modeNone requireMode = iota
	modePolicy
	modePARC
	modeScopeAll
	modeScopeAny
	modeRoleAll
	modeRoleAny
	modeMethod
)

func (m requireMode) String() string {
	switch m {
	case modePolicy:
		return "WithPolicyName"
	case modePARC:
		return "WithPARC"
	case modeScopeAll:
		return "WithScopes"
	case modeScopeAny:
		return "WithAnyScope"
	case modeRoleAll:
		return "WithRoles"
	case modeRoleAny:
		return "WithAnyRole"
	case modeMethod:
		return "WithMethods/WithUserPresent/WithM2M"
	default:
		return "none"
	}
}

type requireConfig struct {
	engine         *authz.PolicyEngine
	resource       ResourceExtractorFunc
	actionResolver ActionResolver

	mode         requireMode
	policyName   string
	parcAction   string
	parcResource string
	scopes       []string
	roles        []string
	methods      []principal.AuthMethod
}

// RequireOption configures a Require(...) guard. Exactly one requirement-
// defining option (WithPolicyName / WithPARC / WithScopes / WithAnyScope /
// WithRoles / WithAnyRole / WithMethods / WithUserPresent / WithM2M) must be
// supplied. WithEngine is a MANDATORY modifier for the WithPolicyName/WithPARC
// modes (Require panics at construction time if it is missing for either of
// those two modes -- gap-analysis-final.md Tier 1 line 100, authz half:
// "fail at wire time, not request time"); WithResource remains an optional
// modifier applicable to the policy/PARC modes. WithEngine is ignored
// entirely by the scope/role/method modes, which need no PolicyEngine at all.
type RequireOption func(*requireConfig)

// setMode records cfg's single requirement mode, panicking if one was
// already set -- ambiguous configuration (e.g. both WithPolicyName and
// WithScopes) is always a caller bug, never a runtime condition, so this
// fails as loudly and as early as possible.
func setMode(cfg *requireConfig, m requireMode) {
	if cfg.mode != modeNone {
		panic(fmt.Sprintf("authz: Require: conflicting requirement options -- %s was already set when %s was supplied; exactly one is allowed", cfg.mode, m))
	}
	cfg.mode = m
}

// WithEngine supplies the PolicyEngine used to evaluate the WithPolicyName/
// WithPARC modes. It is MANDATORY for those two modes: Require(...) panics at
// its own construction time (not at first request) if either mode is
// selected and WithEngine was not supplied (gap-analysis-final.md Tier 1
// line 100, authz half -- "fail at wire time, not request time"). This is a
// deliberate break from the package's earlier convenience pattern, where an
// omitted WithEngine fell back to resolving the PolicyEngine from the gin
// context at request time (set by New()/UseAuthorization); that fallback no
// longer exists for these two modes. Ignored by the scope/role/method modes,
// which (like their predecessors RequireScope/RequireRole/RequireMethod)
// evaluate their single requirement directly and need no PolicyEngine at
// all.
func WithEngine(engine *authz.PolicyEngine) RequireOption {
	return func(cfg *requireConfig) { cfg.engine = engine }
}

// WithResource supplies a ResourceExtractorFunc populating the evaluated
// Resource for the policy/PARC modes.
func WithResource(extractor ResourceExtractorFunc) RequireOption {
	return func(cfg *requireConfig) { cfg.resource = extractor }
}

// WithActionResolver overrides how the modePolicy (WithPolicyName) guard
// derives a logical Action.Name from the incoming request's HTTP verb (Tier 1
// line 98, "Unify action semantics"). Defaults to DefaultActionResolver.
// Ignored by every other mode: WithPARC always supplies its own explicit
// logical action, and the scope/role/method modes never populate Action at
// all.
func WithActionResolver(resolver ActionResolver) RequireOption {
	return func(cfg *requireConfig) { cfg.actionResolver = resolver }
}

// WithPolicyName evaluates the named, pre-registered policy against the
// resolved PolicyEngine. Replaces Authorize(policyName, ...) / WithPolicy /
// RequirePolicy(engine, policyName, ...).
func WithPolicyName(name string) RequireOption {
	return func(cfg *requireConfig) {
		setMode(cfg, modePolicy)
		cfg.policyName = name
	}
}

// WithPARC evaluates an inline PARC requirement for the given action and
// resource type. Replaces RequirePARC(engine, action, resourceType, ...).
func WithPARC(action, resourceType string) RequireOption {
	return func(cfg *requireConfig) {
		setMode(cfg, modePARC)
		cfg.parcAction = action
		cfg.parcResource = resourceType
	}
}

// WithScopes requires that the principal has ALL of the given scopes.
// Replaces RequireScope(scopes...).
func WithScopes(scopes ...string) RequireOption {
	return func(cfg *requireConfig) {
		setMode(cfg, modeScopeAll)
		cfg.scopes = scopes
	}
}

// WithAnyScope requires that the principal has AT LEAST ONE of the given
// candidate scopes. Replaces RequireAnyScope(scopes...). An empty
// candidate list fails closed (Tier 0 #6), same as before.
func WithAnyScope(scopes ...string) RequireOption {
	return func(cfg *requireConfig) {
		setMode(cfg, modeScopeAny)
		cfg.scopes = scopes
	}
}

// WithRoles requires that the principal has ALL of the given roles.
// Replaces RequireRole(roles...).
func WithRoles(roles ...string) RequireOption {
	return func(cfg *requireConfig) {
		setMode(cfg, modeRoleAll)
		cfg.roles = roles
	}
}

// WithAnyRole requires that the principal has AT LEAST ONE of the given
// candidate roles. Replaces RequireAnyRole(roles...). An empty candidate
// list fails closed (Tier 0 #6), same as before.
func WithAnyRole(roles ...string) RequireOption {
	return func(cfg *requireConfig) {
		setMode(cfg, modeRoleAny)
		cfg.roles = roles
	}
}

// WithMethods requires that the principal authenticated via one of the given
// methods/OAuth flows. Replaces RequireMethod(methods...).
func WithMethods(methods ...principal.AuthMethod) RequireOption {
	return func(cfg *requireConfig) {
		setMode(cfg, modeMethod)
		cfg.methods = methods
	}
}

// WithUserPresent requires an interactive end-user flow (AuthCode+PKCE or
// Device Flow). Replaces RequireUser(). Equivalent to
// WithMethods(principal.AuthMethodAuthCodePKCE, principal.AuthMethodDeviceFlow).
func WithUserPresent() RequireOption {
	return WithMethods(principal.AuthMethodAuthCodePKCE, principal.AuthMethodDeviceFlow)
}

// WithM2M requires an automated Machine-to-Machine flow (Client Credentials
// or API Key). Replaces RequireM2M(). Equivalent to
// WithMethods(principal.AuthMethodClientCredentials, principal.AuthMethodAPIKey).
func WithM2M() RequireOption {
	return WithMethods(principal.AuthMethodClientCredentials, principal.AuthMethodAPIKey)
}

var (
	scopeHandler  = &authz.ScopeRequirementHandler{}
	roleHandler   = &authz.RoleRequirementHandler{}
	methodHandler = &authz.MethodRequirementHandler{}
)

// ResourceExtractorFunc extracts the target domain Resource from the incoming Gin context.
// Formerly declared in guard.go; moved here alongside its only consumers
// (the policy/PARC modes of Require).
type ResourceExtractorFunc func(c *gin.Context) authz.Resource

// ExtractResourceFromParam returns a ResourceExtractorFunc that populates Resource.ID from a URL route param.
func ExtractResourceFromParam(paramName, resourceType string) ResourceExtractorFunc {
	return func(c *gin.Context) authz.Resource {
		return authz.Resource{
			Type: resourceType,
			ID:   c.Param(paramName),
		}
	}
}

// Require builds a single gin.HandlerFunc route guard from opts. It is the
// sole route-guard entry point in this package (gap-analysis-final.md Tier 4
// line 131), replacing the eleven former Authorize/WithPolicy/RequirePolicy/
// RequirePARC/RequireScope/RequireAnyScope/RequireMethod/RequireUser/
// RequireM2M/RequireRole/RequireAnyRole constructors. Note that New()'s
// FallbackPolicy enforcement does NOT infer anything from a route's use of
// Require -- see routes.go (Group/ProtectGroup) for how a route opts out of
// FallbackPolicy explicitly.
//
// Require panics at this, its own construction time, in two cases (never
// deferred into the returned gin.HandlerFunc, i.e. never at request time):
// no requirement-defining option was supplied at all, or exactly one of the
// WithPolicyName/WithPARC modes was selected without an accompanying
// WithEngine(...) (gap-analysis-final.md Tier 1 line 100, authz half -- "fail
// at wire time, not request time"). The scope/role/method modes need no
// PolicyEngine and are unaffected by the second check.
func Require(opts ...RequireOption) gin.HandlerFunc {
	cfg := &requireConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	if cfg.mode == modeNone {
		panic("authz: Require: no requirement option supplied -- provide exactly one of " +
			"WithPolicyName/WithPARC/WithScopes/WithAnyScope/WithRoles/WithAnyRole/" +
			"WithMethods/WithUserPresent/WithM2M")
	}
	if (cfg.mode == modePolicy || cfg.mode == modePARC) && cfg.engine == nil {
		panic(fmt.Sprintf("authz: Require: %s requires WithEngine(...) to be supplied at "+
			"construction time -- no PolicyEngine was provided", cfg.mode))
	}

	// The inline PARC policy is built once, at guard-construction time (not
	// per request), matching the former RequirePARC's own optimization.
	var inlinePolicy authz.Policy
	if cfg.mode == modePARC {
		inlinePolicy = authz.NewPolicy(fmt.Sprintf("inline:parc:%s:%s", cfg.parcAction, cfg.parcResource)).
			RequirePARC(cfg.parcAction, cfg.parcResource).
			Build()
	}

	return func(c *gin.Context) {
		switch cfg.mode {
		case modePolicy:
			requirePolicyGuard(c, cfg)
		case modePARC:
			requirePARCGuard(c, cfg, inlinePolicy)
		case modeScopeAll:
			requireScopeGuard(c, cfg.scopes, true)
		case modeScopeAny:
			requireScopeGuard(c, cfg.scopes, false)
		case modeRoleAll:
			requireRoleGuard(c, cfg.roles, true)
		case modeRoleAny:
			requireRoleGuard(c, cfg.roles, false)
		case modeMethod:
			requireMethodGuard(c, cfg.methods)
		}
	}
}

// requirePolicyGuard evaluates a named policy. Behavior carried over
// verbatim from the former RequirePolicy (and byte-identical, by
// inspection, to the former Authorize/WithPolicy's default response path
// through handleResult). cfg.engine is guaranteed non-nil here: Require(...)
// panics at its own construction time if WithEngine was omitted for
// modePolicy, so there is no request-time nil-engine path left to check
// (gap-analysis-final.md Tier 1 line 100, authz half).
func requirePolicyGuard(c *gin.Context, cfg *requireConfig) {
	engine := cfg.engine

	user := ginprincipal.User(c)
	if user == nil {
		// authz never emits 401 -- that is authn's job (gap-analysis-final.md
		// Tier 2 line 107, G8-5). No principal in context here means authn
		// did not run (or ran and found nothing) ahead of this guard -- a
		// misconfiguration/missing-authn condition, not a credential
		// challenge -- so it is answered exactly like any other
		// authorization failure: 403, with no WWW-Authenticate (that header
		// exists to accompany a 401 challenge, which this package no longer
		// issues; see httpsec.go).
		logAuthzDenial(fmt.Sprintf("policy %q", cfg.policyName), "no principal in context")
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":             "forbidden",
			"error_description": descAuthenticationRequired,
			"policy":            cfg.policyName,
		})
		return
	}

	var res authz.Resource
	if cfg.resource != nil {
		res = cfg.resource(c)
	}

	resolver := cfg.actionResolver
	if resolver == nil {
		resolver = defaultActionResolver
	}

	evalCtx := &authz.EvaluationContext{
		Action: authz.Action{
			Name:       resolver(c.Request.Method),
			HTTPMethod: c.Request.Method,
		},
		Resource: res,
		Context: authz.Context{
			ClientIP:  c.ClientIP(),
			Timestamp: time.Now().UTC(),
		},
	}

	// Tier 0 #7: decision.Reason is deliberately NOT echoed to the caller --
	// see httpsec.go. Log server-side, answer with a fixed description.
	decision, err := engine.EvaluatePolicy(c.Request.Context(), cfg.policyName, user, evalCtx)
	if err != nil || !decision.Allowed {
		logAuthzDenial(fmt.Sprintf("policy %q", cfg.policyName), decision.Reason)

		c.Header("WWW-Authenticate", fmt.Sprintf("Bearer error=%s, error_description=%s",
			quoteRFC7235(rfc6750InsufficientScope), quoteRFC7235(descAccessDeniedByPolicy)))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":             "forbidden",
			"error_description": descAccessDeniedByPolicy,
			"policy":            cfg.policyName,
		})
		return
	}

	c.Next()
}

// requirePARCGuard evaluates an inline PARC requirement. Behavior carried
// over verbatim from the former RequirePARC. cfg.engine is guaranteed
// non-nil here: Require(...) panics at its own construction time if
// WithEngine was omitted for modePARC, so there is no request-time
// nil-engine path left to check (gap-analysis-final.md Tier 1 line 100,
// authz half).
func requirePARCGuard(c *gin.Context, cfg *requireConfig, inlinePolicy authz.Policy) {
	engine := cfg.engine

	user := ginprincipal.User(c)
	if user == nil {
		// authz never emits 401 -- same reasoning as requirePolicyGuard
		// above (gap-analysis-final.md Tier 2 line 107, G8-5).
		logAuthzDenial(fmt.Sprintf("PARC action=%q resource_type=%q", cfg.parcAction, cfg.parcResource), "no principal in context")
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":             "forbidden",
			"error_description": descAuthenticationRequired,
			"action":            cfg.parcAction,
			"resource_type":     cfg.parcResource,
		})
		return
	}

	var res authz.Resource
	if cfg.resource != nil {
		res = cfg.resource(c)
	} else {
		res = authz.Resource{Type: cfg.parcResource, ID: "*"}
	}

	evalCtx := &authz.EvaluationContext{
		Action: authz.Action{
			Name:       cfg.parcAction,
			HTTPMethod: c.Request.Method,
		},
		Resource: res,
		Context: authz.Context{
			ClientIP:  c.ClientIP(),
			Timestamp: time.Now().UTC(),
		},
	}

	// Tier 0 #7: decision.Reason is deliberately NOT echoed (same reasoning
	// as requirePolicyGuard). The action/resourceType-based description is
	// always safe -- both are route-wiring constants, never derived from an
	// error.
	decision, err := engine.Evaluate(c.Request.Context(), inlinePolicy, user, evalCtx)
	if err != nil || !decision.Allowed {
		logAuthzDenial(fmt.Sprintf("PARC action=%q resource_type=%q", cfg.parcAction, cfg.parcResource), decision.Reason)

		safeDesc := fmt.Sprintf("Missing permission for action '%s' on resource '%s'", cfg.parcAction, cfg.parcResource)
		c.Header("WWW-Authenticate", fmt.Sprintf("Bearer error=%s, error_description=%s",
			quoteRFC7235(rfc6750InsufficientScope), quoteRFC7235(safeDesc)))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":             "insufficient_permissions",
			"error_description": safeDesc,
			"action":            cfg.parcAction,
			"resource_type":     cfg.parcResource,
		})
		return
	}

	c.Next()
}

// requireScopeGuard evaluates a scope requirement directly against
// scopeHandler, with no PolicyEngine involved -- same as the former
// RequireScope (all=true) / RequireAnyScope (all=false).
func requireScopeGuard(c *gin.Context, scopes []string, all bool) {
	user := ginprincipal.User(c)
	if user == nil {
		respondNoPrincipalForbidden(c)
		return
	}

	req := authz.ScopeRequirement{Scopes: scopes, RequireAll: all}
	allowed, _ := scopeHandler.Handle(c.Request.Context(), user, req, nil)
	if !allowed {
		// scopes is route-wiring config, not attacker input -- but per
		// Tier 0 #7 every auth-param value written into this header goes
		// through the same RFC 7235 quoting regardless.
		c.Header("WWW-Authenticate", fmt.Sprintf("Bearer error=%s, scope=%s",
			quoteRFC7235(rfc6750InsufficientScope), quoteRFC7235(strings.Join(scopes, " "))))
		if all {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":             "insufficient_scope",
				"error_description": fmt.Sprintf("Requires all of the following scopes: %s", strings.Join(scopes, ", ")),
				"missing_scopes":    missingScopes(user, scopes),
			})
		} else {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":             "insufficient_scope",
				"error_description": fmt.Sprintf("Requires at least one of the following scopes: %s", strings.Join(scopes, ", ")),
			})
		}
		return
	}

	c.Next()
}

// requireRoleGuard evaluates a role requirement directly against
// roleHandler -- same as the former RequireRole (all=true) / RequireAnyRole
// (all=false).
func requireRoleGuard(c *gin.Context, roles []string, all bool) {
	user := ginprincipal.User(c)
	if user == nil {
		respondNoPrincipalForbidden(c)
		return
	}

	req := authz.RoleRequirement{Roles: roles, RequireAll: all}
	allowed, _ := roleHandler.Handle(c.Request.Context(), user, req, nil)
	if !allowed {
		if all {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":             "insufficient_role",
				"error_description": fmt.Sprintf("Missing required role: %s", firstMissingRole(user, roles)),
			})
		} else {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":             "insufficient_role",
				"error_description": fmt.Sprintf("Requires at least one of the following roles: %s", strings.Join(roles, ", ")),
			})
		}
		return
	}

	c.Next()
}

// requireMethodGuard evaluates a method requirement directly against
// methodHandler -- same as the former RequireMethod (and, by extension,
// RequireUser/RequireM2M, which forwarded to it).
func requireMethodGuard(c *gin.Context, methods []principal.AuthMethod) {
	user := ginprincipal.User(c)
	if user == nil {
		respondNoPrincipalForbidden(c)
		return
	}

	req := authz.MethodRequirement{Methods: methods}
	allowed, _ := methodHandler.Handle(c.Request.Context(), user, req, nil)
	if !allowed {
		methodNames := make([]string, len(methods))
		for i, m := range methods {
			methodNames[i] = string(m)
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":             "disallowed_auth_flow",
			"error_description": fmt.Sprintf("This endpoint requires authentication via [%s], but received [%s]", strings.Join(methodNames, ", "), user.Method),
			"current_method":    user.Method,
		})
		return
	}

	c.Next()
}

// respondNoPrincipalForbidden answers a request that reached one of the
// scope/role/method guards with no principal in context. authz never emits
// 401 -- that is authn's job (gap-analysis-final.md Tier 2 line 107, G8-5)
// -- so this is a 403 like any other authorization failure, with no
// WWW-Authenticate (that header exists to accompany a 401 challenge, which
// this package no longer issues; see httpsec.go). Formerly named
// respondUnauthenticated and returned 401; renamed alongside the behavior
// change so the name matches what it actually does.
func respondNoPrincipalForbidden(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"error":             "forbidden",
		"error_description": descAuthenticationRequired,
	})
}

func missingScopes(p *principal.Principal, required []string) []string {
	var missing []string
	for _, req := range required {
		if !p.HasScope(req) {
			missing = append(missing, req)
		}
	}
	return missing
}

func firstMissingRole(p *principal.Principal, required []string) string {
	for _, r := range required {
		if !p.HasRole(r) {
			return r
		}
	}
	return ""
}

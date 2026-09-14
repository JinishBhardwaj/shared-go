package gin

import "net/http"

// Tier 1 line 98 ("Unify action semantics"): Authorize/RequirePolicy (now
// folded into requirePolicyGuard) and the FallbackPolicy check in New() used
// to set Action.Name = c.Request.Method directly -- the raw HTTP verb, not a
// logical action -- while RequirePARC (now requirePARCGuard) always set the
// logical action from its own cfg.parcAction. PermissionRule.Matches then
// accepted a match against EITHER Action.Name or Action.HTTPMethod, so a rule
// written for one action model silently granted the other. authz/parc.go's
// PermissionRule.Matches now checks Action.Name only; this file supplies the
// "explicit route->action map" the gap analysis calls for, so every call site
// in this package populates Action.Name with a logical action instead of the
// raw verb.

// defaultMethodActions is the built-in HTTP-verb -> logical-action mapping,
// following ordinary REST convention. GET/HEAD/OPTIONS all map to "read" (the
// least-privilege choice for verbs that conventionally have no side effect);
// POST maps to "create"; PUT/PATCH map to "update"; DELETE maps to "delete".
var defaultMethodActions = map[string]string{
	http.MethodGet:     "read",
	http.MethodHead:    "read",
	http.MethodOptions: "read",
	http.MethodPost:    "create",
	http.MethodPut:     "update",
	http.MethodPatch:   "update",
	http.MethodDelete:  "delete",
}

// ActionResolver derives the logical action name for an incoming request,
// used by requirePolicyGuard and New()'s FallbackPolicy check wherever no
// more specific action is already known (WithPARC/requirePARCGuard always
// supplies its own explicit logical action and never consults this).
type ActionResolver func(method string) string

// defaultActionResolver is DefaultActionResolver by another name, used
// wherever no MiddlewareOption/RequireOption override is supplied.
func defaultActionResolver(method string) string {
	if a, ok := defaultMethodActions[method]; ok {
		return a
	}
	// An unmapped verb (e.g. a nonstandard method) maps to itself. This can
	// only ever make a rule pinned to that literal, unusual verb string match
	// -- it never falls back to a permissive default, and Action.HTTPMethod
	// is no longer consulted by PermissionRule.Matches at all, so this can
	// never widen a grant beyond what an explicit rule spells out.
	return method
}

// DefaultActionResolver returns the library's built-in HTTP-verb -> logical-
// action mapping (GET/HEAD/OPTIONS->"read", POST->"create", PUT/PATCH->"update",
// DELETE->"delete"). Exposed so callers can wrap or override part of it via
// WithActionResolver while falling back to the rest.
func DefaultActionResolver(method string) string {
	return defaultActionResolver(method)
}

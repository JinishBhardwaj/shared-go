package gin

import (
	"net/http"
	"path"
	"sync"

	"github.com/gin-gonic/gin"
)

// This file replaces the former strings.Contains(c.HandlerNames(), "...")
// route-detection hack (gap-analysis-final.md Tier 1, line 97: "breaks under
// renames and wrappers and false-positives on any consumer handler whose
// name contains Authorize") with real, explicit, registration-time route
// metadata -- Group / ProtectGroup, matching the doc's own recommended fix.
//
// An earlier attempt in this same gate tried a runtime, identity-based
// detection scheme instead (comparing c.HandlerNames() by exact equality
// against the compiler-assigned qualified name of Require's and
// AllowAnonymous's own closures, computed once via
// runtime.FuncForPC(reflect.ValueOf(fn).Pointer()).Name()). That was
// implemented, then adversarially tested against itself (a throwaway debug
// test print of the computed names) and found to be UNSOUND, not just
// theoretically risky: Go's inliner rewrites a trivially small function's
// returned closure's symbol name to be relative to ITS CALL SITE once
// inlined (observed directly: the exact same AllowAnonymous() call produced
// "...gin.init.AllowAnonymous.func2" from one call site and
// "...gin.TestZZDebugNames.AllowAnonymous.func1" from another, in the same
// build). An exact-match check against a name precomputed at package init
// would therefore silently fail to recognize AllowAnonymous()/Require(...)
// at ANY other call site once the compiler chose to inline them -- a
// fail-open-shaped false negative that would have caused FallbackPolicy to
// be (wrongly) NOT skipped for a genuinely-annotated route... except the
// concrete symptom actually observed was the opposite and more visible
// (FallbackPolicy stayed engaged and correctly-annotated routes started
// returning 401), which is how this was caught before it shipped: the
// existing TestUseAuthorizationMiddleware/AllowAnonymous_succeeds_without_auth
// subtest went red the moment this was wired up. That approach was discarded
// entirely (not patched) in favor of the registration-time design below,
// which has no dependency on compiler inlining behavior at all.

// explicitRouteRegistry tracks (method, fullPath) pairs registered through
// Group/ProtectGroup -- populated once, at router-setup time, well before
// any request is served, and consulted read-only per request by New()'s
// FallbackPolicy enforcement via c.FullPath() (valid and accurate at that
// point: gin resolves routing, and therefore FullPath(), before any
// middleware in the matched route's chain executes).
//
// KNOWN LIMITATION, accepted as-is (not fixed in this gate): this registry
// is a single package-level (process-global) map, keyed only on (method,
// fullPath) -- it is NOT scoped to a particular *gin.Engine/*gin.RouterGroup
// instance. Two independent routers in the same process that happen to
// register the same (method, path) pair share one entry: if either router
// marks it explicit via Group/ProtectGroup, FallbackPolicy is skipped for
// that path on BOTH routers, even one that never called Group itself for
// it. This is accepted rather than fixed because the real deployment shape
// for this library is one router per process (one gin.Engine serving one
// authz-protected surface); multi-router-per-process is not a supported or
// observed usage pattern here. If that ever changes, the fix is to key the
// registry per *gin.Engine (or per RouteGroup root) instead of process-wide.
var explicitRouteRegistry = struct {
	mu sync.RWMutex
	m  map[string]struct{}
}{m: make(map[string]struct{})}

func markExplicitRoute(method, fullPath string) {
	explicitRouteRegistry.mu.Lock()
	defer explicitRouteRegistry.mu.Unlock()
	explicitRouteRegistry.m[method+" "+fullPath] = struct{}{}
}

// hasExplicitAuthAnnotation reports whether the route matched for c was
// registered through Group/ProtectGroup -- i.e. whether the application
// developer explicitly took responsibility for this route's authorization,
// regardless of which specific guard (if any) is actually attached to it.
func hasExplicitAuthAnnotation(c *gin.Context) bool {
	explicitRouteRegistry.mu.RLock()
	defer explicitRouteRegistry.mu.RUnlock()
	_, ok := explicitRouteRegistry.m[c.Request.Method+" "+c.FullPath()]
	return ok
}

// joinPaths mirrors gin's own unexported joinPaths (routergroup.go /
// utils.go): path.Join plus preserving a trailing slash on relativePath.
// Needed here because RouteGroup computes the same absolute route path gin
// computes internally (and later reports via c.FullPath()), using only
// gin's exported RouterGroup.BasePath().
func joinPaths(absolutePath, relativePath string) string {
	if relativePath == "" {
		return absolutePath
	}
	finalPath := path.Join(absolutePath, relativePath)
	if len(relativePath) > 0 && relativePath[len(relativePath)-1] == '/' &&
		(len(finalPath) == 0 || finalPath[len(finalPath)-1] != '/') {
		return finalPath + "/"
	}
	return finalPath
}

// RouteGroup wraps a *gin.RouterGroup so that every route registered
// through it (GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD/Any/Handle) is recorded
// in explicitRouteRegistry -- explicit, registration-time metadata,
// replacing the former runtime handler-name inspection. Group itself
// attaches no middleware; ProtectGroup additionally attaches a
// Require(WithPolicyName(...)) guard at the group level.
type RouteGroup struct {
	rg *gin.RouterGroup
}

// Group wraps rg so that every route subsequently registered through the
// returned RouteGroup is recorded as having explicit authorization handling
// -- regardless of which guard(s) (if any) are actually attached to it.
// This is the explicit metadata that fulfills gap-analysis-final.md Tier 1
// line 97's "authz.Group(policy)" naming (used bare, with no policy, this is
// the mechanism for marking a route as deliberately exempt, e.g. combined
// with AllowAnonymous()).
func Group(rg *gin.RouterGroup) *RouteGroup {
	return &RouteGroup{rg: rg}
}

// ProtectGroup is Group(rg) with Require(WithPolicyName(policyName), opts...)
// attached as automatic group-level middleware -- fulfilling both of the gap
// doc's names for this idea (Tier 1 line 97's authz.Group(policy) and Tier 4
// / §1.6 item 7's ProtectGroup; the doc itself notes they converge).
func ProtectGroup(rg *gin.RouterGroup, policyName string, opts ...RequireOption) *RouteGroup {
	rg.Use(Require(append([]RequireOption{WithPolicyName(policyName)}, opts...)...))
	return Group(rg)
}

// Use adds middleware to the wrapped group (mirrors gin.RouterGroup.Use).
func (g *RouteGroup) Use(handlers ...gin.HandlerFunc) *RouteGroup {
	g.rg.Use(handlers...)
	return g
}

// Group creates a nested RouteGroup (mirrors gin.RouterGroup.Group); routes
// registered under it are independently marked explicit too.
func (g *RouteGroup) Group(relativePath string, handlers ...gin.HandlerFunc) *RouteGroup {
	return &RouteGroup{rg: g.rg.Group(relativePath, handlers...)}
}

func (g *RouteGroup) mark(method, relativePath string) {
	markExplicitRoute(method, joinPaths(g.rg.BasePath(), relativePath))
}

// GET registers a GET route, recording it as explicit.
func (g *RouteGroup) GET(relativePath string, handlers ...gin.HandlerFunc) *RouteGroup {
	g.mark(http.MethodGet, relativePath)
	g.rg.GET(relativePath, handlers...)
	return g
}

// POST registers a POST route, recording it as explicit.
func (g *RouteGroup) POST(relativePath string, handlers ...gin.HandlerFunc) *RouteGroup {
	g.mark(http.MethodPost, relativePath)
	g.rg.POST(relativePath, handlers...)
	return g
}

// PUT registers a PUT route, recording it as explicit.
func (g *RouteGroup) PUT(relativePath string, handlers ...gin.HandlerFunc) *RouteGroup {
	g.mark(http.MethodPut, relativePath)
	g.rg.PUT(relativePath, handlers...)
	return g
}

// PATCH registers a PATCH route, recording it as explicit.
func (g *RouteGroup) PATCH(relativePath string, handlers ...gin.HandlerFunc) *RouteGroup {
	g.mark(http.MethodPatch, relativePath)
	g.rg.PATCH(relativePath, handlers...)
	return g
}

// DELETE registers a DELETE route, recording it as explicit.
func (g *RouteGroup) DELETE(relativePath string, handlers ...gin.HandlerFunc) *RouteGroup {
	g.mark(http.MethodDelete, relativePath)
	g.rg.DELETE(relativePath, handlers...)
	return g
}

// OPTIONS registers an OPTIONS route, recording it as explicit.
func (g *RouteGroup) OPTIONS(relativePath string, handlers ...gin.HandlerFunc) *RouteGroup {
	g.mark(http.MethodOptions, relativePath)
	g.rg.OPTIONS(relativePath, handlers...)
	return g
}

// HEAD registers a HEAD route, recording it as explicit.
func (g *RouteGroup) HEAD(relativePath string, handlers ...gin.HandlerFunc) *RouteGroup {
	g.mark(http.MethodHead, relativePath)
	g.rg.HEAD(relativePath, handlers...)
	return g
}

// Handle registers a route for an arbitrary HTTP method, recording it as
// explicit (mirrors gin.RouterGroup.Handle).
func (g *RouteGroup) Handle(httpMethod, relativePath string, handlers ...gin.HandlerFunc) *RouteGroup {
	g.mark(httpMethod, relativePath)
	g.rg.Handle(httpMethod, relativePath, handlers...)
	return g
}

// Any registers relativePath for every method gin.RouterGroup.Any covers,
// recording each one as explicit.
func (g *RouteGroup) Any(relativePath string, handlers ...gin.HandlerFunc) *RouteGroup {
	for _, method := range []string{
		http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodHead, http.MethodOptions, http.MethodDelete,
		http.MethodConnect, http.MethodTrace,
	} {
		g.mark(method, relativePath)
	}
	g.rg.Any(relativePath, handlers...)
	return g
}

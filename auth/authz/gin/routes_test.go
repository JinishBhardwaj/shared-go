package gin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JinishBhardwaj/shared-go/auth/authz"
	"github.com/JinishBhardwaj/shared-go/auth/principal"
	ginprincipal "github.com/JinishBhardwaj/shared-go/auth/principal/gin"
	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// TestRequire_PanicsOnNoModeOption confirms Require fails fast (at
// construction time, not at first request) when no requirement-defining
// option is supplied -- a static configuration error.
func TestRequire_PanicsOnNoModeOption(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected Require() with no options to panic")
		}
	}()
	Require()
}

// TestRequire_PanicsOnConflictingModeOptions confirms Require fails fast
// when more than one requirement-defining option is supplied -- ambiguous
// configuration, always a caller bug.
func TestRequire_PanicsOnConflictingModeOptions(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected Require(WithPolicyName, WithScopes) to panic on conflicting modes")
		}
	}()
	Require(WithPolicyName("X"), WithScopes("read"))
}

// TestAuthorizeResource_HonorsAllowAnonymous is the regression test for G6's
// "make AllowAnonymous real" (gap-analysis-final.md Tier 1 line 96, item 2):
// before this gate, grepping confirmed nothing anywhere ever read
// ContextKeyAllowAnonymous back. AuthorizeResource now does. A route marked
// AllowAnonymous() must let AuthorizeResource succeed even against a policy
// that would otherwise deny the (nil) principal.
func TestAuthorizeResource_HonorsAllowAnonymous(t *testing.T) {
	engine := authz.NewPolicyEngine()
	engine.RegisterPolicy(authz.NewPolicy("EditPolicy").RequireRole("editor").Build())

	r := gin.New()
	r.Use(UseAuthorization(engine))

	pub := Group(&r.RouterGroup)
	pub.GET("/anon-resource", AllowAnonymous(), func(c *gin.Context) {
		// No principal was ever set on this request at all -- if
		// AuthorizeResource did not honor AllowAnonymous, this would fail
		// closed (FailedResult, "Authentication required").
		result := AuthorizeResource(c, authz.Resource{Type: "doc", ID: "1"}, "EditPolicy")
		if !result.Succeeded {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": result.FailureReason})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req, _ := http.NewRequest(http.MethodGet, "/anon-resource", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected AuthorizeResource to short-circuit to success on an AllowAnonymous route, got %d: %s", w.Code, w.Body.String())
	}
}

// TestAuthorizeResource_WithoutAllowAnonymous_StillEnforces is the negative
// counterpart: without AllowAnonymous(), AuthorizeResource must still deny a
// nil principal exactly as before -- confirming the new read-side of
// ContextKeyAllowAnonymous did not loosen the default (unmarked) path at all.
func TestAuthorizeResource_WithoutAllowAnonymous_StillEnforces(t *testing.T) {
	engine := authz.NewPolicyEngine()
	engine.RegisterPolicy(authz.NewPolicy("EditPolicy").RequireRole("editor").Build())

	r := gin.New()
	r.Use(UseAuthorization(engine))
	r.GET("/resource", func(c *gin.Context) {
		result := AuthorizeResource(c, authz.Resource{Type: "doc", ID: "1"}, "EditPolicy")
		if !result.Succeeded {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": result.FailureReason})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req, _ := http.NewRequest(http.MethodGet, "/resource", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected AuthorizeResource to still deny an unauthenticated caller without AllowAnonymous, got %d", w.Code)
	}
}

// TestProtectGroup_SkipsFallbackPolicy_DirectAttachDoesNot demonstrates the
// deliberate, documented behavior of the final Group/ProtectGroup design
// (routes.go): FallbackPolicy-skip recognition is purely registration-time
// metadata, independent of which guard (if any) is attached. A route
// guarded by Require(...) but registered directly on the raw router (no
// Group) is NOT recognized and still gets FallbackPolicy applied on top;
// the same guard registered via ProtectGroup IS recognized and the
// redundant FallbackPolicy layer is skipped.
func TestProtectGroup_SkipsFallbackPolicy_DirectAttachDoesNot(t *testing.T) {
	engine := authz.NewPolicyEngine()
	engine.RegisterPolicy(authz.NewPolicy("ScopedPolicy").RequireScope("read:x").Build())

	buildRouter := func(useGroup bool) *gin.Engine {
		r := gin.New()
		r.Use(func(c *gin.Context) {
			// Principal satisfies ScopedPolicy (has the scope) but NOT
			// FallbackPolicy (RequireUser -- an interactive-user method),
			// since it authenticates as a machine client. This
			// deliberately separates "does the route's own guard pass"
			// from "does FallbackPolicy also apply and fail."
			ginprincipal.Set(c, &principal.Principal{
				Subject: "svc1",
				Scopes:  []string{"read:x"},
				Method:  principal.AuthMethodClientCredentials,
			})
			c.Next()
		})
		r.Use(UseAuthorization(engine,
			WithFallbackPolicy(authz.NewPolicy("Fallback").RequireUser().Build()),
		))

		if useGroup {
			g := ProtectGroup(&r.RouterGroup, "ScopedPolicy", WithEngine(engine))
			g.GET("/scoped", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})
		} else {
			guard := Require(WithEngine(engine), WithPolicyName("ScopedPolicy"))
			r.GET("/scoped", guard, func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})
		}
		return r
	}

	t.Run("direct attach (no Group): FallbackPolicy still applies and denies", func(t *testing.T) {
		r := buildRouter(false)
		req, _ := http.NewRequest(http.MethodGet, "/scoped", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		// G8-5: authz never emits 401 (that's authn's job), so this
		// RequireUser-shaped FallbackPolicy denial is always 403, not 401 --
		// this principal IS present in context (it just fails the
		// FallbackPolicy's method requirement), so this exercises the
		// ordinary policy-denial path, not the no-principal path, but both
		// now converge on 403.
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected FallbackPolicy to still reject a client-credentials principal (RequireUser fails) with 403, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("registered via Group: FallbackPolicy is skipped, route's own guard governs", func(t *testing.T) {
		r := buildRouter(true)
		req, _ := http.NewRequest(http.MethodGet, "/scoped", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected the route's own ScopedPolicy guard (which this principal satisfies) to govern once registered via Group, got %d: %s", w.Code, w.Body.String())
		}
	})
}

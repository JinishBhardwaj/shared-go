package gin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JinishBhardwaj/shared-go/auth/authz"
	"github.com/JinishBhardwaj/shared-go/auth/principal"
	ginprincipal "github.com/JinishBhardwaj/shared-go/auth/principal/gin"
	"github.com/gin-gonic/gin"
)

// TestRequirePolicyGuard_UsesLogicalActionNotRawVerb is the end-to-end,
// through-the-gin-layer regression test for Tier 1 line 98 ("Unify action
// semantics"). Before this fix, requirePolicyGuard (the former Authorize/
// WithPolicy/RequirePolicy) set Action.Name = c.Request.Method -- the raw
// HTTP verb -- while PermissionRule.Matches accepted a match against either
// Action.Name or Action.HTTPMethod. A stored rule pinned to the literal verb
// "POST" would therefore grant a request through a named-policy PARCRequirement
// authored against the logical action "create", and vice versa. This test
// proves: (a) a rule pinned to the logical action "create" now grants a POST
// request routed through WithPolicyName, and (b) a rule pinned to the raw
// verb "POST" does NOT grant that same request, because Action.Name is now
// always the mapped logical action, never the raw verb, and Matches no
// longer consults HTTPMethod at all.
func TestRequirePolicyGuard_UsesLogicalActionNotRawVerb(t *testing.T) {
	gin.SetMode(gin.TestMode)

	newRouter := func(rule authz.PermissionRule) *gin.Engine {
		repo := authz.NewMemoryPermissionRepository()
		_ = repo.GrantPermission(context.Background(), &principal.Principal{Subject: "creator_1"}, rule)

		parcHandler, _ := authz.NewPARCHandler(authz.PARCHandlerConfig{Repository: repo})
		engine := authz.NewPolicyEngine(parcHandler)
		engine.RegisterPolicy(authz.NewPolicy("CreateWidget").
			AddRequirement(authz.PARCRequirement{Action: "create", ResourceType: "widget"}).
			Build())

		r := gin.New()
		r.Use(func(c *gin.Context) {
			ginprincipal.Set(c, &principal.Principal{
				Subject:     "creator_1",
				Method:      principal.AuthMethodAuthCodePKCE,
				UserPresent: true,
			})
			c.Next()
		})
		r.POST("/widgets", Require(WithEngine(engine), WithPolicyName("CreateWidget")), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "created"})
		})
		return r
	}

	t.Run("rule pinned to the logical action 'create' grants a POST request", func(t *testing.T) {
		r := newRouter(authz.PermissionRule{
			ActionPattern:     "create",
			ResourceType:      "widget",
			ResourceIDPattern: "*",
			Effect:            authz.EffectPermit,
		})
		req, _ := http.NewRequest(http.MethodPost, "/widgets", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for a rule matching the logical action, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("rule pinned to the raw verb 'POST' does NOT grant, since Action.Name is the mapped logical action", func(t *testing.T) {
		r := newRouter(authz.PermissionRule{
			ActionPattern:     "POST",
			ResourceType:      "widget",
			ResourceIDPattern: "*",
			Effect:            authz.EffectPermit,
		})
		req, _ := http.NewRequest(http.MethodPost, "/widgets", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code == http.StatusOK {
			t.Fatalf("expected a rule pinned to the raw verb 'POST' NOT to grant a request whose logical action is 'create', but got 200 OK")
		}
	})
}

// TestDefaultActionResolver_MapsCommonVerbs pins down the built-in
// HTTP-verb -> logical-action mapping so a future change to it is a
// deliberate, reviewed edit rather than an accidental drift.
func TestDefaultActionResolver_MapsCommonVerbs(t *testing.T) {
	cases := map[string]string{
		http.MethodGet:     "read",
		http.MethodHead:    "read",
		http.MethodOptions: "read",
		http.MethodPost:    "create",
		http.MethodPut:     "update",
		http.MethodPatch:   "update",
		http.MethodDelete:  "delete",
	}
	for method, want := range cases {
		if got := DefaultActionResolver(method); got != want {
			t.Errorf("DefaultActionResolver(%q) = %q, want %q", method, got, want)
		}
	}
}

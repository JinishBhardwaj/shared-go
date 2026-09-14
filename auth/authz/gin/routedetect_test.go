package gin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JinishBhardwaj/shared-go/auth/authz"
	"github.com/gin-gonic/gin"
)

// consumerAuthorizeReports is a stand-in for a hypothetical consumer
// application's OWN, entirely unrelated handler that just happens to have
// "Authorize" in its name (e.g. a report-authoring feature, nothing to do
// with this package's authorization guards). It performs no authentication
// or authorization check at all -- it is deliberately a no-op that always
// lets the request through.
//
// This is the literal false-positive scenario named in gap-analysis-final.md
// Tier 1 line 97: "false-positives on any consumer handler whose own name
// happens to contain e.g. Authorize." Before this gate's fix, New()'s
// FallbackPolicy enforcement detected "explicit auth" via
// strings.Contains(c.HandlerNames(), "Authorize"), which this handler's own
// runtime name satisfies purely by coincidence, causing FallbackPolicy to be
// skipped for a route that has NO real authorization check at all -- a
// genuine fail-open defect. After the fix (routes.go: Group/ProtectGroup,
// registration-time metadata, not runtime name inspection at all), this
// route -- registered directly on the raw router, not through Group -- is
// simply never in explicitRouteRegistry, regardless of what this handler is
// named, so FallbackPolicy always applies to it.
func consumerAuthorizeReports(c *gin.Context) {
	c.Next()
}

// TestFallbackPolicy_DoesNotFalsePositiveOnUnrelatedConsumerHandlerName is
// the adversarial regression test for gap-analysis-final.md Tier 1 line 97
// (G6, item 1). Confirmed red against the pre-fix
// strings.Contains(c.HandlerNames(), "Authorize"|...) hack: a request with
// NO principal at all reached the final handler and returned 200, when it
// should have been rejected by FallbackPolicy at 401. Confirmed green after
// the fix.
func TestFallbackPolicy_DoesNotFalsePositiveOnUnrelatedConsumerHandlerName(t *testing.T) {
	gin.SetMode(gin.TestMode)

	engine := authz.NewPolicyEngine()

	r := gin.New()
	r.Use(UseAuthorization(engine,
		WithFallbackPolicy(authz.NewPolicy("Fallback").RequireUser().Build()),
	))

	// No authn middleware at all in this router: no principal is ever set.
	// consumerAuthorizeReports performs no auth check of its own -- this
	// route is, in truth, completely unprotected. FallbackPolicy is the
	// ONLY thing standing between an anonymous caller and this handler.
	r.GET("/reports", consumerAuthorizeReports, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "reports"})
	})

	req, _ := http.NewRequest(http.MethodGet, "/reports", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected FallbackPolicy to reject an unauthenticated request to an "+
			"unprotected route whose only handler coincidentally contains \"Authorize\" "+
			"in its name; got %d (body: %s) -- this is the Tier 1 line 97 false-positive "+
			"fail-open defect", w.Code, w.Body.String())
	}
}

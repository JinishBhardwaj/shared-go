package pipeline

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	authngin "github.com/JinishBhardwaj/shared-go/auth/authn/gin"
	"github.com/JinishBhardwaj/shared-go/auth/authz"
	authzgin "github.com/JinishBhardwaj/shared-go/auth/authz/gin"
	"github.com/JinishBhardwaj/shared-go/auth/principal"
	"github.com/gin-gonic/gin"
)

// stubBearerValidator is a minimal BearerTokenValidator stub (per this
// task's instructions: "any stub satisfying BearerTokenValidator"),
// mapping a small fixed set of fake tokens to principals so tests don't
// need a real signed JWT.
type stubBearerValidator struct{}

func (stubBearerValidator) ValidateToken(ctx context.Context, tokenStr string) (*principal.Principal, error) {
	switch tokenStr {
	case "admin-token":
		return &principal.Principal{Subject: "admin-user", Roles: []string{"admin"}}, nil
	case "user-token":
		return &principal.Principal{Subject: "regular-user", Roles: []string{"user"}}, nil
	default:
		return nil, errors.New("stubBearerValidator: unrecognized token")
	}
}

// validConfig returns a Config wired with a working AuthenticationBuilder
// (stubBearerValidator) and a working AuthorizationBuilder (an "AdminOnly"
// policy requiring the "admin" role), suitable for the request-level tests
// below.
func validConfig() Config {
	return Config{
		Authentication: authngin.NewBuilder().WithBearerValidator(stubBearerValidator{}),
		Authorization: authzgin.NewBuilder().
			AddPolicy("AdminOnly", authz.NewPolicyBuilder().RequireRole("admin").Build()),
	}
}

func TestSetup_MissingAuthenticationBuilder(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	cfg := Config{
		Authorization: authzgin.NewBuilder(),
	}

	engine, err := Setup(r, cfg)
	if !errors.Is(err, ErrNoAuthenticationBuilder) {
		t.Fatalf("expected ErrNoAuthenticationBuilder, got %v", err)
	}
	if engine != nil {
		t.Fatalf("expected nil engine on error, got %v", engine)
	}
}

func TestSetup_MissingAuthorizationBuilder(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	cfg := Config{
		Authentication: authngin.NewBuilder().WithBearerValidator(stubBearerValidator{}),
	}

	engine, err := Setup(r, cfg)
	if !errors.Is(err, ErrNoAuthorizationBuilder) {
		t.Fatalf("expected ErrNoAuthorizationBuilder, got %v", err)
	}
	if engine != nil {
		t.Fatalf("expected nil engine on error, got %v", engine)
	}
}

// TestSetup_ReturnsTheSameEngineWiredIntoMiddleware is the critical test: it
// proves the *authz.PolicyEngine Setup returns is the SAME instance that
// UseAuthorization wired into the router's middleware chain, not a second,
// independently-constructed engine (the exact bug class
// BuildEngineAndMiddleware exists to prevent -- calling Build() and
// BuildMiddleware() separately would allocate two different
// *authz.PolicyEngine values from two independent NewAuthorizationService
// calls). The authz middleware stores the engine it was built with in the
// gin context under authzgin.ContextKeyAuthorizationService; the test route
// below reads it back out and asserts pointer identity against the engine
// Setup returned, then separately exercises real HTTP requests through
// Require(WithEngine(engine), ...) to confirm that engine actually
// evaluates the registered "AdminOnly" policy correctly end-to-end.
func TestSetup_ReturnsTheSameEngineWiredIntoMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	engine, err := Setup(r, validConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}

	r.GET("/admin", authzgin.Require(authzgin.WithEngine(engine), authzgin.WithPolicyName("AdminOnly")), func(c *gin.Context) {
		val, exists := c.Get(authzgin.ContextKeyAuthorizationService)
		if !exists {
			c.String(http.StatusInternalServerError, "no authorization service in context")
			return
		}
		contextEngine, ok := val.(*authz.PolicyEngine)
		if !ok {
			c.String(http.StatusInternalServerError, "context value is not *authz.PolicyEngine")
			return
		}
		if contextEngine != engine {
			c.String(http.StatusInternalServerError, "different engine instance wired into middleware than the one Setup returned")
			return
		}
		c.String(http.StatusOK, "admin granted")
	})

	// A principal with the admin role, evaluated by the SAME engine
	// instance both through the middleware chain and through Require's
	// explicit WithEngine(engine), succeeds.
	req, _ := http.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != "admin granted" {
		t.Errorf("unexpected body (engine-identity check failed?): %s", w.Body.String())
	}

	// A principal without the admin role is correctly denied by the same
	// policy/engine.
	req2, _ := http.NewRequest(http.MethodGet, "/admin", nil)
	req2.Header.Set("Authorization", "Bearer user-token")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for non-admin principal, got %d: %s", w2.Code, w2.Body.String())
	}
}

// TestSetup_RegistersAuthenticationBeforeAuthorization confirms that
// Setup's router.Use(authnMiddleware, authzMiddleware) call genuinely runs
// authentication before authorization. authn/gin's middleware aborts with
// 401 on any authentication failure (including "no credentials at all"),
// while authz/gin's Require(WithPolicyName(...)) guard, per
// gap-analysis-final.md Tier 2 line 107 (G8-5), never emits 401 itself --
// a missing principal there is answered with 403. So an unauthenticated
// request to a route guarded by Require(WithPolicyName(...)) can only come
// back 401 if authn's middleware ran first and aborted the chain before the
// route's own Require guard (which never runs authn) had a chance to
// execute at all; if authz ran first, this would be a 403 like the
// non-admin-principal case in TestSetup_ReturnsTheSameEngineWiredIntoMiddleware.
func TestSetup_RegistersAuthenticationBeforeAuthorization(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	engine, err := Setup(r, validConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r.GET("/admin", authzgin.Require(authzgin.WithEngine(engine), authzgin.WithPolicyName("AdminOnly")), func(c *gin.Context) {
		c.String(http.StatusOK, "admin granted")
	})

	// No Authorization header at all.
	req, _ := http.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized (proving authn ran and aborted before authz's Require guard), got %d: %s", w.Code, w.Body.String())
	}
}

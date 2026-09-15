// Package example_test provides the complete, compiling, runnable
// authn -> authz -> handler walkthrough that auth/README.md's "End-to-end
// example" section is drawn from verbatim (gap-analysis-final.md Tier 4
// line 132, README half -- the one-call bootstrap itself, pipeline.Setup,
// already shipped in an earlier gate; this file is only the missing README
// walkthrough, backed by real code so it can't silently drift out of sync).
//
// It lives at the module root, in its own external test package, because it
// is meant to read as a tour of the WHOLE module (authn/gin, authz/gin,
// principal/gin, pipeline) rather than belonging to any one of them.
package example_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	authngin "github.com/JinishBhardwaj/shared-go/auth/authn/gin"
	"github.com/JinishBhardwaj/shared-go/auth/authz"
	authzgin "github.com/JinishBhardwaj/shared-go/auth/authz/gin"
	"github.com/JinishBhardwaj/shared-go/auth/pipeline"
	"github.com/JinishBhardwaj/shared-go/auth/principal"
	ginprincipal "github.com/JinishBhardwaj/shared-go/auth/principal/gin"
	"github.com/gin-gonic/gin"
)

// exampleBearerValidator is a minimal authngin.BearerTokenValidator stub,
// standing in for a real validator (e.g. authngin.WithCognito(...)) so this
// example has no network dependency. It maps two fixed bearer tokens to
// principals: "admin-token" (role "admin") and "alice-token" (an ordinary
// user, granted PARC access to one specific order below).
type exampleBearerValidator struct{}

func (exampleBearerValidator) ValidateToken(ctx context.Context, token string) (*principal.Principal, error) {
	switch token {
	case "admin-token":
		return &principal.Principal{Subject: "admin-user", Roles: []string{"admin"}}, nil
	case "alice-token":
		return &principal.Principal{Subject: "alice", Roles: []string{"user"}}, nil
	default:
		return nil, errors.New("exampleBearerValidator: unrecognized token")
	}
}

// TestReadmeExample_EndToEnd builds the full authn -> authz -> handler
// pipeline with pipeline.Setup and exercises it with real HTTP requests via
// httptest. This is the literal source auth/README.md's end-to-end code
// block is drawn from -- keep the two in sync if you touch either.
func TestReadmeExample_EndToEnd(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// --- authn: "who is this?" ------------------------------------------
	authentication := authngin.NewBuilder().
		WithBearerValidator(exampleBearerValidator{})

	// --- authz: "what may they do?" --------------------------------------
	// A named policy ("AdminOnly") for a coarse-grained role check, plus a
	// PARC (Principal-Action-Resource-Context) repository granting alice
	// permission to read order "order-1" specifically, for a fine-grained
	// per-resource check.
	permissions := authz.NewMemoryPermissionRepository()
	if err := permissions.GrantPermission(context.Background(), "alice", authz.PermissionRule{
		ActionPattern:     "read",
		ResourceType:      "order",
		ResourceIDPattern: "order-1",
		Effect:            authz.EffectPermit,
	}); err != nil {
		t.Fatalf("unexpected error granting permission: %v", err)
	}

	authorization := authzgin.NewBuilder().
		AddPolicy("AdminOnly", authz.NewPolicyBuilder().RequireRole("admin").Build()).
		WithMemoryPARC(5*time.Minute, permissions)

	// --- wire authn + authz together in one call -------------------------
	router := gin.New()
	engine, err := pipeline.Setup(router, pipeline.Config{
		Authentication: authentication,
		Authorization:  authorization,
	})
	if err != nil {
		t.Fatalf("pipeline.Setup: %v", err)
	}

	// A named-policy-guarded route: only "admin" role principals pass.
	router.GET("/admin", authzgin.Require(authzgin.WithEngine(engine), authzgin.WithPolicyName("AdminOnly")),
		func(c *gin.Context) {
			user := ginprincipal.MustUser(c)
			c.String(http.StatusOK, "hello admin %s", user.Subject)
		})

	// A PARC-guarded route with route-param resource extraction: the
	// resource ID comes straight from the :id path param, so "GET
	// /orders/order-1" is evaluated as read access to resource
	// {Type: "order", ID: "order-1"}.
	router.GET("/orders/:id",
		authzgin.Require(
			authzgin.WithEngine(engine),
			authzgin.WithPARC("read", "order"),
			authzgin.WithResource(authzgin.ExtractResourceFromParam("id", "order")),
		),
		func(c *gin.Context) {
			user := ginprincipal.MustUser(c)
			c.JSON(http.StatusOK, gin.H{"order_id": c.Param("id"), "requested_by": user.Subject})
		})

	// admin-token has the "admin" role -> 200.
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /admin as admin: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// alice-token lacks the "admin" role -> 403 (authz never emits 401;
	// that's authn's job).
	req = httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Authorization", "Bearer alice-token")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("GET /admin as alice: expected 403, got %d: %s", w.Code, w.Body.String())
	}

	// alice was granted read access to order-1 specifically -> 200.
	req = httptest.NewRequest(http.MethodGet, "/orders/order-1", nil)
	req.Header.Set("Authorization", "Bearer alice-token")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /orders/order-1 as alice: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// alice was NOT granted access to order-2 -> 403.
	req = httptest.NewRequest(http.MethodGet, "/orders/order-2", nil)
	req.Header.Set("Authorization", "Bearer alice-token")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("GET /orders/order-2 as alice: expected 403, got %d: %s", w.Code, w.Body.String())
	}

	// No credentials at all -> 401 (authn's job; runs before any authz
	// guard, so an unauthenticated request never even reaches Require's
	// own "no principal" 403 path).
	req = httptest.NewRequest(http.MethodGet, "/orders/order-1", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("GET /orders/order-1 unauthenticated: expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

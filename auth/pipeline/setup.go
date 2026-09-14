// Package pipeline provides the one-call authn+authz bootstrap named in
// gap-analysis-final.md Tier 4, line 132: "security.Setup(router, cfg)"
// one-call bootstrap" (this task, G9-8, covers only that bootstrap; route-
// param-resource-extraction defaults and the README example named in the
// same line are out of scope, tracked separately).
//
// Per §3.4 of the design doc (target package layout), pipeline is the ONLY
// package allowed to import both auth/authn/gin and auth/authz/gin in the
// same file -- it sits above both, composing them, and is exempt from the
// authz-must-not-depend-on-authn CI check (auth/scripts/check-no-authn-dep.sh),
// which only ever constrains the authz package itself, not new sibling
// packages such as this one.
package pipeline

import (
	"errors"
	"fmt"

	authngin "github.com/JinishBhardwaj/shared-go/auth/authn/gin"
	"github.com/JinishBhardwaj/shared-go/auth/authz"
	authzgin "github.com/JinishBhardwaj/shared-go/auth/authz/gin"
	"github.com/gin-gonic/gin"
)

// Config configures Setup's one-call authn+authz bootstrap.
type Config struct {
	// Authentication builds and wires the authn middleware. Required.
	Authentication *authngin.AuthenticationBuilder

	// Authorization builds and wires the authz middleware, and provides
	// the *authz.PolicyEngine returned by Setup for route-level
	// Require(WithEngine(engine), ...) calls. Required.
	Authorization *authzgin.AuthorizationBuilder
}

// ErrNoAuthenticationBuilder is returned by Setup when cfg.Authentication is
// nil -- fail at wire time, not request time (gap-analysis-final.md Tier 1
// line 100).
var ErrNoAuthenticationBuilder = errors.New("pipeline: Config.Authentication is required")

// ErrNoAuthorizationBuilder is returned by Setup when cfg.Authorization is
// nil -- fail at wire time, not request time (gap-analysis-final.md Tier 1
// line 100).
var ErrNoAuthorizationBuilder = errors.New("pipeline: Config.Authorization is required")

// Setup is the one-call authn -> authz bootstrap (gap-analysis-final.md
// Tier 4 line 132, pipeline-bootstrap half): it builds the authentication
// middleware, builds the authorization engine and its middleware (as ONE
// shared instance -- see AuthorizationBuilder.BuildEngineAndMiddleware),
// and registers both on router IN ORDER (authentication first, so a
// principal is on the gin context before any authorization check runs --
// authz/gin's own Require(...) already assumes this, since G7 made
// WithEngine mandatory rather than falling back to a context-resolved
// engine at request time for a DIFFERENT reason, but the ordering
// requirement is the same: authz must run after authn).
//
// Returns the constructed *authz.PolicyEngine so calling code can wire
// per-route guards via authzgin.Require(authzgin.WithEngine(engine), ...)
// or authzgin.ProtectGroup(rg, policyName, authzgin.WithEngine(engine)).
func Setup(router gin.IRouter, cfg Config) (*authz.PolicyEngine, error) {
	if cfg.Authentication == nil {
		return nil, ErrNoAuthenticationBuilder
	}
	if cfg.Authorization == nil {
		return nil, ErrNoAuthorizationBuilder
	}

	authnMiddleware, err := cfg.Authentication.BuildMiddleware()
	if err != nil {
		return nil, fmt.Errorf("pipeline: authentication setup failed: %w", err)
	}

	engine, authzMiddleware, err := cfg.Authorization.BuildEngineAndMiddleware()
	if err != nil {
		return nil, fmt.Errorf("pipeline: authorization setup failed: %w", err)
	}

	router.Use(authnMiddleware, authzMiddleware)

	return engine, nil
}

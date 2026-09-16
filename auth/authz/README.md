# authz

PARC (Principal, Action, Resource, Context) authorization engine with ASP.NET Core Authorization conventions, wired onto Gin via `authz/gin`.

`authz` itself is framework-agnostic -- it never imports Gin. It evaluates a `*principal.Principal` (from `github.com/JinishBhardwaj/shared-go/auth/principal`, populated by `authn`) against `Policy`/`PermissionRule` definitions and produces a `Decision`/`AuthorizationResult`. `authz/gin` is the HTTP-layer adapter: middleware, route guards, and a fluent builder.

## Features

- **ASP.NET Core Authorization conventions, via `authz/gin`**:
  - `authzgin.UseAuthorization(service)` (mirrors `app.UseAuthorization()`): pipeline authorization middleware, enforcing `FallbackPolicy` on any route not registered through `Group`/`ProtectGroup`.
  - `authzgin.AllowAnonymous()` (mirrors `[AllowAnonymous]`): marks a route exempt from `FallbackPolicy` (only within a `Group`).
  - `authzgin.Require(opts ...RequireOption)` (mirrors `[Authorize(Policy = "...")]`): the single route-guard entry point -- `WithPolicyName`, `WithPARC(action, resourceType)`, `WithScopes`/`WithAnyScope`, `WithRoles`/`WithAnyRole`, `WithMethods`, `WithUserPresent`, `WithM2M`, plus `WithEngine` (required for policy/PARC modes) and `WithResource`/`WithActionResolver`.
  - `authzgin.AuthorizeResource(c, resource, "PolicyName")` (mirrors `await _authService.AuthorizeAsync(...)`): imperative in-handler check.
  - `authzgin.NewBuilder()` (mirrors `services.AddAuthorization(options => ...)`): `AddPolicy`, `WithDefaultPolicy`, `WithFallbackPolicy` (Zero-Trust default), `WithPARC`/`WithMemoryPARC`, `WithOnDecision`, `Build()`/`BuildMiddleware()`/`BuildEngineAndMiddleware()`.
- **PARC Authorization Model**:
  - **Principal**: authenticated caller ID, client ID, roles, scopes, auth method, and an `Attributes` bag (mapped 1:1 from `principal.Principal.Metadata`).
  - **Action**: verb or operation (e.g. `read`, `write`, `delete`, `approve`) -- matched only against the logical `Action.Name`, never `Action.HTTPMethod`.
  - **Resource**: target entity type, ID, and an `Attributes` bag for ABAC rules. No tenant/account field: which account a request is scoped to is a property of the *Principal* asking, resolved by `PermissionRepository.GetPermissions` before a rule ever reaches evaluation -- not a Resource concern, and not something a generic engine can check for arbitrary resource types anyway (that's the application's own data-access-layer job).
  - **Context**: request-runtime metadata (client IP, timestamp, headers, an arbitrary `Data` bag) -- available to custom `RequirementHandler`s, not matched by `PermissionRule` itself.
- **PARC caching, via `PARCHandler`** (`authz.NewPARCHandler`):
  - Backed by any `cache.Cache[T]` (`github.com/JinishBhardwaj/shared-go/cache`) -- defaults to the in-process `cache/memory` store if none is supplied; swap in `cache/rediscache` (Redis-backed) composed through `cache/tiered` (L1+L2, with `cache/invalidation`'s `Bus` propagating a `Delete` on one node to every other node sharing that L2) for a multi-instance deployment.
  - Soft/hard TTL (`GrantTTL`/`StaleTTL`) with stale-while-revalidate: a refresh failure (repository error, deadline exceeded, or an open circuit breaker) serves the last-known-good bundle rather than failing the request, until `StaleTTL` is exceeded.
  - Concurrent refreshes for the same cache key are collapsed into a single repository call (`golang.org/x/sync/singleflight`), each bounded by `RepoTimeout` and protected by a per-handler circuit breaker.
  - Revocation is explicit, not automatic: a caller pairs `PermissionRepository.RevokeAll` with a `cache.Delete` on the same key. With a tiered+Redis cache, that delete propagates to every instance via the invalidation bus; with the default in-process cache, it's local to that instance.
  - `CacheKeyFunc` (`PARCHandlerConfig`) lets a caller whose permissions vary by more than `Principal.Subject` (e.g. an active account read from `Metadata`) supply a cache key that reflects it -- `authz` has no built-in concept of "account"/"tenant" to default this correctly on its own.

## Installation

```bash
go get github.com/JinishBhardwaj/shared-go/auth
```

Import as `github.com/JinishBhardwaj/shared-go/auth/authz` (core, framework-agnostic) and `github.com/JinishBhardwaj/shared-go/auth/authz/gin` (Gin wiring).

## Fluent Chained Configuration

```go
// Mirrors builder.Services.AddAuthorization().AddPolicy().WithMemoryPARC()
authorization := authzgin.NewBuilder().
    AddPolicy("AdminOnly", authz.NewPolicyBuilder().RequireRole("admin").Build()).
    WithMemoryPARC(5*time.Minute, permissions)
```

`authorization` is then handed to `pipeline.Setup` alongside an `authngin.AuthenticationBuilder` -- see the end-to-end example below.

## Quick Start (end-to-end, real and runnable)

This mirrors `example_test.go` at the module root verbatim (that file is the source of truth this section is drawn from -- run `go test ./...` at the module root to see it pass).

```go
package main

import (
	"context"
	"errors"
	"net/http"
	"time"

	authngin "github.com/JinishBhardwaj/shared-go/auth/authn/gin"
	"github.com/JinishBhardwaj/shared-go/auth/authz"
	authzgin "github.com/JinishBhardwaj/shared-go/auth/authz/gin"
	"github.com/JinishBhardwaj/shared-go/auth/pipeline"
	"github.com/JinishBhardwaj/shared-go/auth/principal"
	ginprincipal "github.com/JinishBhardwaj/shared-go/auth/principal/gin"
	"github.com/gin-gonic/gin"
)

// exampleBearerValidator stands in for a real validator (e.g.
// authngin.WithCognito(...)) so this example has no network dependency.
type exampleBearerValidator struct{}

func (exampleBearerValidator) ValidateToken(ctx context.Context, token string) (*principal.Principal, error) {
	switch token {
	case "admin-token":
		return &principal.Principal{Subject: "admin-user", Roles: []string{"admin"}}, nil
	case "alice-token":
		return &principal.Principal{Subject: "alice", Roles: []string{"user"}}, nil
	default:
		return nil, errors.New("unrecognized token")
	}
}

func main() {
	// --- authn: "who is this?" -------------------------------------------
	authentication := authngin.NewBuilder().
		WithBearerValidator(exampleBearerValidator{})

	// --- authz: "what may they do?" --------------------------------------
	// A named policy ("AdminOnly") for a coarse-grained role check, plus a
	// PARC repository granting alice permission to read order "order-1"
	// specifically, for a fine-grained per-resource check.
	permissions := authz.NewMemoryPermissionRepository()
	_ = permissions.GrantPermission(context.Background(), "alice", authz.PermissionRule{
		ActionPattern:     "read",
		ResourceType:      "order",
		ResourceIDPattern: "order-1",
		Effect:            authz.EffectPermit,
	})

	authorization := authzgin.NewBuilder().
		AddPolicy("AdminOnly", authz.NewPolicyBuilder().RequireRole("admin").Build()).
		WithMemoryPARC(5*time.Minute, permissions)

	// --- wire authn + authz together in one call --------------------------
	router := gin.Default()
	engine, err := pipeline.Setup(router, pipeline.Config{
		Authentication: authentication,
		Authorization:  authorization,
	})
	if err != nil {
		panic(err)
	}

	// [Authorize(Policy = "AdminOnly")] -- only the "admin" role passes.
	router.GET("/admin",
		authzgin.Require(authzgin.WithEngine(engine), authzgin.WithPolicyName("AdminOnly")),
		func(c *gin.Context) {
			user := ginprincipal.MustUser(c)
			c.String(http.StatusOK, "hello admin %s", user.Subject)
		})

	// PARC-guarded route with route-param resource extraction: "GET
	// /orders/order-1" is evaluated as read access to {Type: "order", ID: "order-1"}.
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

	router.Run(":8080")
}
```

Requesting `/admin` with `Authorization: Bearer admin-token` returns 200; with `alice-token` (no `admin` role) it returns 403 -- `authz` never emits 401, that's `authn`'s job, which already ran in the pipeline before this guard. Requesting `/orders/order-1` as alice returns 200 (granted above); `/orders/order-2` returns 403 (never granted); no credentials at all returns 401 before either route guard runs.

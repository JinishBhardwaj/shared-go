# authz

High-Performance Authorization Engine with PARC (Principal, Action, Resource, Context) and ASP.NET Core Conventions for Gin.

`authz` consumes authenticated callers (`*authn.Principal`) from `github.com/JinishBhardwaj/shared-go/authn` and provides fine-grained, policy-based authorization capable of handling 10,000–50,000+ RPS.

## Features

- **ASP.NET Core Authorization Architecture**:
  - `authz.UseAuthorization(service)` (mirrors `app.UseAuthorization()`): Pipeline authorization middleware.
  - `authz.AllowAnonymous()` (mirrors `[AllowAnonymous]`): Explicit opt-out for public endpoints.
  - `authz.Authorize("PolicyName")` (mirrors `[Authorize(Policy = "...")]`): Declarative endpoint policy enforcement.
  - `authz.AuthorizeResource(c, resource, "PolicyName")` (mirrors `await _authService.AuthorizeAsync(...)`): Imperative evaluation in handlers.
  - `authz.NewOptions()` with `DefaultPolicy`, `FallbackPolicy` (Zero-Trust defaults), and `AddPolicy()`.
- **PARC Authorization Model**:
  - **Principal**: Authenticated caller ID, client ID, roles, scopes, auth method, and claims.
  - **Action**: Verb or operation (e.g. `read`, `write`, `delete`, `approve`).
  - **Resource**: Target entity type, ID, tenant, and attributes (e.g. `type: report, tenant: acme`).
  - **Context**: Request runtime environment (IP address, time of day, department, client version).
- **Sub-Millisecond L1/L2 Caching (10k–50k+ RPS)**:
  - **L1 In-Memory**: Backed by `dgraph-io/ristretto` for ultra-fast in-memory evaluation (30–50 nanoseconds lookup).
  - **L2 Distributed Cache**: Backed by Redis with 60-second grant TTL.
  - **Instant Revocation (< 5ms)**: Distributed invalidation via Redis Pub/Sub (`InvalidationBus`), immediately purging local L1 instances upon revocation.

## Installation

```bash
go get github.com/JinishBhardwaj/shared-go/authz
```

## Fluent Chained Configuration

```go
// Mirrors builder.Services.AddAuthorization().AddPolicy().WithMemoryPARC()
authzMiddleware, err := authz.NewBuilder().
    AddPolicy("UserOnly", authz.NewPolicyBuilder().RequireUser().Build()).
    AddPolicy("AdminOnly", authz.NewPolicyBuilder().RequireRole("admin").Build()).
    WithMemoryPARC(60 * time.Second).
    BuildMiddleware()

r.Use(authzMiddleware)
```

## Quick Start (Manual Configuration)
package main

import (
	"context"
	"net/http"
	"time"

	"github.com/JinishBhardwaj/shared-go/authn"
	"github.com/JinishBhardwaj/shared-go/authz"
	"github.com/JinishBhardwaj/shared-go/authz/cache"
	"github.com/gin-gonic/gin"
)

type AppPermissionRepo struct{}

func (r *AppPermissionRepo) GetPermissions(ctx context.Context, principalID string) (*authz.PrincipalPermissions, error) {
	return &authz.PrincipalPermissions{
		PrincipalID: principalID,
		Rules: []authz.PermissionRule{
			{
				Actions:       []string{"read", "write"},
				ResourceTypes: []string{"document"},
				Effect:        "ALLOW",
			},
		},
	}, nil
}

func main() {
	r := gin.Default()

	// 1. Initialize L1 Cache and PARC Handler
	memCache, _ := cache.NewMemoryCacheProvider()
	parcHandler, _ := authz.NewPARCHandler(authz.PARCHandlerConfig{
		Repository: &AppPermissionRepo{},
		Cache:      memCache,
		GrantTTL:   60 * time.Second,
	})

	// 2. Configure Authorization Options (mirrors services.AddAuthorization(options => ...))
	opts := authz.NewOptions()
	opts.AddPolicy("EditDocumentPolicy", authz.NewPolicyBuilder().
		RequireRole("editor").
		RequirePARC("write", "document").
		Build(),
	)

	// Zero-Trust: fallback policy enforces authentication on unannotated routes
	opts.FallbackPolicy = authz.NewPolicyBuilder().
		RequireAuthenticatedUser().
		Build()

	// 3. Create Authorization Service (mirrors IAuthorizationService)
	authService := authz.NewService(opts, parcHandler)

	// 4. Attach pipeline middleware (mirrors app.UseAuthentication() & app.UseAuthorization())
	// r.Use(authn.UseAuthentication(...))
	r.Use(authz.UseAuthorization(authService))

	// 5. Routes with ASP.NET Core semantics
	// [AllowAnonymous]
	r.GET("/health", authz.AllowAnonymous(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	// [Authorize(Policy = "EditDocumentPolicy")]
	r.POST("/documents/:id",
		authz.Authorize("EditDocumentPolicy", func(c *gin.Context) authz.Resource {
			return authz.Resource{
				Type: "document",
				ID:   c.Param("id"),
			}
		}),
		func(c *gin.Context) {
			user := authn.User(c)
			c.JSON(http.StatusOK, gin.H{
				"message": "Document edited successfully",
				"user":    user.Subject,
			})
		},
	)

	r.Run(":8080")
}
```

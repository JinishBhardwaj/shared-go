# authz

High-Performance Authorization Engine with PARC (Principal, Action, Resource, Context) and ASP.NET Core Policy Conventions for Gin.

`authz` consumes authenticated callers (`*authn.Principal`) from `github.com/JinishBhardwaj/shared-go/authn` and provides fine-grained, policy-based authorization capable of handling 10,000–50,000+ RPS.

## Features

- **PARC Authorization Model**:
  - **Principal**: Authenticated caller ID, client ID, roles, scopes, auth method, and claims.
  - **Action**: Verb or operation (e.g. `read`, `write`, `delete`, `approve`).
  - **Resource**: Target entity type, ID, tenant, and attributes (e.g. `type: report, tenant: acme`).
  - **Context**: Request runtime environment (IP address, time of day, department, client version).
- **ASP.NET Core Policy-Based Architecture**:
  - `PolicyEngine` (mirrors `IAuthorizationService`): Coordinates evaluation across extensible `RequirementHandler`s.
  - Built-in requirement handlers: `ScopeRequirement`, `RoleRequirement`, `UserPresentRequirement`, `M2MRequirement`, `CustomRequirement`, and `PARCRequirement`.
- **Sub-Millisecond L1/L2 Caching (10k–50k+ RPS)**:
  - **L1 In-Memory**: Backed by `dgraph-io/ristretto` for ultra-fast in-memory evaluation (30–50 nanoseconds lookup).
  - **L2 Distributed Cache**: Backed by Redis with 60-second grant TTL.
  - **Instant Revocation (< 5ms)**: Distributed invalidation via Redis Pub/Sub (`InvalidationBus`), immediately purging local L1 instances upon revocation.
- **Gin Middleware Guard**: Clean `authz.Authorize("PolicyName", engine)` integration.

## Installation

```bash
go get github.com/JinishBhardwaj/shared-go/authz
```

## Quick Start

```go
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

// Example repository fetching user permissions from database
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

	// 2. Configure Policy Engine
	engine := authz.NewPolicyEngine(parcHandler)
	engine.RegisterPolicy(authz.NewPolicyBuilder("EditDocumentPolicy").
		RequireRole("editor").
		RequirePARC("write", "document").
		Build())

	// 3. Attach routes with authn + authz guards
	r.POST("/documents/:id",
		// authn middleware sets authn.User(c)
		authz.Authorize("EditDocumentPolicy", engine,
			authz.WithResourceExtractor(func(c *gin.Context) authz.Resource {
				return authz.Resource{
					Type: "document",
					ID:   c.Param("id"),
				}
			}),
		),
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

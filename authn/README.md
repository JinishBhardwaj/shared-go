# authn

Pluggable Authentication Middleware for Gin with ASP.NET Core conventions.

`authn` provides robust authentication handling for Gin applications, supporting OIDC (Cognito, Keycloak, Okta, Google SAML), JWT bearer tokens, and API keys.

Designed around ASP.NET Core patterns:
- **`Principal`** (mirrors `ClaimsPrincipal`): Strongly typed caller identity containing Subject, ClientID, Roles, Scopes, AuthMethod, and Claims.
- **`ClaimsTransformer`** (mirrors `IClaimsTransformation`): Pluggable post-auth enrichment hook to fetch application-specific roles/metadata from databases or caches.
- **`authn.User(c)`** (mirrors `HttpContext.User`): Idiomatic accessor to retrieve the authenticated `*Principal` anywhere in your HTTP handler pipeline.

## Features

- **Decoupled IdP Validation**: Built on `github.com/coreos/go-oidc/v3` with dynamic discovery, automatic JWKS key rotation, and claims normalization (`StandardOIDCNormalizer`, `CognitoClaimsNormalizer`).
- **OAuth2 / OIDC Flows**: Native support for Authorization Code + PKCE, Client Credentials (M2M), and Device Flow (RFC 8628).
- **API Key Authentication**: Extensible header parsing (`X-API-Key` or `Authorization: ApiKey <key>`) with hashed lookup and TTL revocation.
- **Claims Transformation**: Pluggable `ClaimsTransformer` to enrich principals with roles, tenant IDs, and scopes without bloating JWT tokens.
- **Gin Route Guards**: `RequireScope`, `RequireAnyScope`, `RequireRole`, `RequireAnyRole`, `RequireAuthMethod`.

## Installation

```bash
go get github.com/JinishBhardwaj/shared-go/authn
```

## Quick Start

```go
package main

import (
	"context"
	"net/http"

	"github.com/JinishBhardwaj/shared-go/authn"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	// 1. Configure OIDC Validator (Cognito, Keycloak, Okta, etc.)
	oidcValidator, err := authn.NewOIDCValidator(context.Background(), authn.OIDCOptions{
		IssuerURL:  "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
		ClientID:   "your-client-id",
		Normalizer: &authn.CognitoClaimsNormalizer{},
	})
	if err != nil {
		panic(err)
	}

	// 2. Optional: Configure ClaimsTransformer (ASP.NET Core IClaimsTransformation)
	claimsTransformer := authn.ClaimsTransformerFunc(func(ctx context.Context, p *authn.Principal) (*authn.Principal, error) {
		// Enrich principal from your database or user repository
		p.Roles = append(p.Roles, "reports:viewer")
		return p, nil
	})

	// 3. Attach authn middleware
	authMiddleware := authn.New(
		[]authn.Authenticator{oidcValidator},
		authn.WithClaimsTransformer(claimsTransformer),
	)

	api := r.Group("/api", authMiddleware)
	{
		api.GET("/profile", func(c *gin.Context) {
			// Access caller via authn.User(c) (mirrors HttpContext.User)
			user := authn.User(c)
			c.JSON(http.StatusOK, gin.H{
				"sub":   user.Subject,
				"roles": user.Roles,
				"email": user.Claims["email"],
			})
		})

		// Route guard
		api.GET("/admin", authn.RequireRole("admin"), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "admin access granted"})
		})
	}

	r.Run(":8080")
}
```

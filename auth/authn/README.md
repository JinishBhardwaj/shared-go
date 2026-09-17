# authn

Pluggable Authentication Middleware for Gin with ASP.NET Core conventions.

`authn` provides robust authentication handling for Gin applications, supporting OIDC (Cognito, Keycloak, Okta, Google SAML), JWT bearer tokens, and API keys.

Designed around ASP.NET Core patterns:
- **`Principal`** (mirrors `ClaimsPrincipal`): Strongly typed caller identity containing Subject, ClientID, Roles, Scopes, AuthMethod, and Claims (`User.IsInRole()`).
- **`ClaimsTransformation`** (mirrors `IClaimsTransformation`): Pluggable post-auth enrichment hook to fetch application-specific roles/metadata from databases or caches.
- **`authn.UseAuthentication(handler)`** (mirrors `app.UseAuthentication()`): Standard pipeline authentication middleware.
- **`authn.User(c)`** (mirrors `HttpContext.User`): Idiomatic accessor to retrieve the authenticated `*Principal` anywhere in your HTTP handler pipeline.

## Features

- **Decoupled IdP Validation**: Built on `github.com/coreos/go-oidc/v3` with dynamic discovery, automatic JWKS key rotation, and claims normalization (`StandardOIDCNormalizer`, `CognitoClaimsNormalizer`).
- **OAuth2 / OIDC Flows**: Native support for Authorization Code + PKCE, Client Credentials (M2M), and Device Flow (RFC 8628).
- **API Key Authentication**: Extensible header parsing (`X-API-Key` or `Authorization: ApiKey <key>`) with hashed lookup and TTL revocation.
- **Claims Transformation**: Pluggable `ClaimsTransformation` to enrich principals with roles, tenant IDs, and scopes without bloating JWT tokens.
- **Pipeline Middleware**: Clean `authn.UseAuthentication(schemeHandler, opts...)`.

## Installation

```bash
go get github.com/JinishBhardwaj/shared-go/authn
```

## Fluent Chained Configuration

```go
// Mirrors builder.Services.AddAuthentication().AddCognito().AddClaimsTransformation()
authnMiddleware, err := authn.NewBuilder().
    WithCognito(ctx, authn.CognitoOptions{
        IssuerURL:  "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
        Region:     "us-east-1",
        UserPoolID: "us-east-1_example",
    }).
    WithClaimsTransformation(claimsTransformer).
    BuildMiddleware()

r.Use(authnMiddleware)
```

## Quick Start (Manual Configuration)
package main

import (
	"context"
	"net/http"

	"github.com/JinishBhardwaj/shared-go/authn"
	"github.com/JinishBhardwaj/shared-go/authn/mapping"
	"github.com/JinishBhardwaj/shared-go/authn/oidc"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	// 1. Configure OIDC Bearer Validator (Cognito, Keycloak, Okta, etc.)
	oidcValidator, err := oidc.NewOIDCValidator(context.Background(), oidc.OIDCValidatorConfig{
		IssuerURL:  "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
		ExpectedClientID: "your-client-id",
		Normalizer: mapping.NewCognitoClaimsNormalizer(),
	})
	if err != nil {
		panic(err)
	}

	// 2. Scheme handler (Composite Authenticator)
	authHandler := authn.NewSchemeHandler(authn.SchemeHandlerConfig{
		ExtractorConfig: authn.DefaultExtractorConfig(),
		BearerValidator: oidcValidator,
	})

	// 3. Claims Transformation (mirrors ASP.NET Core IClaimsTransformation)
	claimsTransformation := authn.ClaimsTransformerFunc(func(ctx context.Context, p *authn.Principal) (*authn.Principal, error) {
		// Enrich principal from your database or user repository
		p.Roles = append(p.Roles, "reports:viewer")
		return p, nil
	})

	// 4. Attach pipeline authentication middleware (mirrors app.UseAuthentication())
	r.Use(authn.UseAuthentication(
		authHandler,
		authn.WithClaimsTransformation(claimsTransformation),
	))

	r.GET("/api/profile", func(c *gin.Context) {
		// Access caller via authn.User(c) (mirrors HttpContext.User)
		user := authn.User(c)
		c.JSON(http.StatusOK, gin.H{
			"sub":      user.Subject,
			"roles":    user.Roles,
			"is_admin": user.IsInRole("admin"),
			"metadata": user.Metadata,
		})
	})

	r.Run(":8080")
}
```

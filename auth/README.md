# auth

Authentication and authorization for Gin, built around a simple split:

- **authn** answers "**who is this?**" -- validates a bearer token or API key
  and produces a `principal.Principal` (mirrors ASP.NET Core's
  `ClaimsPrincipal`).
- **authz** answers "**what may they do?**" -- evaluates named policies
  and/or fine-grained PARC (Principal-Action-Resource-Context) rules against
  the `Principal` authn attached to the request.

authn and authz are independent packages (authz never imports authn); the
`pipeline` package sits above both and wires them together in the order that
matters: authentication first, so a `Principal` is on the Gin context before
any authorization check runs.

## Package layout

| Package | What it's for |
|---|---|
| `authn` | Core authentication: `BearerTokenValidator`/`KeyValidator` interfaces, OIDC/JWT/API-key validators, issuer registry, claims normalization. |
| `authn/gin` | Gin wiring for authn: `AuthenticationBuilder`, `UseAuthentication` middleware, credential extraction from headers. |
| `authz` | Core authorization: `Policy`/`PolicyEngine`, PARC evaluation, requirement handlers (role/scope/method), `PermissionRepository`. |
| `authz/gin` | Gin wiring for authz: `AuthorizationBuilder`, the single `Require(opts...)` route guard, route-param resource extraction. |
| `principal` | The `Principal` type itself and `ClaimsTransformer` hook, independent of any web framework. |
| `principal/gin` | Gin context accessors for the authenticated `Principal` (`Set`, `User`, `MustUser`). |
| `pipeline` | `pipeline.Setup(router, cfg)`, the one-call authn+authz bootstrap. |
| `authtest` | Test helpers/fakes for exercising authn-guarded code without a real IdP. |

## End-to-end example

The block below is copied verbatim from `TestReadmeExample_EndToEnd` in
[`example_test.go`](./example_test.go) at the module root -- it is a real,
compiling test that fires actual HTTP requests through `httptest` and
asserts the expected 200/403/401 outcomes, so it cannot silently drift out
of sync with the packages it demonstrates. Run it yourself with:

```sh
go test -run TestReadmeExample_EndToEnd -v ./...
```

```go
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

// --- authn: "who is this?" ------------------------------------------
authentication := authngin.NewBuilder().
	WithBearerValidator(exampleBearerValidator{})

// --- authz: "what may they do?" --------------------------------------
// A named policy ("AdminOnly") for a coarse-grained role check, plus a
// PARC (Principal-Action-Resource-Context) repository granting alice
// permission to read order "order-1" specifically, for a fine-grained
// per-resource check.
permissions := authz.NewMemoryPermissionRepository()
if err := permissions.GrantPermission(context.Background(), &principal.Principal{Subject: "alice"}, authz.PermissionRule{
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
```

With this wiring: `admin-token` gets 200 from `/admin` and 403 from
`/orders/order-1` (no PARC grant); `alice-token` gets 403 from `/admin` (no
admin role), 200 from `/orders/order-1` (has the grant), and 403 from
`/orders/order-2` (no grant for that specific order); no credentials at all
gets 401 from either route, before `Require`'s own guard ever runs. See
`example_test.go` for the requests that prove all five of those outcomes.

## Fail-closed defaults worth knowing about

- An empty scope/role candidate list in `WithAnyScope`/`WithAnyRole` denies
  rather than allows -- there is no vacuous-truth "no requirements means
  anyone passes" case.
- `authz`'s `Require(...)` guards never emit `401` themselves -- a missing
  `Principal` in context is answered with `403 Forbidden`. Returning a
  credential challenge (`401` + `WWW-Authenticate`) is authn's job; run
  authn's middleware ahead of any `authz.Require(...)` guard (`pipeline.Setup`
  already does this for you).
- `Require(...)` panics at its own construction time (not at request time)
  if no requirement option is supplied, or if `WithPolicyName`/`WithPARC` is
  selected without an accompanying `WithEngine(...)` -- misconfiguration
  fails at wire time, not on the first real request.
- `pipeline.Setup` returns the *same* `*authz.PolicyEngine` instance it wired
  into the router's authorization middleware -- pass that returned engine
  into every route's `authzgin.Require(authzgin.WithEngine(engine), ...)`
  rather than constructing or resolving a second one.

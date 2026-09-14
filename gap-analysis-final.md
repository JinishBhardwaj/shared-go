# Gap Analysis (Final): `authn` & `authz`

**Scope:** `github.com/JinishBhardwaj/shared-go/authn` and `.../authz` (incl. `authz/cache`, `authn/oauthprovider`).
**Method:** full read of all non-test sources; `go vet ./...` clean on both modules; claims in a prior third-party analysis verified line-by-line against source.
**Date:** 2026-09-14

> `go vet` passes on both modules. Nothing in Tier 0 below is compiler- or vet-detectable. Assume static analysis has told you nothing about the security posture of these packages.

---

## Part 1 — Review of the prior analysis (`gap-analysis.md`)

Directionally reasonable on architecture. **Not written against this code**, so its ✅ ratings should not be relied on, and it missed every fail-open defect.

### 1.1 Fabricated APIs

| Claimed | Actual |
|---|---|
| `NewBuilder().AddOIDC(...).AddAPIKeys(...)` | `AddCognito` / `AddBearerValidator` / `AddApiKeyValidator` |
| `NewAuthorizationBuilder()` | `authz.NewBuilder()` |
| `PolicyBuilder.Require(...)` | no such method |
| `AuthorizeResource(c, resource, action)` | `(c, resource, policyName)` — `authz/middleware.go:215` |
| `authz.Resource{Type, ID, Action}` | `Resource` has no `Action` field — `authz/parc.go:34` |
| `authz.NewResource().Type().ID().Action()` | proposed builder is shaped around a field that does not exist |

### 1.2 Ratings contradicted by the code

| Prior rating | Reality |
|---|---|
| OCP "✅ Strong" (both pkgs) | `NewAuthorizationService` type-switches for `*PARCHandler` and silently discards every other handler — `authz/engine.go:313` |
| ISP "authn ✅ Good" | `Authenticate(*gin.Context)` welds the decision core to Gin — `authn/authenticator.go:17` |
| "HTTP response mapping ✅ Clean" | `err.Error()` / `FailureReason` interpolated into `WWW-Authenticate` — `authn/middleware.go:140`, `authz/middleware.go:267` |
| "strict algorithm enforcement" | `AllowedSigningAlgs` is optional — `authn/jwt_validator.go:70` |
| "RFC 7519 ✅ Compliant … `aud` validation" | `ExpectedAudience` optional, and `WithCognito` hardcodes `SkipClientIDCheck: true` — `authn/builder.go:49` |
| "Flow detection ✅ Clean" | defaults to `AuthCodePKCE` on any `sub`; M2M tokens satisfy `RequireUser()` — `authn/jwt_validator.go:249` |
| "AllowAnonymous ✅ Good" | no-op. Sets `ContextKeyAllowAnonymous`; nothing ever reads it — `authz/middleware.go:135` |
| "Redis failure handling ✅ Good" | reads degrade to DB, but the revocation listener exits permanently on a dropped pubsub channel with no resubscribe — `authz/cache/tiered.go:97`, `authz/cache/redis.go:108` |
| "Concurrent safety ✅ thread-safe" | `PolicyEngine.policies` / `.handlers` mutated by `RegisterPolicy` / `RegisterHandler` with no lock |
| "constant-time compare ✅ Strong" | the compare at `authn/apikey_validator.go:130` runs *after* a keyed map lookup on the same hash. Harmless, but buys nothing — not a security strength |

### 1.3 Pattern misclassifications

- `CompositeAuthenticator` is **not** Composite — it does not compose homogeneous `Authenticator`s, it dispatches by credential type. Strategy selector.
- `MockOAuthProvider` is **not** a Facade — test fake.
- **"Observer ❌ Not used" is wrong** — `cache.InvalidationBus` is Observer (`authz/cache/cache.go:36`). The real point, buried: no hook for *decision* events.
- **"Chain of Responsibility ✅ no gap"** credits Gin's pipeline, not the packages. `CredentialExtractor.Extract` is a monolithic if-chain (`authn/extractor.go:68`) — the actual CoR gap.
- Missed the highest-value pattern gap: **Composite for requirements**. Policies are AND-only, so OR/NOT are inexpressible.

### 1.4 Recommendations to reject

- **`nonce` validation (their priority #4)** — category error. `nonce` is a relying-party check performed when the RP redeems the authorization code and inspects the ID token. These packages are resource-server side, validating inbound access tokens; there is no nonce in scope.
- **Shared `Principal` interface via `identity.Actor` (their #6, "High impact")** — `identity/` does exist and is unused by both packages, so the observation is correct. But `Actor` is an audit-attribution type (`Kind` user/system, `ID`, `Sub`) with no scopes, roles, issuer, audiences, or expiry. Not a security-principal contract; unifying them conflates audit authorship with authentication. Separately, `authz` depending on `*authn.Principal` is the **correct** direction — depending on a stable data type in a lower layer is not a DIP violation, and interface-ifying it adds indirection on the hot path. The real defect is the duplicate `authz.Principal` re-mapping, which they did spot in their §4.
- **"Split `PolicyEngine` into `PolicyEvaluator` / `PolicyLoader` / `PermissionQuerier`"** — over-decomposition; the engine does not query permissions (`PARCHandler` does). `Authorizer` + `PolicyRegistry` suffices.
- **"Pre-index for O(1)"** — indexing by resource type yields O(matching rules), not O(1).

### 1.5 Missed entirely

Every Tier 0 item below, plus: handler discard, the named-`CustomRequirement` dead path, `AllowAnonymous` being inert, the `strings.Contains(HandlerNames())` route-detection hack, JSON round-trip per authorized request, absent singleflight, revocation-listener death, double principal mapping per request, `RoleRequirement.RequireAll` ignored, and `go 1.20` in both submodules while the root `go.mod` is `go 1.23`.

### 1.6 Genuinely additive — adopted below

1. **Decision audit hooks** — `OnDecision(principal, resource, action, result)`. Sharper framing than generic observability.
2. **Benchmark tests** — confirmed zero exist. Prerequisite for any perf claim.
3. **Circuit breaker** (`sony/gobreaker`) for JWKS / OIDC / Redis / permission DB.
4. **DB-backed `PermissionRepository`** — memory-only persistence in a shared library is a real gap.
5. **Provider helpers** for Auth0 / Okta / Entra — secondary, and must not repeat the `SkipClientIDCheck` mistake.
6. **RFC 9068 `typ: at+jwt`** — independently corroborated.
7. **`ProtectGroup(routerGroup, policy)`** — converges with the `authz.Group` proposal.
8. **End-to-end pipeline example in the README.**

---

## Part 2 — Consolidated recommendations

### Tier 0 — Fail-open defects. Ship first.

Each of these grants access that should not be granted.

| # | Location | Defect | Fix |
|---|---|---|---|
| 1 | `authz/parc.go:90` | Tenant check skipped when `req.Resource.TenantID == ""` — any extractor that omits TenantID bypasses tenant isolation | Fail closed: rule pins a tenant + empty request tenant → no match |
| 2 | `authz/parc.go:139` | `matchGlob` returns `true` for an empty pattern — a blank `ActionPattern`/`ResourceIDPattern` in a DB row silently becomes `*` | Empty pattern → no match; require literal `"*"` |
| 3 | `authn/jwt_validator.go:249` | `determineOAuthFlow` defaults to `AuthMethodAuthCodePKCE` whenever `sub != ""` — client-credentials tokens from IdPs that omit `gty`/`amr` are classified as interactive users and satisfy `RequireUser()` / `UserPresentRequirement` | Default `AuthMethodUnknown`; "user present" becomes per-issuer opt-in, never inferred |
| 4 | `authn/builder.go:49` | `WithCognito` hardcodes `SkipClientIDCheck: true` — audience validation off for every Cognito consumer (confused-deputy exposure, RFC 9068 §4 / RFC 7519 §4.1.3) | Accept `AllowedAudiences []string`; make skipping explicit and loud |
| 5 | `authn/normalizer.go:111` | `token_use` read only to resolve ClientID, never enforced — **Cognito ID tokens are accepted as access tokens** | Require `token_use == "access"` for API-facing validation; reject `id` |
| 6 | `authn/principal.go:97,130` | `HasAnyScope()` / `HasAnyRole()` return `true` for an empty list, so `ScopeRequirement{RequireAll:false, Scopes:nil}` allows everything (`authz/engine.go:42`) | Empty requirement set → deny |
| 7 | `authn/middleware.go:137,140`; `authz/middleware.go:267`; `authz/guard.go:66,126` | Internal error text interpolated into the `WWW-Authenticate` header and body. Leaks DB/IdP messages; quotes or CRLF in an error break the quoted-string → header injection | Map to a fixed RFC 6750 error-code set; escape per RFC 7235 `quoted-string`; log detail server-side only |
| 8 | `authz/engine.go:53` | `RoleRequirement.RequireAll` is declared but ignored — handler always ANDs. Silent misconfiguration | Honor the flag or delete it |
| 9 | `authn/oauthprovider/provider.go:85` | Hardcoded client secret in a non-test build path of an importable module | Move to `authntest/` or `internal/`, or gate behind a test build tag |

**Add fail-closed table tests for 1, 2, 3 and 6.** These are precisely the cases static analysis cannot see.

### Tier 1 — Structural correctness

- **Generic handler registry.** `NewAuthorizationService` discards non-PARC handlers (`authz/engine.go:313`) — the variadic is a lie. Give `RequirementHandler` a `RequirementType() string` and register by it. Same change fixes named `CustomRequirement`s, which today resolve to no handler and deny silently (`authz/policy.go:56`).
- **`AllowAnonymous` is inert**; `ContextKeyEndpointPolicy` and `ContextKeyEndpointResource` are dead constants. Make anonymity real or remove it.
- **Drop the route-detection hack.** `strings.Contains(c.HandlerNames(), "Authorize")` (`authz/middleware.go:83`) breaks under renames and wrappers and false-positives on any consumer handler whose name contains `Authorize`. Replace with explicit route metadata — `authz.Group(policy)` / `ProtectGroup`.
- **Unify action semantics.** `Authorize` / `RequirePolicy` set `Action.Name = c.Request.Method`; `RequirePARC` sets the logical action; and `PermissionRule.Matches` accepts *either* `Action.Name` or `HTTPMethod` (`authz/parc.go:75`), so a rule written for one grants the other. Logical actions only, from an explicit route→action map.
- **Freeze `PolicyEngine` at `Build()`** — no post-serve registration, no unguarded map writes.
- **Fail at wire time, not request time.** `authn.Builder.Build()` succeeds with zero validators configured (surfaces per-request as `ErrAuthenticatorNotConfigured`); `authz.Authorize` panics at request time when no engine is in context (`authz/middleware.go:167`).

### Tier 2 — Separation of concerns

- **Move all of `authn/guards.go` into `authz`** as built-in `Requirement` types (`RequireScope`, `RequireAnyScope`, `RequireRole`, `RequireAnyRole`, `RequireMethod`, `RequireUser`, `RequireM2M`). Highest-ROI structural change; both analyses agree.
- **Move API-key issuance** (`CreateKey` / `RevokeKey`) out of `authn` into an `apikeys` store package. Credential lifecycle is not authentication.
- **Map the principal once.** `authn.Principal` → `authz.Principal` is currently rebuilt per requirement per request (`authz/engine.go:85`, `:191`) — two allocations plus a map copy on every hot-path call. Map once in the middleware into `EvaluationContext`; keep `authz.Principal` internal. **Do not** introduce a shared `Principal` interface, and leave `identity.Actor` alone (see §1.4).
- **authz emits 403 only.** 401 + challenge logic is duplicated in four places (`authz/middleware.go:98,172,257`; `authz/guard.go:34,92`). Challenges are authn's job.
- **De-Gin the cores.** `Authenticate(ctx, *http.Request)` and a transport-free resource extractor, with thin `authngin` / `authzgin` adapters. Unlocks gRPC/chi and router-free tests.
- **Extract `Authorizer` + `PolicyRegistry`** interfaces from `PolicyEngine`. Two, not four.
- **Delete dead code.** `mapClaimsToPrincipal` (`authn/jwt_validator.go:106`) is unused; move `extractClientID` / `extractScopes` / `extractRoles` / `determineOAuthFlow` into `normalizer.go`, where their only callers live.
- Split `PermissionRepository` into reader/writer — the hot path needs only `GetPermissions`.

### Tier 3 — Performance & fault tolerance

- **Typed L1 cache — biggest single win.** Every authorized request unmarshals `PrincipalPermissions` (`authz/engine.go:161`) after `MemoryCacheProvider.Get` has already copied the bytes (`authz/cache/memory.go:94`). Ristretto stores `any`: cache the decoded struct in L1 and keep bytes for L2 only. The byte-oriented `CacheProvider` interface is what forces the waste — add a typed provider alongside it.
- **Singleflight** on `perm:<sub>` (`x/sync/singleflight`) — a cache miss on a hot principal currently fans every concurrent request out to the DB.
- **Supervise the revocation listener.** Backoff reconnect + a liveness gauge. Today a single dropped Redis pubsub channel stops revocation permanently and silently — the worst failure mode in the library.
- **Deadlines + breakers.** Per-lookup context deadline (~50ms) on repo/Redis calls; `sony/gobreaker` on JWKS, OIDC discovery, Redis and the permission DB; soft-TTL/hard-TTL stale-while-revalidate so a brief DB outage is not a library-wide 403 storm.
- **Precompile rule globs** and index rules by resource type at bundle load — `path.Match` currently runs per rule per request.
- **Verified-token cache** keyed on a hash of the token, bounded by the token's own `exp` — saves an RSA verify (~50–100µs) per request.
- **JWKS hardening.** Rate-limit refetch on unknown `kid` plus a negative `kid` cache (random-`kid` tokens currently amplify into JWKS traffic); retry OIDC discovery with exponential backoff instead of failing boot (`authn/oidc_validator.go:79`).
- **Benchmarks** for `Authenticate`, `PolicyEngine.Authorize` and PARC evaluation — establish baselines before optimizing, and to prove the claims above.
- Note: Ristretto `Set` is asynchronous, so a `Get` immediately following a `Set` can miss. Acceptable under a 60s grant TTL, but document it — combined with the missing singleflight it widens the stampede window.

### Tier 4 — Observability, coverage, ergonomics

- **`OnDecision` audit hook** + an OTel/metrics decorator: deny-reason counters, cache-hit ratio, revocation lag, p99. Both packages currently ship zero instrumentation — the largest operational gap after Tier 0.
- **DB-backed `PermissionRepository`.**
- **Composite requirements** — `AnyOf` / `AllOf` / `Not`, recursing into the engine. OR is inexpressible today; highest-value pattern addition.
- **Chain of Responsibility** for credential extraction (`Authorization` header → `X-API-Key` → cookie → mTLS → query); **Registry keyed by `iss`** for multi-IdP/multi-tenant; **Decorator** on `BearerTokenValidator` for cache/trace/breaker concerns that have nowhere to live today.
- **Consolidate the five route-guard entry points** (`Authorize`, `WithPolicy`, `RequirePolicy`, `RequirePARC`, `authn.RequireScope`) into one `authz.Require(opts...)`; replace `args ...any` type switches (`authz/middleware.go:144`) and pseudo-optional variadics with typed options.
- **`security.Setup(router, cfg)`** one-call bootstrap, route-param resource extraction by default, and a complete authn → authz → handler README example.
- **Bump `authn` and `authz` from `go 1.20` (EOL) to match the root module's `go 1.23`;** re-evaluate `ristretto v0.2.0` (known memory-accounting issues) against `ristretto/v2` or `otter`.
- **Optional — document as a deliberate decision if declined:** RFC 9068 `typ: at+jwt`, RFC 7662 introspection for opaque tokens, a `jti` replay denylist, DPoP (RFC 9449) / mTLS (RFC 8705) sender-constrained tokens. Skip `nonce` and OIDC back-channel logout: not resource-server concerns.

---

## Sequencing

1. Tier 0 items 1–6 — exploitable today.
2. Tier 0 items 7–9, plus the `RequireAll` and named-`CustomRequirement` dead paths.
3. Tier 2: move `guards.go`; map the principal once; Tier 3 typed L1 cache.
4. Tier 3: singleflight, deadlines, breakers, revocation-listener supervision; Tier 4 metrics + `OnDecision`.
5. Tier 1: consolidate route guards, remove the `HandlerNames()` hack, make `AllowAnonymous` real.
6. Tier 2 interface cleanup (de-Gin the cores, `Authorizer`, generic handler registry) and Tier 4 Composite requirements.

---

## Part 3 — Package & module structure

> Do this **before** Tier 0. Nothing is published (see §3.1), so restructuring costs zero migration today and gets more expensive every week. It also converts roughly half of Tier 1–3 from judgment calls into mechanical `git mv` + import rewrites.
>
> All `file:line` anchors in Parts 1–2 refer to the **pre-restructure** layout.

### 3.1 Blocking module defects (verified)

**1. `authz` is not installable outside this repo.** `authz/go.mod` declares `require github.com/JinishBhardwaj/shared-go/authn v0.0.0` plus `replace => ../authn`. A `replace` directive in a dependency's `go.mod` is ignored by consumers, and `git tag` returns nothing — there is no `v0.0.0` to resolve. Any external `go get` of `authz` fails.

**2. Two competing cache abstractions in one repo.**

| | root `cache/` | `authz/cache/` |
|---|---|---|
| Interface | `Cache[T any]` — generic, typed | `CacheProvider` — `[]byte` |
| Miss semantics | `(zero T, false, nil)` — documented as *never* an error | `ErrCacheMiss` — a miss *is* an error |
| Backends | `cache/memory`, `cache/rediscache` | `memory.go`, `redis.go`, `tiered.go` |
| Teardown | `Dispose()` | `Close() error` |

Tier 3's headline item — "typed L1 cache, stop the per-request JSON round-trip" — is **already implemented** in the root module. `authz` simply isn't using it.

**3. Go version and module-granularity drift.**

| Module | Go |
|---|---|
| root (`cache/`, `health/`, `identity/`) | 1.23 |
| `search`, `search/pgx`, `versioning` | 1.24 |
| **`authn`, `authz`** | **1.20 (EOL)** |

Module boundaries follow no rule: `cache`/`health`/`identity` sit inside the root module; `authn`/`authz`/`search`/`search/pgx`/`versioning` are separate modules.

### 3.2 Should `authz` depend on `authn`? No.

The two packages answer different questions — *who is this* vs *what may they do* — and ASP.NET Core, which these packages are modeled on, keeps them apart at the assembly level:

| Layer | Assembly | References |
|---|---|---|
| Identity contract | `System.Security.Claims` — `ClaimsPrincipal`, `ClaimsIdentity`, `Claim` | nothing |
| Authentication | `Microsoft.AspNetCore.Authentication.Abstractions` — `IAuthenticationService`, `IAuthenticationHandler`, `AuthenticationTicket` | claims |
| Authorization | `Microsoft.AspNetCore.Authorization` — `IAuthorizationService`, `AuthorizationPolicy`, `IAuthorizationRequirement`, `AuthorizationHandler<T>` | claims. **Not authentication.** |
| Composition / transport | `Microsoft.AspNetCore.Authorization.Policy` — `AuthorizationMiddleware`, `IPolicyEvaluator` | **both** |

Two details confirm the separation is deliberate:

- `IAuthorizationService.AuthorizeAsync(ClaimsPrincipal user, object? resource, ...)` takes the **claims** type, not an authentication type. Authorization consumes an identity and has no opinion on how it was produced.
- `AuthorizationPolicy.AuthenticationSchemes` is `IReadOnlyList<string>` — **stringly typed on purpose**, so that the one place a policy must name a scheme does not create a reference back to authentication.

And the glue is its own assembly: `AuthorizationMiddleware` must call `context.AuthenticateAsync(scheme)` before authorizing, so that code lives in a *fourth* package rather than adding an authentication reference to `Microsoft.AspNetCore.Authorization`.

**Ruling:** the `authz → authn` edge is removed, not justified. `Principal` moves to a third, stdlib-only package that both import. The code that legitimately needs both moves to a fourth.

One further parallel that changes the layout: **`HttpContext.User` lives in `Microsoft.AspNetCore.Http.Abstractions`, not in authentication.** The transport owns the principal slot. So `authn.User()` / `MustUser()` / `GetPrincipal()` / `DefaultContextKeyPrincipal` (`authn/middleware.go:154-184`) do **not** belong in `authn` — they belong in a transport-adjacent package that `authn` writes and `authz` reads. Without this, an `authz/gin` leaf calling `authn.User(c)` keeps the edge alive and nothing is fixed.

### 3.3 Module merge

Merge `authn` + `authz` into **one** module:

```
shared-go/auth/          # one module, go 1.23, owns gin + go-oidc + golang-jwt + ristretto
```

Rationale: they cannot version independently. `authz` references the principal type in its core handler signature, so every `authn` release forces an `authz` release. Two modules in permanent lockstep buy nothing and cost the `v0.0.0` trap in §3.1.

Keep `search` and `versioning` as separate modules — those have genuinely disjoint dependency sets. Tag everything (`auth/v0.1.0`) once merged; the absence of tags is currently masking defect §3.1(1).

### 3.4 Target layout

```
auth/
  go.mod                        # go 1.23: gin, go-oidc, golang-jwt, ristretto
  README.md                     # end-to-end authn -> authz -> handler example

  principal/                    # = System.Security.Claims. stdlib only, no deps.
    principal.go                #   Principal, AuthMethod, HasScope/HasRole/IsUserPresent
    actor.go                    #   Principal -> identity.Actor (audit attribution)
  principal/gin/                # = HttpContext.User. owns the gin context key.
    context.go                  #   Set / User / MustUser / GetPrincipal

  authn/                        # = Authentication.Abstractions. imports principal. NEVER authz.
    authn.go                    #   Authenticator iface, sentinel errors
    credential/                 #   Chain of Responsibility extraction
      credential.go             #     Credential, Source iface
      header.go apikey.go query.go
    validator/
      jwt.go oidc.go apikey.go
      registry.go               #   iss -> validator (multi-IdP)
    claims/
      claims.go standard.go cognito.go
    apikeys/                    #   issuance + store, out of the validator
      store.go memory.go
    builder.go
    gin/                        #   transport adapter; WRITES the principal
      middleware.go

  authz/                        # = Microsoft.AspNetCore.Authorization. imports principal. NEVER authn.
    authz.go                    #   Authorizer iface, Result, Decision
    policy/
      policy.go requirement.go builder.go
    requirement/                #   handlers, incl. the guards moved out of authn
      scope.go role.go method.go parc.go composite.go
    parc/
      model.go match.go         #   compiled globs, resource-type index
    permission/
      repository.go             #   Reader / Writer split
      memory.go postgres.go
    engine/
      engine.go grants.go       #   grant loader: root cache + singleflight
    audit/
      audit.go                  #   OnDecision hook as an Authorizer decorator
    gin/                        #   transport adapter; READS the principal
      middleware.go group.go extractor.go

  pipeline/                     # = Authorization.Policy. the ONLY package allowed both.
    setup.go                    #   security.Setup(router, cfg): scheme selection, ordering

  authtest/                     # fka oauthprovider. fixtures only, never a production path.
    oauthprovider.go principal.go
```

Import DAG, acyclic: `principal ← parc ← requirement ← engine ← authz/gin ← pipeline`, with `audit` wrapping `engine` through the root `Authorizer` interface.

### 3.5 Why each move earns its place

| Move | Recommendation it discharges |
|---|---|
| `principal/` | Kills the `authz → authn` edge (§3.2) and the shared-interface debate (§1.4) in one step — a shared *data* package needs no interface, no dynamic dispatch, no hot-path cost. Also the natural home for the once-per-request mapping that replaces the double `authz.Principal` build (Tier 2). |
| `principal/gin/` | Moves `HttpContext.User`'s equivalent out of authn, which is what actually keeps the dependency edge deleted. |
| `authn/gin/`, `authz/gin/` | Turns "de-Gin the cores" (Tier 2) into a folder move the **compiler enforces** — neither core can import gin if gin lives only in a leaf. A gRPC adapter later is a sibling directory. |
| `authz/requirement/` | Gives the moved `authn/guards.go` exactly one destination, so no second scope/role implementation can drift from it (Tier 2). |
| `authz/permission/` | Reader/Writer split (Tier 2) plus a real home for the DB-backed repository (Tier 4). |
| `authz/audit/` | `OnDecision` (Tier 4) as a decorator over the `Authorizer` interface (Tier 2 / §1.4 item 1). |
| `pipeline/` | `security.Setup(router, cfg)` (Tier 4) and the one sanctioned place for authn+authz co-dependence. |
| `authtest/` | Tier 0 #9 (hardcoded client secret at `authn/oauthprovider/provider.go:85`) becomes a `git mv`. |

Naming payoff from subpackages: `requirement.Scope` over `authz.ScopeRequirement`, `validator.JWT` over `authn.JWTValidator`, `claims.Cognito` over `authn.CognitoClaimsNormalizer`.

Also drop the ASP.NET **type alias** layer while moving — `SchemeHandler`, `SchemeHandlerConfig`, `NewSchemeHandler`, `AuthenticationHandler`, `ClaimsTransformation`, `AuthorizationService`, `Service`, `AuthorizationHandler`, `Handler`, `Result`, `Options`, `NewOptions`, `AuthorizationRequirement`, `AuthorizationPolicy`, `AuthorizationPolicyBuilder` are ~15 aliases that double the API surface and make godoc unreadable. Keep the ASP.NET-shaped **builders**; drop the aliases.

### 3.6 Delete `authz/cache/`

Rebuild on the root module's generic abstraction:

- `cache.Cache[*parc.PrincipalPermissions]` for L1 removes **both** the per-request `json.Unmarshal` (`authz/engine.go:161`) and the defensive byte copy (`authz/cache/memory.go:94`) — Tier 3's largest single win, available because the root abstraction is already typed.
- Keep only what is genuinely authz-specific: the tiered L1+L2 composition and `InvalidationBus`. Promote those to the root module as `cache/tiered` and `cache/invalidation`, beside the backends they compose.
- Reconcile the two contracts on the root module's semantics: a miss is `(zero, false, nil)`, **never** an error. The current `ErrCacheMiss`-as-error shape is what lets `PARCHandler.Handle` swallow a real cache failure and a plain miss through the same branch (`authz/engine.go:158-164`).
- Rename `Close() error` → `Dispose()` to match, or adapt at the boundary.

Net effect: one cache abstraction in the repo, typed, with the L1 fast path allocating nothing.

### 3.7 Reference migration

Every current `authz → authn` reference and its destination:

| Today | After |
|---|---|
| `authn.Principal` in `RequirementHandler.Handle` (`authz/engine.go:28`) | `principal.Principal` |
| `authn.AuthMethodClientCredentials`, `authn.AuthMethodAPIKey` (`authz/engine.go:72`) | `principal.AuthMethod*` |
| `p.IsUserPresent()` (`authz/engine.go:65`) | method on `principal.Principal` |
| `p.HasAllScopes` / `HasAnyScope` / `HasRole` (`authz/engine.go:40-57`) | methods on `principal.Principal` |
| `authn.User(c)` (`authz/middleware.go:96,170,225`; `authz/guard.go:32,90`) | `ginprincipal.User(c)` |

**Acceptance test — enforce in CI.** This edge will grow back the first time someone needs one constant:

```sh
go list -deps ./authz/... | grep -q '/auth/authn' && { echo "authz must not depend on authn"; exit 1; }
```

Two rules to keep it removed:

- If a policy must require a specific authentication scheme, **use a string**, exactly as `AuthorizationPolicy.AuthenticationSchemes` does. Never reach for an authn type.
- `UserPresentRequirement` and `M2MRequirement` inspect *how* the caller authenticated, which looks like a violation but is not: `AuthMethod` is a claim **about** the identity, so it rides in `principal/` — the same way authorizing on `amr` works. Fixing its fail-open default (Tier 0 #3) stays an authn concern, since that is where the claim is derived.

### 3.8 Recommended first commit

Full §3.4 is ~18 directories; do not land it at once. This subset captures most of the value, is almost entirely `git mv` + import rewrites, and is verifiable with `go build ./... && go test ./...`:

1. Merge `authn` + `authz` into one `auth` module, `go 1.23`, tag it.
2. Extract `principal/` and `principal/gin/`; move `User`/`MustUser`/`GetPrincipal`/context key out of `authn`.
3. Extract `authn/gin/` and `authz/gin/`.
4. `authn/oauthprovider/` → `authtest/`.
5. Delete `authz/cache/`; adopt root `cache` (§3.6).
6. Move `authn/guards.go` into `authz` (fixing Tier 0 #6 and #8 in the same change — a straight port carries both bugs across).
7. Add the §3.7 CI check.

Defer `validator/`, `claims/`, `credential/`, `requirement/` splits until the files grow — drive them from the Tier 4 work (multi-IdP registry, Composite requirements) rather than up front.

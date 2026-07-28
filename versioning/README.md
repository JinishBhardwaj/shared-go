# versioning

Configurable API versioning middleware for Gin. Supports per-endpoint version tracking, pluggable version reading strategies, and RFC 9457 Problem Details error responses.

## Features

- **Per-endpoint version support** — each endpoint declares its versions via `VersionedGroup` during route registration
- **Strategy pattern for version reading** — header, query string, URL segment, or composite (combine multiple)
- **Configurable default version** — assume a default when no version is specified
- **Report supported versions** — optionally include `api-supported-versions` response header
- **RFC 9457 error responses** — unsupported/missing/invalid version returns proper Problem Details JSON

## Quick Start

```go
import "github.com/tucowsinc/tdp-shared-go/versioning"

func (server Server) RegisterRoutes() {
    registry := versioning.NewRouteVersionRegistry()
    server.router.Use(versioning.Middleware(server.router, registry))

    apiGroup := server.router.Group("/api")
    registerV1Routes(api, apiGroup, registry)
    registerV2Routes(apiV2, apiGroup, registry)
}

func registerV1Routes(api v1.Api, apiGroup *gin.RouterGroup, registry *versioning.RouteVersionRegistry) {
    v1Routes := versioning.NewVersionedGroup(apiGroup.Group("v1"), registry, "v1")
    v1Routes.POST("/domains", api.CreateDomainHandler)
    v1Routes.GET("/domains/:id", api.GetDomainHandler)
    v1Routes.GET("/domains", api.ListDomainsHandler)
}

func registerV2Routes(api v2.Api, apiGroup *gin.RouterGroup, registry *versioning.RouteVersionRegistry) {
    v2Routes := versioning.NewVersionedGroup(apiGroup.Group("v2"), registry, "v2")
    v2Routes.POST("/domains", api.CreateDomainHandler) // Only POST has v2
}
```

With the above setup:
- `POST /api/domains` with `x-version: v2` routes to the v2 handler
- `GET /api/domains` with `x-version: v2` returns `400 Unsupported API version Header`
- `GET /api/domains` with `x-version: v1` routes to the v1 handler

## Configuration

```go
cfg := versioning.Config{
    DefaultVersion:                     "v1",
    AssumeDefaultVersionWhenUnspecified: true,   // don't require version header
    ReportApiVersions:                  true,    // add api-supported-versions header
    Reader: versioning.NewCompositeVersionStrategy(
        versioning.NewHeaderVersionStrategy("x-version"),
        versioning.NewQueryStringVersionStrategy("api-version"),
    ),
    VersionFormat: `^v\d+(b\d+)?$`,
}
server.router.Use(versioning.Middleware(server.router, registry, cfg))
```

When no config is provided, `DefaultConfig()` is used: header-based (`x-version`), default `v1`, require header, no version reporting.

## Version Reading Strategies

| Strategy | Client sends | Example |
|---|---|---|
| `NewHeaderVersionStrategy("x-version")` | Header | `x-version: v2` |
| `NewQueryStringVersionStrategy("api-version")` | Query parameter | `?api-version=v2` |
| `URLSegmentVersionStrategy{}` | URL path | `/api/v2/domains` |
| `NewCompositeVersionStrategy(...)` | Multiple (first match wins) | Header, then query string |

## Error Responses

All error responses use RFC 9457 Problem Details format with `Content-Type: application/problem+json`:

```json
{
  "type": "https://tools.ietf.org/html/rfc7231#section-6.5.1",
  "title": "Bad Request",
  "status": 400,
  "detail": "Unsupported API version",
  "instance": "/api/domains"
}
```

## Backward Compatibility

Pass `nil` as the registry for services that haven't migrated to `VersionedGroup` yet:

```go
server.router.Use(versioning.Middleware(server.router, nil))
```

This skips per-endpoint version checking and behaves like a traditional global version validator.

## Testing

```bash
go test ./... -v
```

### Functional Test Coverage

The functional tests simulate a realistic domain service with v1 and v2 routes (`POST /domains` has both versions; `GET /domains`, `GET /domains/:id`, `PUT`, `DELETE`, `POST /domains/search` have v1 only) and exercise the full HTTP request lifecycle.

| Scenario | Method | Path | Version | Expected |
|---|---|---|---|---|
| v1 create domain | POST | /api/domains | v1 | 201 Created |
| v2 create domain | POST | /api/domains | v2 | 201 Created |
| v1 list domains | GET | /api/domains | v1 | 200 OK |
| v2 list domains (unsupported) | GET | /api/domains | v2 | 400 Unsupported API version |
| v1 get domain by name | GET | /api/domains/example.com | v1 | 200 OK |
| v2 get domain (unsupported) | GET | /api/domains/example.com | v2 | 400 Unsupported API version |
| v1 update domain | PUT | /api/domains/example.com | v1 | 200 OK |
| v1 delete domain | DELETE | /api/domains/example.com | v1 | 204 No Content |
| v1 search domains | POST | /api/domains/search | v1 | 200 OK |
| Missing version header | GET | /api/domains | (none) | 400 Missing API version |
| Invalid version format | GET | /api/domains | "latest" | 400 Invalid API version |
| Non-existent endpoint | GET | /api/contacts | v1 | 404 Not Found |
| Health endpoint (excluded) | GET | /health | (none) | 200 OK |
| OPTIONS request (excluded) | OPTIONS | /api/domains | (none) | not 400 |
| Assume default (no header) | GET | /api/domains | (none) | 200 OK (assumes v1) |
| Assume default + explicit v2 | POST | /api/domains | v2 | 201 Created |
| Report versions (POST) | POST | /api/domains | v1 | header: v1, v2 |
| Report versions (GET) | GET | /api/domains | v1 | header: v1 |
| Query string strategy | GET | /api/domains?api-version=v2 | (query) | 400 Unsupported |
| Composite: header wins | POST | /api/domains?api-version=v1 | v2 (header) | 201 Created (v2) |
| Composite: falls to query | POST | /api/domains?api-version=v1 | (no header) | 201 Created (v1) |
| URL segment strategy | POST | /api/v2/domains | (URL) | 201 Created (v2) |
| Problem details content type | GET | /api/domains | v2 | application/problem+json |
| Problem details structure | GET | /api/domains | v2 | RFC 9457 fields present |

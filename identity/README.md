# identity

Request-scoped actor identity propagation via `context.Context`.

The Go equivalent of `IHttpContextAccessor` + `IUserContext` in .NET Core — a
lightweight, zero-dependency bridge that carries authenticated user or
system identity through the call stack without coupling HTTP, database, or
business layers to one another.

```go
type Actor struct {
	Kind ActorKind // ActorKindUser or ActorKindSystem
	ID   string    // e.g. the user's email; "system" for system actors
	Sub  string    // stable JWT subject claim (Cognito UUID); empty for system actors
}
```

## Usage

```go
// In auth middleware (HTTP layer), after JWT validation:
actor := identity.Actor{Kind: identity.ActorKindUser, ID: "user@example.com", Sub: "cognito-sub-uuid"}
ctx = identity.NewContext(ctx, actor)

// In a repository or any downstream layer:
actor := identity.FromContext(ctx) // returns a system actor if none was set
entity.CreatedBy = actor.ID

// At a background job / engine entry point:
ctx = identity.SystemContext(ctx)
```

`FromContext` never requires callers to handle a nil/zero case: if no actor
was set (e.g. background jobs, tests), it returns a system actor
(`Kind: ActorKindSystem, ID: "system"`).

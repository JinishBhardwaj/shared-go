// Package identity provides request-scoped actor identity propagation via context.Context.
//
// It is the Go equivalent of IHttpContextAccessor + IUserContext in .NET Core —
// a lightweight, zero-dependency bridge that carries authenticated user or system
// identity through the call stack without coupling HTTP, database, or business layers
// to one another.
//
// Usage:
//
//	// In auth middleware (HTTP layer):
//	actor := identity.Actor{Kind: identity.ActorKindUser, ID: "user@example.com", Sub: "cognito-sub-uuid"}
//	ctx = identity.NewContext(ctx, actor)
//
//	// In repository or any downstream layer:
//	actor := identity.FromContext(ctx) // returns system actor if none set
//	entity.CreatedBy = actor.ID
//
//	// In background/engine contexts:
//	ctx = identity.SystemContext(ctx)
package identity

import "context"

// ActorKind distinguishes a human user from an automated system actor.
type ActorKind string

const (
	// ActorKindUser represents an authenticated human user (AuthCode + PKCE flow).
	ActorKindUser ActorKind = "user"

	// ActorKindSystem represents an automated system actor (engine, background jobs).
	ActorKindSystem ActorKind = "system"
)

// systemActorID is the identifier written to audit fields for system-initiated operations.
const systemActorID = "system"

// Actor represents the identity of the entity performing an operation.
// For user-initiated requests, ID is the user's email and Sub is the stable JWT subject claim.
// For system-initiated operations, Kind is ActorKindSystem and ID is "system".
type Actor struct {
	// Kind distinguishes user from system actors.
	Kind ActorKind

	// ID is the human-readable identifier written to audit fields (e.g., email for users).
	ID string

	// Sub is the stable JWT subject claim (Cognito UUID). Empty for system actors.
	// Use this when you need an immutable identifier that survives email changes.
	Sub string
}

// String returns the actor's ID, suitable for use as a string in audit fields.
func (a Actor) String() string { return a.ID }

// IsUser returns true if the actor represents an authenticated human user.
func (a Actor) IsUser() bool { return a.Kind == ActorKindUser }

// IsSystem returns true if the actor represents an automated system.
func (a Actor) IsSystem() bool { return a.Kind == ActorKindSystem }

// contextKey is an unexported type to prevent key collisions with other packages.
type contextKey struct{}

// NewContext returns a new context carrying the given actor.
// Called by auth middleware after JWT validation.
func NewContext(ctx context.Context, actor Actor) context.Context {
	return context.WithValue(ctx, contextKey{}, actor)
}

// FromContext retrieves the Actor from ctx.
// If no actor has been set (e.g., in background jobs or tests), a system actor is returned
// so downstream code never needs to handle a nil/zero case.
func FromContext(ctx context.Context) Actor {
	if actor, ok := ctx.Value(contextKey{}).(Actor); ok {
		return actor
	}
	return Actor{Kind: ActorKindSystem, ID: systemActorID}
}

// SystemContext returns a new context carrying a system actor.
// Use this at engine or background job entry points so all writes
// within that context record "system" as the audit actor.
func SystemContext(ctx context.Context) context.Context {
	return NewContext(ctx, Actor{Kind: ActorKindSystem, ID: systemActorID})
}

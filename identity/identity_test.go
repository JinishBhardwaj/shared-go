package identity_test

import (
	"context"
	"testing"

	"github.com/JinishBhardwaj/shared-go/identity"
)

func TestFromContext_NoActor_ReturnSystemFallback(t *testing.T) {
	actor := identity.FromContext(context.Background())

	if actor.Kind != identity.ActorKindSystem {
		t.Errorf("expected ActorKindSystem, got %q", actor.Kind)
	}
	if actor.ID != "system" {
		t.Errorf("expected ID %q, got %q", "system", actor.ID)
	}
	if actor.Sub != "" {
		t.Errorf("expected empty Sub for system actor, got %q", actor.Sub)
	}
}

func TestNewContext_RoundTrip(t *testing.T) {
	want := identity.Actor{
		Kind: identity.ActorKindUser,
		ID:   "jane@tucows.com",
		Sub:  "cognito-sub-abc123",
	}

	ctx := identity.NewContext(context.Background(), want)
	got := identity.FromContext(ctx)

	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestSystemContext_SetsSystemActor(t *testing.T) {
	ctx := identity.SystemContext(context.Background())
	actor := identity.FromContext(ctx)

	if !actor.IsSystem() {
		t.Errorf("expected system actor, got kind=%q id=%q", actor.Kind, actor.ID)
	}
	if actor.ID != "system" {
		t.Errorf("expected ID %q, got %q", "system", actor.ID)
	}
}

func TestActor_String(t *testing.T) {
	actor := identity.Actor{Kind: identity.ActorKindUser, ID: "jane@tucows.com"}
	if actor.String() != "jane@tucows.com" {
		t.Errorf("String() = %q, want %q", actor.String(), "jane@tucows.com")
	}
}

func TestActor_IsUser_IsSystem(t *testing.T) {
	user := identity.Actor{Kind: identity.ActorKindUser, ID: "jane@tucows.com"}
	if !user.IsUser() {
		t.Error("expected IsUser() = true")
	}
	if user.IsSystem() {
		t.Error("expected IsSystem() = false for user actor")
	}

	sys := identity.Actor{Kind: identity.ActorKindSystem, ID: "system"}
	if !sys.IsSystem() {
		t.Error("expected IsSystem() = true")
	}
	if sys.IsUser() {
		t.Error("expected IsUser() = false for system actor")
	}
}

func TestFromContext_DoesNotMutateParent(t *testing.T) {
	parent := context.Background()
	child := identity.NewContext(parent, identity.Actor{Kind: identity.ActorKindUser, ID: "jane@tucows.com"})

	// Parent should still return the system fallback
	actorFromParent := identity.FromContext(parent)
	if actorFromParent.Kind != identity.ActorKindSystem {
		t.Errorf("parent context was mutated; got actor kind %q", actorFromParent.Kind)
	}

	// Child should have the user actor
	actorFromChild := identity.FromContext(child)
	if actorFromChild.ID != "jane@tucows.com" {
		t.Errorf("child context has wrong actor; got %q", actorFromChild.ID)
	}
}

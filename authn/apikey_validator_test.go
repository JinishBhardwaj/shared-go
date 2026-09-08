package authn

import (
	"context"
	"testing"
	"time"
)

func TestAPIKeyValidator_SuccessAndExpiration(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	validator, err := NewAPIKeyValidator(store)
	if err != nil {
		t.Fatalf("unexpected error creating validator: %v", err)
	}

	ctx := context.Background()

	// 1. Create valid key
	rawKey, rec, err := store.CreateKey(
		"org_123",
		"ci-runner-app",
		"CI Key",
		[]string{"build:trigger", "read:logs"},
		[]string{"automation"},
		1*time.Hour,
	)
	if err != nil {
		t.Fatalf("failed creating key: %v", err)
	}

	// Validate valid key
	id, err := validator.ValidateKey(ctx, rawKey)
	if err != nil {
		t.Fatalf("ValidateKey failed: %v", err)
	}

	if id.Method != AuthMethodAPIKey {
		t.Errorf("expected method %s, got %s", AuthMethodAPIKey, id.Method)
	}
	if id.Subject != "org_123" {
		t.Errorf("expected subject org_123, got %s", id.Subject)
	}
	if id.ClientID != "ci-runner-app" {
		t.Errorf("expected client_id ci-runner-app, got %s", id.ClientID)
	}
	if !id.HasScope("build:trigger") || !id.HasScope("read:logs") {
		t.Errorf("expected scopes build:trigger and read:logs, got %v", id.Scopes)
	}
	if !id.HasRole("automation") {
		t.Errorf("expected role automation, got %v", id.Roles)
	}

	// 2. Revoked Key
	if err := store.RevokeKey(rec.ID); err != nil {
		t.Fatalf("failed revoking key: %v", err)
	}
	_, err = validator.ValidateKey(ctx, rawKey)
	if err != ErrAPIKeyRevoked {
		t.Errorf("expected ErrAPIKeyRevoked, got %v", err)
	}

	// 3. Expired Key
	expiredKey, _, err := store.CreateKey(
		"org_expired",
		"temp-app",
		"Expired Key",
		[]string{"test"},
		nil,
		-1*time.Second, // Already expired
	)
	if err != nil {
		t.Fatalf("failed creating expired key: %v", err)
	}

	_, err = validator.ValidateKey(ctx, expiredKey)
	if err != ErrAPIKeyExpired {
		t.Errorf("expected ErrAPIKeyExpired, got %v", err)
	}

	// 4. Unknown Key
	_, err = validator.ValidateKey(ctx, "ak_live_unknownkey123456789")
	if err != ErrAPIKeyNotFound {
		t.Errorf("expected ErrAPIKeyNotFound, got %v", err)
	}

	// 5. Empty Key
	_, err = validator.ValidateKey(ctx, "")
	if err != ErrAPIKeyNotFound {
		t.Errorf("expected ErrAPIKeyNotFound, got %v", err)
	}
}

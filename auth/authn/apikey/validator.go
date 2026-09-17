package apikey

import (
	"context"
	"errors"
	"time"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
)

var (
	ErrNilKeyStore = errors.New("authn: api key store is nil")
)

// APIKeyStore abstracts storage lookup for API keys.
type APIKeyStore interface {
	Lookup(ctx context.Context, keyHash string) (*APIKeyRecord, error)
}

// APIKeyValidator validates raw API keys against an APIKeyStore.
type APIKeyValidator struct {
	store APIKeyStore
}

// NewAPIKeyValidator creates a new validator backed by the provided store.
func NewAPIKeyValidator(store APIKeyStore) (*APIKeyValidator, error) {
	if store == nil {
		return nil, ErrNilKeyStore
	}
	return &APIKeyValidator{store: store}, nil
}

// ValidateKey hashes the provided raw key, checks the store, and converts the record to a Principal.
func (v *APIKeyValidator) ValidateKey(ctx context.Context, rawKey string) (*principal.Principal, error) {
	if rawKey == "" {
		return nil, ErrAPIKeyNotFound
	}

	keyHash := HashAPIKey(rawKey)
	record, err := v.store.Lookup(ctx, keyHash)
	if err != nil {
		return nil, err
	}

	var expiresAt time.Time
	if record.ExpiresAt != nil {
		expiresAt = *record.ExpiresAt
	}

	metadata := make(map[string]any, len(record.Metadata)+2)
	for k, val := range record.Metadata {
		metadata[k] = val
	}
	metadata["api_key_id"] = record.ID
	metadata["api_key_name"] = record.Name

	return &principal.Principal{
		Subject:   record.OwnerID,
		ClientID:  record.ClientID,
		Method:    principal.AuthMethodAPIKey,
		Scopes:    record.Scopes,
		Roles:     record.Roles,
		IssuedAt:  record.CreatedAt,
		ExpiresAt: expiresAt,
		Metadata:  metadata,
		RawToken:  rawKey,
	}, nil
}

package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrAPIKeyNotFound = errors.New("authn: api key not found or invalid")
	ErrAPIKeyRevoked  = errors.New("authn: api key has been revoked")
	ErrAPIKeyExpired  = errors.New("authn: api key has expired")
	ErrNilKeyStore    = errors.New("authn: api key store is nil")
)

// APIKeyRecord represents an API key entry in persistent or cached storage.
type APIKeyRecord struct {
	ID        string         `json:"id"`
	KeyHash   string         `json:"-"`
	Name      string         `json:"name"`
	OwnerID   string         `json:"owner_id"`
	ClientID  string         `json:"client_id"`
	Scopes    []string       `json:"scopes"`
	Roles     []string       `json:"roles"`
	Revoked   bool           `json:"revoked"`
	CreatedAt time.Time      `json:"created_at"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// APIKeyStore abstracts storage lookup for API keys.
type APIKeyStore interface {
	Lookup(ctx context.Context, keyHash string) (*APIKeyRecord, error)
}

// HashAPIKey computes the hex-encoded SHA-256 checksum of an API key.
func HashAPIKey(rawKey string) string {
	sum := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(sum[:])
}

// MemoryAPIKeyStore provides a thread-safe in-memory implementation of APIKeyStore.
type MemoryAPIKeyStore struct {
	mu      sync.RWMutex
	records map[string]*APIKeyRecord // keyHash -> Record
	byID    map[string]*APIKeyRecord // ID -> Record
}

// NewMemoryAPIKeyStore creates an initialized in-memory API key store.
func NewMemoryAPIKeyStore() *MemoryAPIKeyStore {
	return &MemoryAPIKeyStore{
		records: make(map[string]*APIKeyRecord),
		byID:    make(map[string]*APIKeyRecord),
	}
}

// CreateKey generates a secure random API key, hashes it, stores the record, and returns the plaintext key.
func (s *MemoryAPIKeyStore) CreateKey(ownerID, clientID, name string, scopes, roles []string, ttl time.Duration) (string, *APIKeyRecord, error) {
	// Generate 32 bytes of cryptographically secure random data
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", nil, fmt.Errorf("authn: failed generating random api key: %w", err)
	}

	rawKey := fmt.Sprintf("ak_live_%s", hex.EncodeToString(randomBytes))
	keyHash := HashAPIKey(rawKey)

	idBytes := make([]byte, 8)
	_, _ = rand.Read(idBytes)
	id := fmt.Sprintf("key_%s", hex.EncodeToString(idBytes))

	now := time.Now().UTC()
	var expiresAt *time.Time
	if ttl != 0 {
		exp := now.Add(ttl)
		expiresAt = &exp
	}

	rec := &APIKeyRecord{
		ID:        id,
		KeyHash:   keyHash,
		Name:      name,
		OwnerID:   ownerID,
		ClientID:  clientID,
		Scopes:    scopes,
		Roles:     roles,
		Revoked:   false,
		CreatedAt: now,
		ExpiresAt: expiresAt,
		Metadata:  make(map[string]any),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[keyHash] = rec
	s.byID[id] = rec

	return rawKey, rec, nil
}

// RevokeKey marks an API key as revoked by ID.
func (s *MemoryAPIKeyStore) RevokeKey(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, exists := s.byID[id]
	if !exists {
		return ErrAPIKeyNotFound
	}
	rec.Revoked = true
	return nil
}

// Lookup queries the store for the record matching keyHash.
func (s *MemoryAPIKeyStore) Lookup(ctx context.Context, keyHash string) (*APIKeyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rec, exists := s.records[keyHash]
	if !exists {
		return nil, ErrAPIKeyNotFound
	}

	// Constant-time compare keyHash to prevent timing attacks
	if subtle.ConstantTimeCompare([]byte(rec.KeyHash), []byte(keyHash)) != 1 {
		return nil, ErrAPIKeyNotFound
	}

	if rec.Revoked {
		return nil, ErrAPIKeyRevoked
	}

	if rec.ExpiresAt != nil && time.Now().UTC().After(*rec.ExpiresAt) {
		return nil, ErrAPIKeyExpired
	}

	return rec, nil
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
func (v *APIKeyValidator) ValidateKey(ctx context.Context, rawKey string) (*Principal, error) {
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

	return &Principal{
		Subject:   record.OwnerID,
		ClientID:  record.ClientID,
		Method:    AuthMethodAPIKey,
		Scopes:    record.Scopes,
		Roles:     record.Roles,
		IssuedAt:  record.CreatedAt,
		ExpiresAt: expiresAt,
		Metadata:  metadata,
		RawToken:  rawKey,
	}, nil
}

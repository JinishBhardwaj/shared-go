package authz

import (
	"context"
	"errors"
	"sync"
)

var (
	ErrPrincipalNotFound = errors.New("authz: principal has no permission records")
)

// PermissionRepository abstracts access to permission records in the application database.
type PermissionRepository interface {
	// GetPermissions retrieves the full bundle of rules for a given principal.
	GetPermissions(ctx context.Context, principalID string) (*PrincipalPermissions, error)

	// GrantPermission appends a permission rule to the principal's record.
	GrantPermission(ctx context.Context, principalID string, rule PermissionRule) error

	// RevokeAll removes all permissions for a principal.
	RevokeAll(ctx context.Context, principalID string) error
}

// MemoryPermissionRepository is an in-memory thread-safe implementation of PermissionRepository.
type MemoryPermissionRepository struct {
	mu          sync.RWMutex
	permissions map[string]*PrincipalPermissions
}

// NewMemoryPermissionRepository creates an initialized in-memory permission repository.
func NewMemoryPermissionRepository() *MemoryPermissionRepository {
	return &MemoryPermissionRepository{
		permissions: make(map[string]*PrincipalPermissions),
	}
}

// GetPermissions returns the permission bundle or an empty bundle if none exists.
func (r *MemoryPermissionRepository) GetPermissions(ctx context.Context, principalID string) (*PrincipalPermissions, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	bundle, exists := r.permissions[principalID]
	if !exists {
		return &PrincipalPermissions{
			PrincipalID: principalID,
			Rules:       nil,
		}, nil
	}

	// Return a copy
	rulesCopy := make([]PermissionRule, len(bundle.Rules))
	copy(rulesCopy, bundle.Rules)

	return &PrincipalPermissions{
		PrincipalID: principalID,
		Rules:       rulesCopy,
	}, nil
}

// GrantPermission adds a rule to a principal's bundle.
func (r *MemoryPermissionRepository) GrantPermission(ctx context.Context, principalID string, rule PermissionRule) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	bundle, exists := r.permissions[principalID]
	if !exists {
		bundle = &PrincipalPermissions{
			PrincipalID: principalID,
			Rules:       nil,
		}
		r.permissions[principalID] = bundle
	}

	bundle.Rules = append(bundle.Rules, rule)
	return nil
}

// RevokeAll clears all permission rules for the principal.
func (r *MemoryPermissionRepository) RevokeAll(ctx context.Context, principalID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.permissions, principalID)
	return nil
}

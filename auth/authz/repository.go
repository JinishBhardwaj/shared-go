package authz

import (
	"context"
	"errors"
	"sync"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
)

var (
	ErrPrincipalNotFound = errors.New("authz: principal has no permission records")
)

// PermissionReader is the read-only subset of PermissionRepository consumed
// by the authorization hot path (gap-analysis-final.md Tier 2: "Split
// PermissionRepository into reader/writer -- the hot path needs only
// GetPermissions").
type PermissionReader interface {
	// GetPermissions retrieves the full bundle of rules for the given
	// principal, already scoped to whatever account/tenant context the
	// caller populated onto p (e.g. p.Metadata["tenant_customer_id"]) --
	// takes the full Principal, not just its Subject, so an implementation
	// can read that context and scope its own query by it. This is the only
	// place tenant/account scoping happens; PermissionRule and Resource
	// carry no such field, and Matches performs no such comparison.
	//
	// A tenant-scoped implementation must also include platform-wide rules
	// that apply regardless of tenant context -- e.g. an internal/staff
	// principal (no tenant/account in Metadata at all, such as one
	// federated via Google SAML through Cognito, see
	// authn.CognitoClaimsNormalizer) still needs its grants returned even
	// though it has no account to scope by. Concretely, a SQL-backed
	// implementation must match "tenant_id = <p's tenant> OR tenant_id IS
	// NULL", not just "tenant_id = <p's tenant>" -- the latter silently
	// drops every platform-wide grant. There is no reference Postgres
	// implementation in this package to copy this from (removed; see
	// authz/parc.go's package history) -- this is the contract the next one
	// must satisfy.
	GetPermissions(ctx context.Context, p *principal.Principal) (*PrincipalPermissions, error)
}

// PermissionWriter is the administrative subset of PermissionRepository --
// granting and revoking permissions -- never called on the authorization
// hot path.
type PermissionWriter interface {
	// GrantPermission appends a permission rule to the principal's record.
	// Takes the full Principal, not just its Subject, for the same reason
	// as PermissionReader.GetPermissions: an implementation that scopes
	// rules by account/tenant needs to read that context from p (e.g.
	// p.Metadata) to know which account's record to write to.
	//
	// A rule with no tenant/account scope at all is a platform-wide grant
	// (see PermissionReader.GetPermissions) -- the highest-blast-radius rule
	// shape a tenant-scoped implementation can express, since it applies
	// regardless of tenant context. This interface does not gate who may
	// call GrantPermission with such a rule; a caller wiring this up behind
	// an admin API must restrict that itself.
	GrantPermission(ctx context.Context, p *principal.Principal, rule PermissionRule) error

	// RevokeAll removes all permissions for a principal.
	RevokeAll(ctx context.Context, p *principal.Principal) error
}

// PermissionRepository abstracts access to permission records in the
// application database. Composed of PermissionReader and PermissionWriter;
// existing implementations (e.g. MemoryPermissionRepository) satisfy it
// unchanged.
type PermissionRepository interface {
	PermissionReader
	PermissionWriter
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

// GetPermissions returns the permission bundle or an empty bundle if none
// exists. MemoryPermissionRepository is a single-account test/reference
// implementation -- it keys purely by p.Subject and does not itself
// demonstrate account-scoped fetching; a real, multi-account-aware
// implementation would additionally read p.Metadata for the caller's active
// account and scope its query by it.
func (r *MemoryPermissionRepository) GetPermissions(ctx context.Context, p *principal.Principal) (*PrincipalPermissions, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	bundle, exists := r.permissions[p.Subject]
	if !exists {
		return &PrincipalPermissions{
			PrincipalID: p.Subject,
			Rules:       nil,
		}, nil
	}

	// Return a copy
	rulesCopy := make([]PermissionRule, len(bundle.Rules))
	copy(rulesCopy, bundle.Rules)

	return &PrincipalPermissions{
		PrincipalID: p.Subject,
		Rules:       rulesCopy,
	}, nil
}

// GrantPermission adds a rule to a principal's bundle.
func (r *MemoryPermissionRepository) GrantPermission(ctx context.Context, p *principal.Principal, rule PermissionRule) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	bundle, exists := r.permissions[p.Subject]
	if !exists {
		bundle = &PrincipalPermissions{
			PrincipalID: p.Subject,
			Rules:       nil,
		}
		r.permissions[p.Subject] = bundle
	}

	bundle.Rules = append(bundle.Rules, rule)
	return nil
}

// RevokeAll clears all permission rules for the principal.
func (r *MemoryPermissionRepository) RevokeAll(ctx context.Context, p *principal.Principal) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.permissions, p.Subject)
	return nil
}

// Package postgres provides a PostgreSQL-backed implementation of
// authz.PermissionRepository (gap-analysis-final.md Tier 4 / §1.6 item 4:
// "DB-backed PermissionRepository -- memory-only persistence in a shared
// library is a real gap"). It is a drop-in alternative to
// authz.MemoryPermissionRepository for callers that need permission rules to
// survive process restarts and be shared across instances.
//
// Expected table shape (documentation only -- this package does not run
// migrations):
//
//	CREATE TABLE auth_permission_rules (
//	    id                  BIGSERIAL PRIMARY KEY,
//	    principal_id        TEXT NOT NULL,
//	    action_pattern      TEXT NOT NULL,
//	    resource_type       TEXT NOT NULL,
//	    resource_id_pattern TEXT NOT NULL,
//	    tenant_id           TEXT NOT NULL DEFAULT '',
//	    effect              TEXT NOT NULL
//	);
//	CREATE INDEX idx_auth_permission_rules_principal_id ON auth_permission_rules (principal_id);
package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/JinishBhardwaj/shared-go/auth/authz"
)

// pgxQuerier is the narrow subset of *pgxpool.Pool (and *pgx.Conn) that
// PermissionRepository depends on, so it can be constructed from either a
// pool or a single connection, and so tests can substitute a hand-rolled
// fake instead of a live database.
type pgxQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// PermissionRepository is a PostgreSQL-backed authz.PermissionRepository.
type PermissionRepository struct {
	pool pgxQuerier
}

// NewPermissionRepository creates a PermissionRepository backed by pool.
// pool is typically a *pgxpool.Pool, but any pgxQuerier (e.g. *pgx.Conn) is
// accepted.
func NewPermissionRepository(pool pgxQuerier) *PermissionRepository {
	return &PermissionRepository{pool: pool}
}

var _ authz.PermissionRepository = (*PermissionRepository)(nil)

// GetPermissions retrieves the full bundle of rules for a given principal.
// A principal with zero rows is not an error: it returns an empty bundle,
// matching authz.MemoryPermissionRepository's contract.
func (r *PermissionRepository) GetPermissions(ctx context.Context, principalID string) (*authz.PrincipalPermissions, error) {
	rows, err := r.pool.Query(ctx, `SELECT action_pattern, resource_type, resource_id_pattern, tenant_id, effect FROM auth_permission_rules WHERE principal_id = $1`, principalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []authz.PermissionRule
	for rows.Next() {
		var rule authz.PermissionRule
		if err := rows.Scan(&rule.ActionPattern, &rule.ResourceType, &rule.ResourceIDPattern, &rule.TenantID, &rule.Effect); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return &authz.PrincipalPermissions{
		PrincipalID: principalID,
		Rules:       rules,
	}, nil
}

// GrantPermission appends a permission rule to the principal's record.
func (r *PermissionRepository) GrantPermission(ctx context.Context, principalID string, rule authz.PermissionRule) error {
	_, err := r.pool.Exec(ctx, `INSERT INTO auth_permission_rules (principal_id, action_pattern, resource_type, resource_id_pattern, tenant_id, effect) VALUES ($1,$2,$3,$4,$5,$6)`,
		principalID, rule.ActionPattern, rule.ResourceType, rule.ResourceIDPattern, rule.TenantID, rule.Effect)
	return err
}

// RevokeAll removes all permissions for a principal.
func (r *PermissionRepository) RevokeAll(ctx context.Context, principalID string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM auth_permission_rules WHERE principal_id = $1`, principalID)
	return err
}

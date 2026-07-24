package database

import (
	"context"
	"testing"

	"github.com/JinishBhardwaj/shared-go/health"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheck_NilPool(t *testing.T) {
	entry := Check(nil)(context.Background())

	assert.Equal(t, health.StatusUnhealthy, entry.Status)
	assert.Contains(t, entry.Description, "not initialized")
	assert.Equal(t, []string{"database", "postgresql"}, entry.Tags)
	assert.NotEmpty(t, entry.Duration)
}

func TestCheck_CustomTags(t *testing.T) {
	entry := Check(nil, "db", "primary")(context.Background())
	assert.Equal(t, []string{"db", "primary"}, entry.Tags)
}

// TestCheck_UnreachableDatabase tests against an unreachable DSN with short timeout.
// No docker, no testcontainers, no real Postgres -- just an unreachable address
// and a short connect timeout to fail quickly.
func TestCheck_UnreachableDatabase(t *testing.T) {
	// Use a non-routable IP address with a short connect timeout.
	// This will fail immediately without needing to wait for a real timeout.
	config, err := pgxpool.ParseConfig("postgres://user:password@127.0.0.1:1/nonexistent?connect_timeout=1")
	require.NoError(t, err)

	// Create the pool with the config (it will fail on ping).
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err == nil {
		// If pool creation succeeded, that's unusual but we'll still test it.
		defer pool.Close()
	}

	// The check should report unhealthy because the connection fails.
	// We can test this by passing a pool that fails on QueryRow.
	// For an unreachable database, the pool creation itself may fail,
	// so we test by creating a pool that will fail when we try to use it.

	// Alternative: use a pool that's been closed.
	if pool != nil {
		pool.Close()
	}

	// Create a new config that will fail on connect.
	config2, err := pgxpool.ParseConfig("postgres://localhost:1/nonexistent?connect_timeout=1")
	require.NoError(t, err)

	pool2, err := pgxpool.NewWithConfig(context.Background(), config2)
	if err != nil {
		// Pool creation failed, which is expected for unreachable database.
		// We can't test with a nil pool here as that's already tested.
		// Instead, skip this as the failure happens at connection time.
		t.Skipf("Pool creation failed as expected: %v", err)
	}
	defer pool2.Close()

	// Run the check with default tags.
	entry := Check(pool2)(context.Background())

	// Should be unhealthy.
	assert.Equal(t, health.StatusUnhealthy, entry.Status)
	assert.NotEmpty(t, entry.Description)
	assert.Equal(t, []string{"database", "postgresql"}, entry.Tags)
	assert.NotEmpty(t, entry.Duration)
	assert.NotNil(t, entry.Data)
	assert.Contains(t, entry.Data, "error")
}

// Package database provides a health.Check for PostgreSQL connectivity backed
// by a pgx connection pool.
package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/JinishBhardwaj/shared-go/health"
)

const (
	// poolPressureThreshold is the fraction of acquired/max connections above
	// which the pool is considered under pressure (Degraded).
	poolPressureThreshold = 0.8
	// latencyThreshold is the probe latency above which the database is
	// considered Degraded.
	latencyThreshold = 100 * time.Millisecond
)

// Check returns a health.Check that verifies PostgreSQL connectivity via a
// `SELECT 1` probe and reports pool statistics.
//
// It reports:
//   - Unhealthy — pool is nil, or the probe query fails.
//   - Degraded  — pool usage > 80% of max connections, or probe latency > 100ms.
//   - Healthy   — otherwise.
//
// If no tags are supplied, {"database", "postgresql"} are used.
func Check(pool *pgxpool.Pool, tags ...string) health.Check {
	if len(tags) == 0 {
		tags = []string{"database", "postgresql"}
	}
	return func(ctx context.Context) health.Entry {
		start := time.Now()

		if pool == nil {
			return health.Entry{
				Status:      health.StatusUnhealthy,
				Description: "Database pool is not initialized",
				Duration:    health.FormatDuration(time.Since(start)),
				Tags:        tags,
			}
		}

		stats := pool.Stat()

		var result int
		err := pool.QueryRow(ctx, "SELECT 1").Scan(&result)
		duration := time.Since(start)

		if err != nil {
			return health.Entry{
				Status:      health.StatusUnhealthy,
				Description: fmt.Sprintf("Database query failed: %v", err),
				Duration:    health.FormatDuration(duration),
				Tags:        tags,
				Data: map[string]any{
					"total_conns":    stats.TotalConns(),
					"acquired_conns": stats.AcquiredConns(),
					"idle_conns":     stats.IdleConns(),
					"max_conns":      stats.MaxConns(),
					"error":          err.Error(),
				},
			}
		}

		status := health.StatusHealthy
		description := "Database is running and responsive"

		if maxConns := stats.MaxConns(); maxConns > 0 {
			if usageRatio := float64(stats.AcquiredConns()) / float64(maxConns); usageRatio > poolPressureThreshold {
				status = health.StatusDegraded
				description = fmt.Sprintf("Database connection pool usage is high (%.0f%%)", usageRatio*100)
			}
		}

		if duration > latencyThreshold {
			status = health.StatusDegraded
			description = fmt.Sprintf("Database latency is high (%s)", duration)
		}

		return health.Entry{
			Status:      status,
			Description: description,
			Duration:    health.FormatDuration(duration),
			Tags:        tags,
			Data: map[string]any{
				"total_conns":    stats.TotalConns(),
				"acquired_conns": stats.AcquiredConns(),
				"idle_conns":     stats.IdleConns(),
				"max_conns":      stats.MaxConns(),
			},
		}
	}
}

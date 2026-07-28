// Package redis provides a health.Check for Redis connectivity backed by
// github.com/redis/go-redis/v9.
package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/JinishBhardwaj/shared-go/health"
)

const latencyThreshold = 100 * time.Millisecond

// Check returns a health.Check that verifies Redis connectivity via a PING.
//
// It reports:
//   - Unhealthy — client is nil, or PING fails.
//   - Degraded  — PING succeeds but takes longer than 100ms.
//   - Healthy   — otherwise.
//
// If no tags are supplied, {"redis", "cache"} are used.
func Check(client *redis.Client, tags ...string) health.Check {
	if len(tags) == 0 {
		tags = []string{"redis", "cache"}
	}
	return func(ctx context.Context) health.Entry {
		start := time.Now()

		if client == nil {
			return health.Entry{
				Status:      health.StatusUnhealthy,
				Description: "Redis client is not initialized",
				Duration:    health.FormatDuration(time.Since(start)),
				Tags:        tags,
			}
		}

		err := client.Ping(ctx).Err()
		duration := time.Since(start)

		if err != nil {
			return health.Entry{
				Status:      health.StatusUnhealthy,
				Description: fmt.Sprintf("Redis PING failed: %v", err),
				Duration:    health.FormatDuration(duration),
				Tags:        tags,
				Data:        map[string]any{"error": err.Error()},
			}
		}

		status := health.StatusHealthy
		description := "Redis is running and responsive"
		if duration > latencyThreshold {
			status = health.StatusDegraded
			description = fmt.Sprintf("Redis latency is high (%s)", duration)
		}

		return health.Entry{
			Status:      status,
			Description: description,
			Duration:    health.FormatDuration(duration),
			Tags:        tags,
		}
	}
}

// Package bus provides a health.Check for a message bus connection,
// probing any provider-agnostic bus.Connection-shaped value (see
// github.com/JinishBhardwaj/message-bus-golang/bus.Connection) without
// depending on that module: Connection below is a local, minimal interface
// this package needs, matched structurally by any concrete adapter.
package bus

import (
	"context"
	"fmt"
	"time"

	"github.com/JinishBhardwaj/shared-go/health"
)

const latencyThreshold = 100 * time.Millisecond

// Connection is the one method this package needs from a bus connection.
// message-bus-golang's bus.Connection documents Connect as a no-op that
// returns nil when already connected, and safe to call again after Close —
// which is exactly what makes it usable as a repeatable connectivity probe
// here, without this package ever dialing, closing, or otherwise mutating
// connection state itself.
type Connection interface {
	Connect(ctx context.Context) error
}

// Check returns a health.Check that verifies bus connectivity by calling
// conn.Connect, relying on it being an idempotent no-op when already
// connected.
//
// It reports:
//   - Unhealthy — conn is nil, or Connect returns an error.
//   - Degraded  — Connect succeeds but takes longer than 100ms.
//   - Healthy   — otherwise.
//
// If no tags are supplied, {"bus", "messaging"} are used.
func Check(conn Connection, tags ...string) health.Check {
	if len(tags) == 0 {
		tags = []string{"bus", "messaging"}
	}
	return func(ctx context.Context) health.Entry {
		start := time.Now()

		if conn == nil {
			return health.Entry{
				Status:      health.StatusUnhealthy,
				Description: "Bus connection is not initialized",
				Duration:    health.FormatDuration(time.Since(start)),
				Tags:        tags,
			}
		}

		err := conn.Connect(ctx)
		duration := time.Since(start)

		if err != nil {
			return health.Entry{
				Status:      health.StatusUnhealthy,
				Description: fmt.Sprintf("Bus connect failed: %v", err),
				Duration:    health.FormatDuration(duration),
				Tags:        tags,
				Data:        map[string]any{"error": err.Error()},
			}
		}

		status := health.StatusHealthy
		description := "Bus is connected"
		if duration > latencyThreshold {
			status = health.StatusDegraded
			description = fmt.Sprintf("Bus connect latency is high (%s)", duration)
		}

		return health.Entry{
			Status:      status,
			Description: description,
			Duration:    health.FormatDuration(duration),
			Tags:        tags,
		}
	}
}

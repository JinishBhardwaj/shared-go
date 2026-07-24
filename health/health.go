// Package health provides transport-agnostic health-check aggregation with a
// response shape matching the ASP.NET Core HealthChecks-UI format.
//
// The package intentionally has no knowledge of HTTP or any web framework:
// register checks on a Checker, call Run to get a Response, and let the
// consuming application decide how to expose it (e.g. gin /health, /live,
// /ready routes) and what status code to emit.
//
// Concrete checks (database, message bus, generic services) live in sibling
// packages (health/database, health/rabbitmq, health/service) so this core
// module stays dependency-free.
package health

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Status represents the health status of a component or the overall system.
type Status string

const (
	StatusHealthy   Status = "Healthy"
	StatusDegraded  Status = "Degraded"
	StatusUnhealthy Status = "Unhealthy"
)

// Entry represents the result of a single health check.
type Entry struct {
	Status      Status   `json:"status"`
	Description string   `json:"description"`
	Duration    string   `json:"duration"`
	Tags        []string `json:"tags"`
	Data        any      `json:"data,omitempty"`
}

// Response represents the complete aggregated health-check response.
type Response struct {
	Status        Status           `json:"status"`
	TotalDuration string           `json:"totalDuration"`
	Entries       map[string]Entry `json:"entries"`
}

// Check performs a single health check and returns its Entry.
// Implementations must respect ctx cancellation/deadline.
type Check func(ctx context.Context) Entry

// Checker manages a set of named health checks and runs them concurrently.
// It is safe for concurrent use.
type Checker struct {
	checks map[string]Check
	mu     sync.RWMutex
}

// NewChecker creates a new, empty Checker.
func NewChecker() *Checker {
	return &Checker{
		checks: make(map[string]Check),
	}
}

// Register adds (or replaces) a health check under the given name.
func (c *Checker) Register(name string, check Check) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checks[name] = check
}

// Run executes all registered checks concurrently and returns the aggregated
// response. The overall status is the worst of any entry
// (Unhealthy > Degraded > Healthy). With no registered checks it reports
// Healthy with an empty entries map.
func (c *Checker) Run(ctx context.Context) Response {
	c.mu.RLock()
	checks := make(map[string]Check, len(c.checks))
	for name, check := range c.checks {
		checks[name] = check
	}
	c.mu.RUnlock()

	start := time.Now()
	entries := make(map[string]Entry, len(checks))
	overallStatus := StatusHealthy

	var wg sync.WaitGroup
	var mu sync.Mutex

	for name, check := range checks {
		wg.Add(1)
		go func(name string, check Check) {
			defer wg.Done()

			entry := check(ctx)

			mu.Lock()
			entries[name] = entry
			// Update overall status (Unhealthy > Degraded > Healthy).
			if entry.Status == StatusUnhealthy {
				overallStatus = StatusUnhealthy
			} else if entry.Status == StatusDegraded && overallStatus != StatusUnhealthy {
				overallStatus = StatusDegraded
			}
			mu.Unlock()
		}(name, check)
	}

	wg.Wait()

	return Response{
		Status:        overallStatus,
		TotalDuration: FormatDuration(time.Since(start)),
		Entries:       entries,
	}
}

// FormatDuration formats a duration in the .NET TimeSpan format
// (hh:mm:ss.fffffff) used by the ASP.NET Core HealthChecks-UI.
func FormatDuration(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60
	nanoseconds := d.Nanoseconds() % 1e9
	// Convert to 100-nanosecond ticks (7 decimal places).
	ticks := nanoseconds / 100
	return fmt.Sprintf("%02d:%02d:%02d.%07d", hours, minutes, seconds, ticks)
}

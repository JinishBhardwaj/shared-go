package health

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func staticCheck(s Status, desc string) Check {
	return func(ctx context.Context) Entry {
		return Entry{Status: s, Description: desc}
	}
}

func TestChecker_AllHealthy(t *testing.T) {
	c := NewChecker()
	c.Register("a", staticCheck(StatusHealthy, "ok"))
	c.Register("b", staticCheck(StatusHealthy, "ok"))

	resp := c.Run(context.Background())

	assert.Equal(t, StatusHealthy, resp.Status)
	assert.Len(t, resp.Entries, 2)
	assert.Contains(t, resp.Entries, "a")
	assert.Contains(t, resp.Entries, "b")
}

func TestChecker_UnhealthyWins(t *testing.T) {
	c := NewChecker()
	c.Register("a", staticCheck(StatusHealthy, "ok"))
	c.Register("b", staticCheck(StatusUnhealthy, "down"))
	c.Register("c", staticCheck(StatusDegraded, "slow"))

	resp := c.Run(context.Background())

	assert.Equal(t, StatusUnhealthy, resp.Status)
	assert.Len(t, resp.Entries, 3)
}

func TestChecker_DegradedOverHealthy(t *testing.T) {
	c := NewChecker()
	c.Register("a", staticCheck(StatusHealthy, "ok"))
	c.Register("b", staticCheck(StatusDegraded, "slow"))

	resp := c.Run(context.Background())

	assert.Equal(t, StatusDegraded, resp.Status)
}

func TestChecker_NoChecks(t *testing.T) {
	resp := NewChecker().Run(context.Background())

	assert.Equal(t, StatusHealthy, resp.Status)
	assert.NotNil(t, resp.Entries)
	assert.Empty(t, resp.Entries)
}

func TestChecker_RegisterReplaces(t *testing.T) {
	c := NewChecker()
	c.Register("a", staticCheck(StatusUnhealthy, "down"))
	c.Register("a", staticCheck(StatusHealthy, "ok")) // replace

	resp := c.Run(context.Background())

	assert.Equal(t, StatusHealthy, resp.Status)
	assert.Len(t, resp.Entries, 1)
}

func TestChecker_PropagatesContext(t *testing.T) {
	type ctxKey struct{}
	c := NewChecker()
	var seen bool
	c.Register("a", func(ctx context.Context) Entry {
		seen = ctx.Value(ctxKey{}) == "v"
		return Entry{Status: StatusHealthy}
	})

	c.Run(context.WithValue(context.Background(), ctxKey{}, "v"))
	assert.True(t, seen, "check should receive the caller's context")
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name string
		in   time.Duration
		want string
	}{
		{"hours+micros", time.Hour + 2*time.Minute + 3*time.Second + 450*time.Microsecond, "01:02:03.0004500"},
		{"zero", 0, "00:00:00.0000000"},
		{"wraps minutes/seconds", 90 * time.Minute, "01:30:00.0000000"},
		{"millis", 5 * time.Millisecond, "00:00:00.0050000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, FormatDuration(tt.in))
		})
	}
}

// TestResponse_JSONShape locks the ASP.NET HealthChecks-UI wire format.
func TestResponse_JSONShape(t *testing.T) {
	resp := Response{
		Status:        StatusDegraded,
		TotalDuration: "00:00:00.0010000",
		Entries: map[string]Entry{
			"database": {
				Status:      StatusDegraded,
				Description: "high latency",
				Duration:    "00:00:00.0009000",
				Tags:        []string{"database", "postgresql"},
				Data:        map[string]any{"max_conns": 25},
			},
		},
	}

	b, err := json.Marshal(resp)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(b, &got))

	assert.Equal(t, "Degraded", got["status"])
	assert.Equal(t, "00:00:00.0010000", got["totalDuration"])
	entries, ok := got["entries"].(map[string]any)
	require.True(t, ok)
	db, ok := entries["database"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "Degraded", db["status"])
	assert.Equal(t, "high latency", db["description"])
	assert.Equal(t, "00:00:00.0009000", db["duration"])
	assert.Contains(t, db, "data")
}

// TestEntry_DataOmittedWhenNil verifies the omitempty on Data.
func TestEntry_DataOmittedWhenNil(t *testing.T) {
	b, err := json.Marshal(Entry{Status: StatusHealthy, Description: "ok"})
	require.NoError(t, err)
	assert.NotContains(t, string(b), "\"data\"")
}

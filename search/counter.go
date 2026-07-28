package search

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// DefaultCountTimeout bounds an exact COUNT(*) before AdaptiveCounter falls back
// to a planner estimate. Tuned for reseller-scale tables.
const DefaultCountTimeout = 200 * time.Millisecond

// DefaultAdminCountTimeout is a more generous bound for admin/cross-tenant
// queries over larger result sets.
const DefaultAdminCountTimeout = 500 * time.Millisecond

// CountFunc runs a count-style query and returns the row count. The caller (or
// an adapter) injects these — one for the exact COUNT(*), one for the planner
// estimate — so the search package stays free of any DB driver (DIP).
type CountFunc func(ctx context.Context) (int64, error)

// Counter is the Strategy for producing a total count for a search result.
type Counter interface {
	// Count decides between an exact count and a planner estimate. `exact` runs
	// COUNT(*); `estimate` runs the planner estimate (see ParseExplainEstimate).
	Count(ctx context.Context, exact, estimate CountFunc) (CountResult, error)
}

// ExactCounter always runs an exact COUNT(*). Use for small tables or where an
// exact total is required.
type ExactCounter struct{}

func (ExactCounter) Count(ctx context.Context, exact, _ CountFunc) (CountResult, error) {
	n, err := exact(ctx)
	if err != nil {
		return CountResult{}, fmt.Errorf("exact count failed: %w", err)
	}
	return CountResult{Count: n, IsEstimated: false}, nil
}

// AdaptiveCounter runs an exact COUNT(*) within Timeout; if it doesn't finish in
// time the query is cancelled and a near-instant PostgreSQL planner estimate is
// returned instead (IsEstimated=true).
type AdaptiveCounter struct {
	Timeout time.Duration // 0 → DefaultCountTimeout
}

func (c AdaptiveCounter) Count(ctx context.Context, exact, estimate CountFunc) (CountResult, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultCountTimeout
	}

	countCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	n, err := exact(countCtx)
	if err == nil {
		return CountResult{Count: n, IsEstimated: false}, nil
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		return CountResult{}, fmt.Errorf("count query failed: %w", err)
	}

	est, estErr := estimate(ctx)
	if estErr != nil {
		return CountResult{}, fmt.Errorf("count timed out and estimate failed: %w", estErr)
	}
	return CountResult{Count: est, IsEstimated: true}, nil
}

// explainPlan is the top-level EXPLAIN (FORMAT JSON) output.
type explainPlan struct {
	Plan struct {
		PlanRows float64 `json:"Plan Rows"`
	} `json:"Plan"`
}

// ParseExplainEstimate extracts the planner's estimated row count from the JSON
// produced by `EXPLAIN (FORMAT JSON) <select>`. EXPLAIN a SELECT (not COUNT(*))
// so Plan Rows reflects matching rows, not the aggregate's single output row.
func ParseExplainEstimate(explainJSON string) (int64, error) {
	var plans []explainPlan
	if err := json.Unmarshal([]byte(explainJSON), &plans); err != nil {
		return 0, fmt.Errorf("failed to parse EXPLAIN output: %w", err)
	}
	if len(plans) == 0 {
		return 0, fmt.Errorf("empty EXPLAIN output")
	}
	return int64(plans[0].Plan.PlanRows), nil
}

// CorrectEmptyFirstPage neutralises an inflated planner estimate: when the first
// page came back empty, the true total is 0 regardless of the estimate.
// `rowsOnPage` is the number of rows returned for the page described by `p`.
func CorrectEmptyFirstPage(result CountResult, p Pagination, rowsOnPage int) CountResult {
	if result.IsEstimated && p.Number() == 1 && rowsOnPage == 0 {
		return CountResult{Count: 0, IsEstimated: false}
	}
	return result
}

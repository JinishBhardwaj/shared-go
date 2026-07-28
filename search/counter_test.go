package search

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestExactCounter(t *testing.T) {
	res, err := ExactCounter{}.Count(context.Background(),
		func(context.Context) (int64, error) { return 42, nil }, nil)
	if err != nil || res.Count != 42 || res.IsEstimated {
		t.Fatalf("res %#v err %v", res, err)
	}

	wantErr := errors.New("boom")
	_, err = ExactCounter{}.Count(context.Background(),
		func(context.Context) (int64, error) { return 0, wantErr }, nil)
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want wrap of %v", err, wantErr)
	}
}

func TestAdaptiveCounter_ExactSucceeds(t *testing.T) {
	res, err := AdaptiveCounter{}.Count(context.Background(),
		func(context.Context) (int64, error) { return 10, nil },
		func(context.Context) (int64, error) { t.Fatal("estimate should not run"); return 0, nil })
	if err != nil || res.Count != 10 || res.IsEstimated {
		t.Fatalf("res %#v err %v", res, err)
	}
}

func TestAdaptiveCounter_NonDeadlineErrorPropagates(t *testing.T) {
	wantErr := errors.New("db down")
	_, err := AdaptiveCounter{}.Count(context.Background(),
		func(context.Context) (int64, error) { return 0, wantErr },
		func(context.Context) (int64, error) { t.Fatal("estimate should not run"); return 0, nil })
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want wrap of %v", err, wantErr)
	}
}

func TestAdaptiveCounter_DeadlineFallsBackToEstimate(t *testing.T) {
	res, err := AdaptiveCounter{Timeout: time.Millisecond}.Count(context.Background(),
		func(context.Context) (int64, error) { return 0, context.DeadlineExceeded },
		func(context.Context) (int64, error) { return 4242, nil })
	if err != nil || !res.IsEstimated || res.Count != 4242 {
		t.Fatalf("res %#v err %v", res, err)
	}
}

func TestAdaptiveCounter_EstimateAlsoFails(t *testing.T) {
	_, err := AdaptiveCounter{Timeout: time.Millisecond}.Count(context.Background(),
		func(context.Context) (int64, error) { return 0, context.DeadlineExceeded },
		func(context.Context) (int64, error) { return 0, errors.New("explain failed") })
	if err == nil {
		t.Fatal("want error when estimate fails")
	}
}

func TestParseExplainEstimate(t *testing.T) {
	n, err := ParseExplainEstimate(`[{"Plan": {"Plan Rows": 1234.0}}]`)
	if err != nil || n != 1234 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if _, err := ParseExplainEstimate(`[]`); err == nil {
		t.Error("empty array should error")
	}
	if _, err := ParseExplainEstimate(`not json`); err == nil {
		t.Error("bad json should error")
	}
}

func TestCorrectEmptyFirstPage(t *testing.T) {
	est := CountResult{Count: 999, IsEstimated: true}
	// page 1, no rows → corrected to exact 0
	got := CorrectEmptyFirstPage(est, Pagination{PageNumber: 1}, 0)
	if got.Count != 0 || got.IsEstimated {
		t.Errorf("got %#v, want exact 0", got)
	}
	// page 1 with rows → unchanged
	if got := CorrectEmptyFirstPage(est, Pagination{PageNumber: 1}, 5); got != est {
		t.Errorf("rows present should not correct: %#v", got)
	}
	// page 2 empty → unchanged (only page 1 is corrected)
	if got := CorrectEmptyFirstPage(est, Pagination{PageNumber: 2}, 0); got != est {
		t.Errorf("page 2 should not correct: %#v", got)
	}
	// exact count never touched
	exact := CountResult{Count: 0, IsEstimated: false}
	if got := CorrectEmptyFirstPage(exact, Pagination{PageNumber: 1}, 0); got != exact {
		t.Errorf("exact should be untouched: %#v", got)
	}
}

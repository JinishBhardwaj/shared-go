package pgx

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestIsQueryTimeout(t *testing.T) {
	if IsQueryTimeout(nil) {
		t.Error("nil should not be a timeout")
	}
	if !IsQueryTimeout(context.DeadlineExceeded) {
		t.Error("DeadlineExceeded should be a timeout")
	}
	if !IsQueryTimeout(context.Canceled) {
		t.Error("Canceled should be a timeout")
	}
	// wrapped context error
	if !IsQueryTimeout(fmt.Errorf("query failed: %w", context.DeadlineExceeded)) {
		t.Error("wrapped DeadlineExceeded should be a timeout")
	}
	// Postgres 57014
	canceled := &pgconn.PgError{Code: "57014"}
	if !IsQueryTimeout(canceled) {
		t.Error("SQLSTATE 57014 should be a timeout")
	}
	if !IsQueryTimeout(fmt.Errorf("exec: %w", canceled)) {
		t.Error("wrapped 57014 should be a timeout")
	}
	// other pg error → not a timeout
	if IsQueryTimeout(&pgconn.PgError{Code: "23505"}) {
		t.Error("unique violation is not a timeout")
	}
	if IsQueryTimeout(errors.New("plain")) {
		t.Error("plain error is not a timeout")
	}
}

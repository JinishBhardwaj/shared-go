package pgx

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// pgErrCodeQueryCanceled is PostgreSQL SQLSTATE 57014 (query_canceled), returned
// when a statement is cancelled — e.g. by statement_timeout or by cancelling the
// query's context.
const pgErrCodeQueryCanceled = "57014"

// IsQueryTimeout reports whether err represents a query that was cancelled or
// timed out: a context deadline/cancellation, or PostgreSQL SQLSTATE 57014.
// Boundaries map this to HTTP 408. It is the pgconn-coupled concern deliberately
// kept out of the driver-agnostic search core.
func IsQueryTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgErrCodeQueryCanceled
}

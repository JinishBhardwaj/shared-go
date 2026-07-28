package pgx

import (
	"context"

	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Querier is the minimal read substrate the searcher needs: scan many rows,
// run a count, and run a single-row scan (for the EXPLAIN estimate). Its method
// set is deliberately narrow so any compatible reader can be passed in directly
// (Go interfaces are structural) without importing this package's dependencies.
type Querier interface {
	Select(ctx context.Context, dest any, query string, args ...any) error
	Count(ctx context.Context, query string, args ...any) (int64, error)
	QueryRow(ctx context.Context, query string, args ...any) pgx.Row
}

// pgxPool is the subset of *pgxpool.Pool the built-in querier uses.
type pgxPool interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

var _ pgxPool = (*pgxpool.Pool)(nil)

// poolQuerier is the built-in Querier backed by a pgx pool and scany.
type poolQuerier struct {
	pool pgxPool
}

func (q poolQuerier) Select(ctx context.Context, dest any, query string, args ...any) error {
	rows, err := q.pool.Query(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	return pgxscan.ScanAll(dest, rows)
}

func (q poolQuerier) Count(ctx context.Context, query string, args ...any) (int64, error) {
	var n int64
	if err := q.pool.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (q poolQuerier) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	return q.pool.QueryRow(ctx, query, args...)
}

var _ Querier = poolQuerier{}

package pgx

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/JinishBhardwaj/shared-go/search"
	"golang.org/x/sync/errgroup"
)

// Table describes the non-search parts of a query the core compiler cannot
// derive: the SELECT column list and the FROM clause (including any JOINs).
// Columns and From are trusted, code-supplied SQL — never request input.
type Table struct {
	Columns string // e.g. "r.*" or "r.id, r.name, t.label"
	From    string // e.g. "registry r" or "registry r LEFT JOIN tld t ON t.registry_id = r.id"
}

// Searcher executes a search.RequestBody against PostgreSQL: it compiles the
// request with a ResourceConfig, runs the data page and the total count in
// parallel, and returns the scanned page plus a paged view model.
type Searcher struct {
	q Querier
}

// New builds a Searcher over any Querier (e.g. a repo/pgx.BaseReader, or a
// transaction-backed reader).
func New(q Querier) *Searcher { return &Searcher{q: q} }

// NewFromPool builds a Searcher over a pgx pool using the built-in scany querier.
func NewFromPool(pool *pgxpool.Pool) *Searcher { return &Searcher{q: poolQuerier{pool: pool}} }

// Search validates and compiles req against cfg, fetches the page into dest (a
// pointer to a slice), counts the total per the resource's Counter strategy, and
// returns the response envelope. Data fetch and count run concurrently.
//
// dest is scanned via the Querier; on a validation failure it returns a
// search.ValidationError (map to 400/422) and does not touch the database.
func (s *Searcher) Search(
	ctx context.Context,
	cfg *search.ResourceConfig,
	req search.RequestBody,
	tbl Table,
	dest any,
	opts ...search.CompileOption,
) (search.PagedViewModel, error) {
	if err := cfg.Validate(&req); err != nil {
		return search.PagedViewModel{}, err
	}
	q, err := cfg.Compile(req, opts...)
	if err != nil {
		return search.PagedViewModel{}, err
	}

	dataSQL := buildDataSQL(tbl, q)
	exact, estimate := s.countFuncs(tbl, q)

	g, gctx := errgroup.WithContext(ctx)

	var count search.CountResult
	g.Go(func() error {
		var cerr error
		count, cerr = cfg.Count(gctx, exact, estimate)
		return cerr
	})

	g.Go(func() error {
		return s.q.Select(gctx, dest, dataSQL, q.Args...)
	})

	if err := g.Wait(); err != nil {
		return search.PagedViewModel{}, err
	}

	// An empty first page means the true total is 0, overriding any inflated
	// planner estimate (search.CorrectEmptyFirstPage).
	count = search.CorrectEmptyFirstPage(count, req.Pagination, sliceLen(dest))
	return search.NewPagedViewModel(req.Pagination, count.Count, count.IsEstimated, cfg.MaxPageSize), nil
}

// buildDataSQL assembles the full data SELECT from the table spec and compiled
// query. ORDER BY / LIMIT are already formatted by the core ("" when absent).
func buildDataSQL(tbl Table, q search.CompiledQuery) string {
	var b strings.Builder
	b.WriteString("SELECT ")
	b.WriteString(tbl.Columns)
	b.WriteString(" FROM ")
	b.WriteString(tbl.From)
	writeWhere(&b, q.Where)
	if q.OrderBy != "" {
		b.WriteByte(' ')
		b.WriteString(q.OrderBy)
	}
	if q.Limit != "" {
		b.WriteByte(' ')
		b.WriteString(q.Limit)
	}
	return b.String()
}

// buildCountSQL assembles the exact COUNT(*) query (no ORDER BY / LIMIT).
func buildCountSQL(tbl Table, q search.CompiledQuery) string {
	var b strings.Builder
	b.WriteString("SELECT COUNT(*) FROM ")
	b.WriteString(tbl.From)
	writeWhere(&b, q.Where)
	return b.String()
}

// buildEstimateSQL assembles the planner-estimate query: EXPLAIN a SELECT 1 (not
// COUNT(*)) so Plan Rows reflects matching rows, not the aggregate's single row.
func buildEstimateSQL(tbl Table, q search.CompiledQuery) string {
	var b strings.Builder
	b.WriteString("EXPLAIN (FORMAT JSON) SELECT 1 FROM ")
	b.WriteString(tbl.From)
	writeWhere(&b, q.Where)
	return b.String()
}

func writeWhere(b *strings.Builder, where string) {
	if where != "" {
		b.WriteString(" WHERE ")
		b.WriteString(where)
	}
}

// countFuncs returns the exact and estimate CountFuncs the core Counter drives.
func (s *Searcher) countFuncs(tbl Table, q search.CompiledQuery) (exact, estimate search.CountFunc) {
	countSQL := buildCountSQL(tbl, q)
	estimateSQL := buildEstimateSQL(tbl, q)

	exact = func(ctx context.Context) (int64, error) {
		return s.q.Count(ctx, countSQL, q.Args...)
	}
	estimate = func(ctx context.Context) (int64, error) {
		var explainJSON string
		if err := s.q.QueryRow(ctx, estimateSQL, q.Args...).Scan(&explainJSON); err != nil {
			return 0, err
		}
		return search.ParseExplainEstimate(explainJSON)
	}
	return exact, estimate
}

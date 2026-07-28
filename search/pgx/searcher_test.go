package pgx

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/JinishBhardwaj/shared-go/search"
)

// --- fake Querier (no database) ----------------------------------------------

type fakeRow struct {
	scan func(dest ...any) error
}

func (r fakeRow) Scan(dest ...any) error { return r.scan(dest...) }

type fakeQuerier struct {
	rowsToReturn int   // how many elements Select populates into dest
	countResult  int64 // value returned by Count
	countErr     error
	explainJSON  string // value scanned by QueryRow (estimate path)

	gotSelectSQL string
	gotCountSQL  string
	gotEstSQL    string
	selectCalls  int
}

func (f *fakeQuerier) Select(ctx context.Context, dest any, query string, args ...any) error {
	f.gotSelectSQL = query
	f.selectCalls++
	// Populate dest (*[]T) with rowsToReturn zero-value elements.
	v := reflect.ValueOf(dest).Elem()
	v.Set(reflect.MakeSlice(v.Type(), f.rowsToReturn, f.rowsToReturn))
	return nil
}

func (f *fakeQuerier) Count(ctx context.Context, query string, args ...any) (int64, error) {
	f.gotCountSQL = query
	return f.countResult, f.countErr
}

func (f *fakeQuerier) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	f.gotEstSQL = query
	return fakeRow{scan: func(dest ...any) error {
		*(dest[0].(*string)) = f.explainJSON
		return nil
	}}
}

func testCfg() *search.ResourceConfig {
	return &search.ResourceConfig{
		Name:        "registry",
		MaxPageSize: 50,
		DefaultSort: search.SortConfig{Field: "name", Direction: search.SortAsc},
		Fields: map[string]search.FieldConfig{
			"name": {Type: search.FieldString, Column: "r.name", Sortable: true, Searchable: true},
			"id":   {Type: search.FieldUUID, Column: "r.id", AllowedOperators: []string{search.OpEq, search.OpIn}},
		},
	}
}

type registryRow struct {
	ID   string `db:"id"`
	Name string `db:"name"`
}

func TestSearch_HappyPath(t *testing.T) {
	fq := &fakeQuerier{rowsToReturn: 10, countResult: 42}
	s := New(fq)
	req := search.RequestBody{
		Filters:    []search.FilterParameter{{Field: "name", Operator: "eq", Value: "acme"}},
		Pagination: search.Pagination{PageSize: 10, PageNumber: 2},
	}
	var dest []registryRow
	tbl := Table{Columns: "r.*", From: "registry r"}
	vm, err := s.Search(context.Background(), testCfg(), req, tbl, &dest)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if vm.TotalCount != 42 || vm.PageSize != 10 || vm.PageNumber != 2 {
		t.Errorf("vm = %#v", vm)
	}
	if vm.IsEstimatedCount {
		t.Error("exact count should not be estimated")
	}
	if len(dest) != 10 {
		t.Errorf("dest len = %d, want 10", len(dest))
	}
	if fq.gotSelectSQL != "SELECT r.* FROM registry r WHERE r.name = $1 ORDER BY r.name ASC LIMIT 10 OFFSET 10" {
		t.Errorf("data SQL = %q", fq.gotSelectSQL)
	}
	if fq.gotCountSQL != "SELECT COUNT(*) FROM registry r WHERE r.name = $1" {
		t.Errorf("count SQL = %q", fq.gotCountSQL)
	}
}

func TestSearch_EmptyFirstPageCorrectsEstimate(t *testing.T) {
	// exact count times out → estimate path; data page empty → corrected to 0.
	fq := &fakeQuerier{
		rowsToReturn: 0,
		countErr:     context.DeadlineExceeded,
		explainJSON:  `[{"Plan": {"Plan Rows": 999.0}}]`,
	}
	cfg := testCfg()
	cfg.Counter = search.AdaptiveCounter{} // explicit (also the default)
	s := New(fq)
	var dest []registryRow
	vm, err := s.Search(context.Background(), cfg,
		search.RequestBody{Pagination: search.Pagination{PageNumber: 1, PageSize: 10}},
		Table{Columns: "r.*", From: "registry r"}, &dest)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if vm.TotalCount != 0 || vm.IsEstimatedCount {
		t.Errorf("empty first page should correct to exact 0, got %#v", vm)
	}
	if fq.gotEstSQL != "EXPLAIN (FORMAT JSON) SELECT 1 FROM registry r" {
		t.Errorf("estimate SQL = %q", fq.gotEstSQL)
	}
}

func TestSearch_ValidationErrorShortCircuits(t *testing.T) {
	fq := &fakeQuerier{}
	s := New(fq)
	var dest []registryRow
	_, err := s.Search(context.Background(), testCfg(),
		search.RequestBody{Filters: []search.FilterParameter{{Field: "ghost", Operator: "eq", Value: "x"}}},
		Table{Columns: "r.*", From: "registry r"}, &dest)
	if !search.IsValidationError(err) {
		t.Fatalf("want ValidationError, got %v", err)
	}
	if fq.selectCalls != 0 {
		t.Error("validation failure must not hit the database")
	}
}

func TestSearch_SelectErrorPropagates(t *testing.T) {
	fq := &fakeQuerier{countResult: 5}
	fq2 := &errSelectQuerier{fakeQuerier: fq, err: errors.New("scan boom")}
	s := New(fq2)
	var dest []registryRow
	_, err := s.Search(context.Background(), testCfg(), search.RequestBody{},
		Table{Columns: "r.*", From: "registry r"}, &dest)
	if err == nil {
		t.Fatal("expected select error to propagate")
	}
}

type errSelectQuerier struct {
	*fakeQuerier
	err error
}

func (e *errSelectQuerier) Select(ctx context.Context, dest any, query string, args ...any) error {
	return e.err
}

// --- pure SQL assembly -------------------------------------------------------

func TestBuildSQL(t *testing.T) {
	tbl := Table{Columns: "r.id, r.name", From: "registry r"}
	q := search.CompiledQuery{
		Where:   "r.name = $1",
		OrderBy: "ORDER BY r.name ASC",
		Limit:   "LIMIT 10 OFFSET 0",
	}
	if got := buildDataSQL(tbl, q); got != "SELECT r.id, r.name FROM registry r WHERE r.name = $1 ORDER BY r.name ASC LIMIT 10 OFFSET 0" {
		t.Errorf("data: %q", got)
	}
	if got := buildCountSQL(tbl, q); got != "SELECT COUNT(*) FROM registry r WHERE r.name = $1" {
		t.Errorf("count: %q", got)
	}
	if got := buildEstimateSQL(tbl, q); got != "EXPLAIN (FORMAT JSON) SELECT 1 FROM registry r WHERE r.name = $1" {
		t.Errorf("estimate: %q", got)
	}

	// no WHERE, no ORDER BY
	empty := search.CompiledQuery{Limit: "LIMIT 10 OFFSET 0"}
	if got := buildDataSQL(tbl, empty); got != "SELECT r.id, r.name FROM registry r LIMIT 10 OFFSET 0" {
		t.Errorf("data no-where: %q", got)
	}
	if got := buildCountSQL(tbl, empty); got != "SELECT COUNT(*) FROM registry r" {
		t.Errorf("count no-where: %q", got)
	}
}

func TestSliceLen(t *testing.T) {
	rows := []registryRow{{}, {}, {}}
	if got := sliceLen(&rows); got != 3 {
		t.Errorf("sliceLen = %d, want 3", got)
	}
	empty := []registryRow{}
	if got := sliceLen(&empty); got != 0 {
		t.Errorf("sliceLen empty = %d, want 0", got)
	}
	// non-slice / non-pointer → safe non-zero
	if got := sliceLen("nope"); got != 1 {
		t.Errorf("sliceLen non-slice = %d, want 1", got)
	}
	var nilPtr *[]registryRow
	if got := sliceLen(nilPtr); got != 1 {
		t.Errorf("sliceLen nil ptr = %d, want 1", got)
	}
}

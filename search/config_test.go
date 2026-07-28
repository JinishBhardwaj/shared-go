package search

import (
	"context"
	"errors"
	"testing"
)

func sampleConfig() *ResourceConfig {
	return &ResourceConfig{
		Name:         "registry",
		TenantColumn: "r.tenant_id",
		MaxPageSize:  50,
		MaxBulkTerms: 5,
		DefaultSort:  SortConfig{Field: "name", Direction: SortAsc},
		Fields: map[string]FieldConfig{
			"name":       {Type: FieldString, Column: "r.name", Sortable: true, Searchable: true},
			"label":      {Type: FieldString, Column: "r.label", Searchable: true},
			"id":         {Type: FieldUUID, Column: "r.id", AllowedOperators: []string{OpEq, OpIn}},
			"created_at": {Type: FieldDate, Column: "r.created_at", Sortable: true, AllowedOperators: []string{OpBetween, OpGte}},
			"active":     {Type: FieldBool, Column: "r.active"},
			"rank":       {Type: FieldInt, Column: "r.rank", AllowedOperators: []string{OpEq, OpGt}},
		},
	}
}

func TestCompile_FullRequestWithTenant(t *testing.T) {
	c := sampleConfig()
	req := RequestBody{
		SearchTerms: []string{"ac*"},
		Filters: []FilterParameter{
			{Field: "active", Operator: "eq", Value: true},
			{Field: "rank", Operator: "gt", Value: float64(3)},
		},
		SortFields: []SortField{{Field: "name", Direction: "desc"}},
		Pagination: Pagination{PageSize: 20, PageNumber: 2},
	}
	if err := c.Validate(&req); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	q, err := c.Compile(req, WithTenant("t-123"))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	// search columns are sorted by column name: r.label, r.name
	wantWhere := "r.tenant_id = $1 AND ((r.label ILIKE $2 OR r.name ILIKE $2)) AND r.active = $3::boolean AND r.rank > $4::bigint"
	if q.Where != wantWhere {
		t.Errorf("Where =\n  %q\nwant\n  %q", q.Where, wantWhere)
	}
	if q.OrderBy != "ORDER BY r.name DESC" {
		t.Errorf("OrderBy = %q", q.OrderBy)
	}
	if q.Limit != "LIMIT 20 OFFSET 20" {
		t.Errorf("Limit = %q", q.Limit)
	}
	if len(q.Args) != 4 || q.Args[0] != "t-123" || q.Args[1] != "ac%" || q.Args[2] != true || q.Args[3] != int64(3) {
		t.Errorf("Args = %#v", q.Args)
	}
}

func TestCompile_TenantOmittedWhenNoOption(t *testing.T) {
	c := sampleConfig()
	q, err := c.Compile(RequestBody{}) // no WithTenant
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if q.Where != "" {
		t.Errorf("expected no WHERE without tenant option, got %q", q.Where)
	}
}

func TestCompile_TenantIgnoredWhenNoTenantColumn(t *testing.T) {
	c := sampleConfig()
	c.TenantColumn = ""
	q, err := c.Compile(RequestBody{}, WithTenant("t-1"))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if q.Where != "" {
		t.Errorf("tenant should be ignored with empty TenantColumn, got %q", q.Where)
	}
}

func TestCompile_DefaultSortFallback(t *testing.T) {
	c := sampleConfig()
	q, _ := c.Compile(RequestBody{}) // no sort fields → default sort
	if q.OrderBy != "ORDER BY r.name ASC" {
		t.Errorf("default sort OrderBy = %q", q.OrderBy)
	}
}

func TestCompile_InvalidSortFieldSkipped(t *testing.T) {
	c := sampleConfig()
	// "active" is not sortable; "name" is. buildOrderBy skips invalid, keeps valid.
	q, _ := c.Compile(RequestBody{SortFields: []SortField{
		{Field: "active", Direction: "asc"},
		{Field: "name", Direction: "asc"},
	}})
	if q.OrderBy != "ORDER BY r.name ASC" {
		t.Errorf("OrderBy = %q", q.OrderBy)
	}
}

func TestCompile_PageClampedToResourceMax(t *testing.T) {
	c := sampleConfig() // MaxPageSize 50
	q, _ := c.Compile(RequestBody{Pagination: Pagination{PageSize: 999, PageNumber: 3}})
	if q.Limit != "LIMIT 50 OFFSET 100" {
		t.Errorf("Limit = %q, want LIMIT 50 OFFSET 100", q.Limit)
	}
}

func TestCompile_EnforcesOperatorAllowlistWithoutValidate(t *testing.T) {
	c := sampleConfig()
	// rank allows eq/gt only; lt must be rejected by Compile itself.
	_, err := c.Compile(RequestBody{Filters: []FilterParameter{{Field: "rank", Operator: "lt", Value: 1.0}}})
	var ue *UnsupportedOperatorError
	if !errors.As(err, &ue) {
		t.Fatalf("want UnsupportedOperatorError, got %v", err)
	}
}

func TestCompile_UnknownFilterFieldRejected(t *testing.T) {
	c := sampleConfig()
	_, err := c.Compile(RequestBody{Filters: []FilterParameter{{Field: "ghost", Operator: "eq", Value: "x"}}})
	var fe *InvalidFieldError
	if !errors.As(err, &fe) {
		t.Fatalf("want InvalidFieldError, got %v", err)
	}
}

func TestCompile_AllWildcardTermSkipped(t *testing.T) {
	c := sampleConfig()
	q, _ := c.Compile(RequestBody{SearchTerms: []string{"***", "  "}})
	if q.Where != "" {
		t.Errorf("all-wildcard/blank terms should be skipped, got %q", q.Where)
	}
}

func TestValidate_AllErrorPaths(t *testing.T) {
	c := sampleConfig()
	cases := []struct {
		name string
		req  RequestBody
	}{
		{"unknown filter field", RequestBody{Filters: []FilterParameter{{Field: "nope", Operator: "eq"}}}},
		{"disallowed operator", RequestBody{Filters: []FilterParameter{{Field: "id", Operator: "gt"}}}},
		{"unknown sort field", RequestBody{SortFields: []SortField{{Field: "nope", Direction: "asc"}}}},
		{"not sortable", RequestBody{SortFields: []SortField{{Field: "active", Direction: "asc"}}}},
		{"too many bulk terms", RequestBody{SearchTerms: []string{"1", "2", "3", "4", "5", "6"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := c.Validate(&tc.req)
			if err == nil || !IsValidationError(err) {
				t.Fatalf("want ValidationError, got %v", err)
			}
		})
	}
}

func TestValidate_BulkTermsCountsOnlyEffective(t *testing.T) {
	c := sampleConfig() // MaxBulkTerms 5
	// 5 real terms + blanks + all-wildcard terms (which Compile skips) → must pass.
	req := RequestBody{SearchTerms: []string{"a", "b", "c", "d", "e", "  ", "", "***", "?"}}
	if err := c.Validate(&req); err != nil {
		t.Fatalf("blank/wildcard terms must not count toward MaxBulkTerms: %v", err)
	}
	// 6 real terms → exceeds limit.
	req6 := RequestBody{SearchTerms: []string{"a", "b", "c", "d", "e", "f"}}
	if err := c.Validate(&req6); !IsValidationError(err) {
		t.Fatalf("6 effective terms should exceed limit, got %v", err)
	}
}

func TestValidate_HappyPath(t *testing.T) {
	c := sampleConfig()
	req := RequestBody{
		Filters:    []FilterParameter{{Field: "id", Operator: "in", Value: []any{"a"}}},
		SortFields: []SortField{{Field: "created_at", Direction: "DESC"}},
	}
	if err := c.Validate(&req); err != nil {
		t.Fatalf("Validate should pass: %v", err)
	}
}

func TestPageSize_DefaultMaxWhenUnset(t *testing.T) {
	c := &ResourceConfig{Name: "x"} // MaxPageSize 0 → DefaultMaxPageSize
	if got := c.PageSize(Pagination{PageSize: 1000}); got != DefaultMaxPageSize {
		t.Errorf("PageSize = %d, want %d", got, DefaultMaxPageSize)
	}
}

func TestSearchColumns_DeterministicOrder(t *testing.T) {
	c := sampleConfig()
	first := c.searchColumns()
	for i := 0; i < 20; i++ {
		got := c.searchColumns()
		if len(got) != len(first) {
			t.Fatalf("length changed: %v vs %v", got, first)
		}
		for j := range got {
			if got[j] != first[j] {
				t.Fatalf("order not deterministic: %v vs %v", got, first)
			}
		}
	}
	// sorted: r.label before r.name
	if first[0] != "r.label" || first[1] != "r.name" {
		t.Errorf("searchColumns = %v, want [r.label r.name]", first)
	}
}

func TestCount_DefaultsToAdaptive(t *testing.T) {
	c := sampleConfig() // no Counter set
	called := false
	exact := func(ctx context.Context) (int64, error) { called = true; return 7, nil }
	res, err := c.Count(context.Background(), exact, nil)
	if err != nil || !called || res.Count != 7 || res.IsEstimated {
		t.Fatalf("res %#v err %v called %v", res, err, called)
	}
}

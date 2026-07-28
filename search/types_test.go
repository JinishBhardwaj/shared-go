package search

import "testing"

func TestPagination_Size(t *testing.T) {
	cases := []struct {
		size, max, want int
	}{
		{0, 0, DefaultPageSize},      // unset → default
		{-5, 0, DefaultPageSize},     // negative → default
		{20, 50, 20},                 // within bounds
		{999, 50, 50},                // clamped to resource max
		{999, 0, DefaultMaxPageSize}, // clamped to default max
		{0, 5, 5},                    // default 10 > max 5 → clamp to max
	}
	for _, tc := range cases {
		if got := (Pagination{PageSize: tc.size}).SizeWithMax(tc.max); got != tc.want {
			t.Errorf("SizeWithMax(size=%d,max=%d) = %d, want %d", tc.size, tc.max, got, tc.want)
		}
	}
}

func TestPagination_NumberOffset(t *testing.T) {
	if n := (Pagination{}).Number(); n != 1 {
		t.Errorf("default Number = %d, want 1", n)
	}
	if n := (Pagination{PageNumber: -3}).Number(); n != 1 {
		t.Errorf("negative Number = %d, want 1", n)
	}
	// page 3, size 20 → offset 40
	if off := (Pagination{PageNumber: 3, PageSize: 20}).OffsetWithMax(50); off != 40 {
		t.Errorf("OffsetWithMax = %d, want 40", off)
	}
}

func TestPagination_TotalPages(t *testing.T) {
	p := Pagination{PageSize: 10}
	cases := []struct {
		total int64
		want  int
	}{
		{0, 0},
		{1, 1},
		{10, 1},
		{11, 2},
		{25, 3},
	}
	for _, tc := range cases {
		if got := p.TotalPagesWithMax(tc.total, 100); got != tc.want {
			t.Errorf("TotalPages(%d) = %d, want %d", tc.total, got, tc.want)
		}
	}
}

func TestPagination_HasPreviousPage(t *testing.T) {
	if (Pagination{PageNumber: 1}).HasPreviousPage() {
		t.Error("page 1 should have no previous")
	}
	if !(Pagination{PageNumber: 2}).HasPreviousPage() {
		t.Error("page 2 should have previous")
	}
}

func TestNewPagedViewModel(t *testing.T) {
	p := Pagination{PageSize: 10, PageNumber: 2}
	vm := NewPagedViewModel(p, 25, true, 100)
	if vm.PageSize != 10 || vm.PageNumber != 2 || vm.TotalCount != 25 {
		t.Errorf("vm = %#v", vm)
	}
	if vm.TotalPages != 3 {
		t.Errorf("TotalPages = %d, want 3", vm.TotalPages)
	}
	if !vm.HasNextPage { // page 2 of 3
		t.Error("HasNextPage should be true")
	}
	if !vm.HasPreviousPage {
		t.Error("HasPreviousPage should be true")
	}
	if !vm.IsEstimatedCount {
		t.Error("IsEstimatedCount should propagate")
	}

	// last page → no next
	last := NewPagedViewModel(Pagination{PageSize: 10, PageNumber: 3}, 25, false, 100)
	if last.HasNextPage {
		t.Error("last page should have no next")
	}
}

func TestFieldType_Cast(t *testing.T) {
	cases := map[FieldType]string{
		FieldString: "",
		FieldUUID:   "::uuid",
		FieldInt:    "::bigint",
		FieldBool:   "::boolean",
		FieldDate:   "::timestamptz",
		FieldArray:  "",
	}
	for ft, want := range cases {
		if got := ft.cast(); got != want {
			t.Errorf("FieldType(%d).cast() = %q, want %q", ft, got, want)
		}
	}
}

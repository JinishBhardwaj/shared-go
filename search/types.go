package search

// FieldType is the data type of a filterable/sortable field. It drives the
// parameter cast applied by DirectColumnResolver and the typed value coercion
// performed before a value is bound.
type FieldType int

const (
	FieldString FieldType = iota
	FieldUUID
	FieldInt
	FieldBool
	FieldDate
	FieldArray
)

// cast returns the SQL cast appended to a bound parameter for this type (so a
// JSON string value compares against a typed column), or "" for none.
func (t FieldType) cast() string {
	switch t {
	case FieldUUID:
		return "::uuid"
	case FieldDate:
		return "::timestamptz"
	case FieldInt:
		// JSON numbers decode to float64; cast so comparisons against integer
		// columns don't fail with a type mismatch.
		return "::bigint"
	case FieldBool:
		return "::boolean"
	default:
		return ""
	}
}

// SortDirection is the normalised sort direction.
type SortDirection string

const (
	SortAsc  SortDirection = "asc"
	SortDesc SortDirection = "desc"
)

// SortConfig is a resource's default sort.
type SortConfig struct {
	Field     string
	Direction SortDirection
}

// SortField is a single sort criterion from a request.
type SortField struct {
	Field     string `json:"field" binding:"required"`
	Direction string `json:"direction" binding:"required,oneof=asc desc ASC DESC"`
}

// FilterParameter is a single filter condition. Value is a scalar for most
// operators, or a JSON array (decoded as []any) for in / not_in / between.
type FilterParameter struct {
	Field    string `json:"field" binding:"required"`
	Operator string `json:"operator" binding:"required"`
	Value    any    `json:"value"`
}

// CountResult is the outcome of a count: the total and whether it's a planner
// estimate (true when an exact count timed out — see AdaptiveCounter).
type CountResult struct {
	Count       int64
	IsEstimated bool
}

// DefaultPageSize is used when a request omits or zeroes the page size.
const DefaultPageSize = 10

// DefaultMaxPageSize caps a page to protect the database when a ResourceConfig
// does not set its own MaxPageSize.
const DefaultMaxPageSize = 100

// Pagination carries 1-based page paging. Clamping is resolved against a
// resource's MaxPageSize via the *WithMax helpers (see ResourceConfig.Compile);
// the bare methods fall back to DefaultMaxPageSize.
type Pagination struct {
	PageSize   int `json:"page_size" binding:"omitempty,gte=1"`
	PageNumber int `json:"page_number" binding:"omitempty,gte=1"`
}

// SizeWithMax returns the clamped page size for an explicit maximum (max<=0 ⇒
// DefaultMaxPageSize).
func (p Pagination) SizeWithMax(max int) int {
	if max <= 0 {
		max = DefaultMaxPageSize
	}
	switch {
	case p.PageSize <= 0:
		if DefaultPageSize > max {
			return max
		}
		return DefaultPageSize
	case p.PageSize > max:
		return max
	default:
		return p.PageSize
	}
}

// Size returns the clamped page size (default 10, max DefaultMaxPageSize).
func (p Pagination) Size() int { return p.SizeWithMax(DefaultMaxPageSize) }

// Number returns the 1-based page number (default 1).
func (p Pagination) Number() int {
	if p.PageNumber <= 0 {
		return 1
	}
	return p.PageNumber
}

// OffsetWithMax returns the SQL OFFSET for the current page under a max size.
func (p Pagination) OffsetWithMax(max int) int { return (p.Number() - 1) * p.SizeWithMax(max) }

// Offset returns the SQL OFFSET for the current page.
func (p Pagination) Offset() int { return p.OffsetWithMax(DefaultMaxPageSize) }

// TotalPagesWithMax returns the page count for a total record count under a max size.
func (p Pagination) TotalPagesWithMax(total int64, max int) int {
	if total <= 0 {
		return 0
	}
	size := int64(p.SizeWithMax(max))
	return int((total + size - 1) / size)
}

// TotalPages returns the page count for a total record count.
func (p Pagination) TotalPages(total int64) int {
	return p.TotalPagesWithMax(total, DefaultMaxPageSize)
}

// HasPreviousPage reports whether the current page is past the first.
func (p Pagination) HasPreviousPage() bool { return p.Number() > 1 }

// RequestBody is the generic search request, shared by all searchable resources.
type RequestBody struct {
	SearchTerms []string          `json:"search_terms"`
	Filters     []FilterParameter `json:"filters"`
	SortFields  []SortField       `json:"sort_fields"`
	Pagination  Pagination        `json:"pagination"`
}

// PagedViewModel is the search response pagination envelope.
type PagedViewModel struct {
	PageSize         int   `json:"page_size"`
	PageNumber       int   `json:"page_number"`
	TotalCount       int64 `json:"total_count"`
	TotalPages       int   `json:"total_pages"`
	HasNextPage      bool  `json:"has_next_page"`
	HasPreviousPage  bool  `json:"has_previous_page"`
	IsEstimatedCount bool  `json:"is_estimated_count"`
}

// NewPagedViewModel builds the response envelope for a request + total count,
// clamping the page size to max (max<=0 ⇒ DefaultMaxPageSize).
func NewPagedViewModel(p Pagination, total int64, estimated bool, max int) PagedViewModel {
	size := p.SizeWithMax(max)
	totalPages := p.TotalPagesWithMax(total, max)
	return PagedViewModel{
		PageSize:         size,
		PageNumber:       p.Number(),
		TotalCount:       total,
		TotalPages:       totalPages,
		HasNextPage:      p.Number() < totalPages,
		HasPreviousPage:  p.HasPreviousPage(),
		IsEstimatedCount: estimated,
	}
}

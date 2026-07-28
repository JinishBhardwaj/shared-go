package versioning

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatchPattern_ExactMatch(t *testing.T) {
	assert.True(t, matchPattern("/domains/search", "/domains/search"))
}

func TestMatchPattern_ParamSegment(t *testing.T) {
	assert.True(t, matchPattern("/domains/test.net", "/domains/:id_or_name"))
}

func TestMatchPattern_MultipleParams(t *testing.T) {
	assert.True(t, matchPattern("/domains/test.net/transfer/approve", "/domains/:name/transfer/:action"))
}

func TestMatchPattern_SegmentCountMismatch(t *testing.T) {
	assert.False(t, matchPattern("/domains", "/domains/:id_or_name"))
	assert.False(t, matchPattern("/domains/test.net/extra", "/domains/:id_or_name"))
}

func TestMatchPattern_LiteralMismatch(t *testing.T) {
	assert.False(t, matchPattern("/contacts/123", "/domains/:id"))
}

func TestMatchPattern_WildcardSegment(t *testing.T) {
	assert.True(t, matchPattern("/swagger/index.html", "/swagger/*any"))
	assert.True(t, matchPattern("/swagger/v1/doc.json", "/swagger/*any"))
}

func TestMatchPattern_RootPath(t *testing.T) {
	assert.True(t, matchPattern("/domains", "/domains"))
}

func TestMatchPattern_AdminRoutes(t *testing.T) {
	assert.True(t, matchPattern("/admin/domains", "/admin/domains"))
	assert.False(t, matchPattern("/domains", "/admin/domains"))
}

func TestSplitPath(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"/domains/test.net", []string{"domains", "test.net"}},
		{"/", nil},
		{"", nil},
		{"/admin/domains", []string{"admin", "domains"}},
	}

	for _, tc := range tests {
		result := splitPath(tc.input)
		assert.Equal(t, tc.expected, result, "splitPath(%q)", tc.input)
	}
}

func TestExtractBasePathForLookup(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/api/domains/test.net", "/domains/test.net"},
		{"/api/v2/domains/test.net", "/domains/test.net"},
		{"/api/v1/admin/domains", "/admin/domains"},
		{"/api/admin/domains", "/admin/domains"},
		{"/api/v1/domains", "/domains"},
		{"/api", "/"},
	}

	for _, tc := range tests {
		result := extractBasePathForLookup(tc.input)
		assert.Equal(t, tc.expected, result, "extractBasePathForLookup(%q)", tc.input)
	}
}

func TestExtractBasePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/api/domains/test.net", "/domains/test.net"},
		{"/api/admin/domains", "/admin/domains"},
		{"/api", "/"},
		{"/health", "/health"},
	}

	for _, tc := range tests {
		result := extractBasePath(tc.input)
		assert.Equal(t, tc.expected, result, "extractBasePath(%q)", tc.input)
	}
}

package versioning

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func newTestContext(method, path string, headers map[string]string) *gin.Context {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(method, path, nil)
	for k, v := range headers {
		c.Request.Header.Set(k, v)
	}
	return c
}

func TestHeaderVersionStrategy_Found(t *testing.T) {
	s := NewHeaderVersionStrategy("x-version")
	c := newTestContext("GET", "/api/domains", map[string]string{"x-version": "v2"})

	version, found := s.ReadVersion(c)
	assert.True(t, found)
	assert.Equal(t, "v2", version)
}

func TestHeaderVersionStrategy_NotFound(t *testing.T) {
	s := NewHeaderVersionStrategy("x-version")
	c := newTestContext("GET", "/api/domains", nil)

	version, found := s.ReadVersion(c)
	assert.False(t, found)
	assert.Equal(t, "", version)
}

func TestHeaderVersionStrategy_EmptyValue(t *testing.T) {
	s := NewHeaderVersionStrategy("x-version")
	c := newTestContext("GET", "/api/domains", map[string]string{"x-version": ""})

	version, found := s.ReadVersion(c)
	assert.True(t, found, "header present but empty should be found=true")
	assert.Equal(t, "", version)
}

func TestQueryStringVersionStrategy_Found(t *testing.T) {
	s := NewQueryStringVersionStrategy("api-version")
	c := newTestContext("GET", "/api/domains?api-version=v2", nil)

	version, found := s.ReadVersion(c)
	assert.True(t, found)
	assert.Equal(t, "v2", version)
}

func TestQueryStringVersionStrategy_NotFound(t *testing.T) {
	s := NewQueryStringVersionStrategy("api-version")
	c := newTestContext("GET", "/api/domains", nil)

	_, found := s.ReadVersion(c)
	assert.False(t, found)
}

func TestURLSegmentVersionStrategy_Found(t *testing.T) {
	s := URLSegmentVersionStrategy{}
	c := newTestContext("GET", "/api/v2/domains", nil)

	version, found := s.ReadVersion(c)
	assert.True(t, found)
	assert.Equal(t, "v2", version)
}

func TestURLSegmentVersionStrategy_NotFound(t *testing.T) {
	s := URLSegmentVersionStrategy{}
	c := newTestContext("GET", "/api/domains", nil)

	_, found := s.ReadVersion(c)
	assert.False(t, found)
}

func TestURLSegmentVersionStrategy_NonApiPath(t *testing.T) {
	s := URLSegmentVersionStrategy{}
	c := newTestContext("GET", "/health", nil)

	_, found := s.ReadVersion(c)
	assert.False(t, found)
}

func TestCompositeVersionStrategy_FirstWins(t *testing.T) {
	s := NewCompositeVersionStrategy(
		NewHeaderVersionStrategy("x-version"),
		NewQueryStringVersionStrategy("api-version"),
	)
	c := newTestContext("GET", "/api/domains?api-version=v1", map[string]string{"x-version": "v2"})

	version, found := s.ReadVersion(c)
	assert.True(t, found)
	assert.Equal(t, "v2", version, "header should win over query string")
}

func TestCompositeVersionStrategy_FallsThrough(t *testing.T) {
	s := NewCompositeVersionStrategy(
		NewHeaderVersionStrategy("x-version"),
		NewQueryStringVersionStrategy("api-version"),
	)
	c := newTestContext("GET", "/api/domains?api-version=v2", nil)

	version, found := s.ReadVersion(c)
	assert.True(t, found)
	assert.Equal(t, "v2", version, "should fall through to query string")
}

func TestCompositeVersionStrategy_NoneFound(t *testing.T) {
	s := NewCompositeVersionStrategy(
		NewHeaderVersionStrategy("x-version"),
		NewQueryStringVersionStrategy("api-version"),
	)
	c := newTestContext("GET", "/api/domains", nil)

	_, found := s.ReadVersion(c)
	assert.False(t, found)
}

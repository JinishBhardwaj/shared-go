package versioning

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/neocotic/go-problem"
	"github.com/stretchr/testify/assert"
)

func TestWriteProblem(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/api/resource", nil)

	writeProblem(c, "test error detail")

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/problem+json")
	assert.True(t, c.IsAborted())

	body, _ := io.ReadAll(w.Body)
	var pd map[string]interface{}
	err := json.Unmarshal(body, &pd)
	assert.NoError(t, err)
	assert.Equal(t, "Bad Request", pd["title"])
	assert.Equal(t, float64(400), pd["status"])
	assert.Equal(t, "test error detail", pd["detail"])
	assert.Equal(t, "/api/resource", pd["instance"])
	assert.Equal(t, "https://tools.ietf.org/html/rfc7231#section-6.5.1", pd["type"])
}

func TestProblemToMap_WithAllFields(t *testing.T) {
	p := problem.New(
		problem.FromType(problemBadRequest),
		problem.WithDetail("some detail"),
		problem.WithInstance("/api/test"),
	)
	m := problemToMap(p)

	assert.Equal(t, "https://tools.ietf.org/html/rfc7231#section-6.5.1", m["type"])
	assert.Equal(t, "Bad Request", m["title"])
	assert.Equal(t, 400, m["status"])
	assert.Equal(t, "some detail", m["detail"])
	assert.Equal(t, "/api/test", m["instance"])
}

func TestProblemToMap_OmitsEmptyOptionalFields(t *testing.T) {
	p := problem.New(
		problem.FromType(problemBadRequest),
	)
	m := problemToMap(p)

	assert.Equal(t, "Bad Request", m["title"])
	assert.Equal(t, 400, m["status"])
	_, hasDetail := m["detail"]
	assert.False(t, hasDetail, "detail should be omitted when empty")
	_, hasInstance := m["instance"]
	assert.False(t, hasInstance, "instance should be omitted when empty")
}

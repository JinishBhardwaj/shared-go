package versioning

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestNewVersionedGroup_NilRegistryPanics(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	assert.Panics(t, func() {
		NewVersionedGroup(router.Group("/api/v1"), nil, "v1")
	})
}

func TestVersionedGroup_POST(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	registry := NewRouteVersionRegistry()
	vg := NewVersionedGroup(router.Group("/api/v1"), registry, "v1")

	handler := func(c *gin.Context) { c.Status(http.StatusOK) }
	vg.POST("/domains", handler)

	exists, supported := registry.Lookup("POST", "/domains", "v1")
	assert.True(t, exists)
	assert.True(t, supported)
}

func TestVersionedGroup_GET(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	registry := NewRouteVersionRegistry()
	vg := NewVersionedGroup(router.Group("/api/v1"), registry, "v1")

	handler := func(c *gin.Context) { c.Status(http.StatusOK) }
	vg.GET("/domains/:id", handler)

	exists, supported := registry.Lookup("GET", "/domains/test.net", "v1")
	assert.True(t, exists)
	assert.True(t, supported)
}

func TestVersionedGroup_PUT(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	registry := NewRouteVersionRegistry()
	vg := NewVersionedGroup(router.Group("/api/v1"), registry, "v1")

	handler := func(c *gin.Context) { c.Status(http.StatusOK) }
	vg.PUT("/domains/:id", handler)

	exists, supported := registry.Lookup("PUT", "/domains/test.net", "v1")
	assert.True(t, exists)
	assert.True(t, supported)
}

func TestVersionedGroup_DELETE(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	registry := NewRouteVersionRegistry()
	vg := NewVersionedGroup(router.Group("/api/v1"), registry, "v1")

	handler := func(c *gin.Context) { c.Status(http.StatusOK) }
	vg.DELETE("/domains/:id", handler)

	exists, supported := registry.Lookup("DELETE", "/domains/test.net", "v1")
	assert.True(t, exists)
	assert.True(t, supported)
}

func TestVersionedGroup_PATCH(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	registry := NewRouteVersionRegistry()
	vg := NewVersionedGroup(router.Group("/api/v1"), registry, "v1")

	handler := func(c *gin.Context) { c.Status(http.StatusOK) }
	vg.PATCH("/domains/:id", handler)

	exists, supported := registry.Lookup("PATCH", "/domains/test.net", "v1")
	assert.True(t, exists)
	assert.True(t, supported)
}

func TestVersionedGroup_MultipleVersions(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	registry := NewRouteVersionRegistry()

	handler := func(c *gin.Context) { c.Status(http.StatusOK) }

	v1 := NewVersionedGroup(router.Group("/api/v1"), registry, "v1")
	v1.POST("/domains", handler)
	v1.GET("/domains", handler)

	v2 := NewVersionedGroup(router.Group("/api/v2"), registry, "v2")
	v2.POST("/domains", handler)

	// POST has v1 + v2
	exists, supported := registry.Lookup("POST", "/domains", "v1")
	assert.True(t, exists)
	assert.True(t, supported)

	exists, supported = registry.Lookup("POST", "/domains", "v2")
	assert.True(t, exists)
	assert.True(t, supported)

	// GET has only v1
	exists, supported = registry.Lookup("GET", "/domains", "v1")
	assert.True(t, exists)
	assert.True(t, supported)

	exists, supported = registry.Lookup("GET", "/domains", "v2")
	assert.True(t, exists, "endpoint exists for GET /domains")
	assert.False(t, supported, "v2 not registered for GET /domains")
}

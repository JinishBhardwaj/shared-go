package versioning

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// setupTestRouter creates a test router with the middleware and a single route.
// Registers the route pattern for both v1 and v2 in the registry.
func setupTestRouter(relativePath string) *gin.Engine {
	router := gin.New()
	registry := NewRouteVersionRegistry()
	router.Use(Middleware(router, registry))

	router.GET(relativePath, func(c *gin.Context) {
		c.String(http.StatusOK, "")
	})

	// Strip any /api/vN prefix to get the base pattern for registration.
	pattern := relativePath
	if strings.HasPrefix(pattern, "/api/v") {
		rest := strings.TrimPrefix(pattern, "/api/")
		if parts := strings.SplitN(rest, "/", 2); len(parts) == 2 {
			pattern = "/" + parts[1]
		}
	}
	registry.Register("GET", pattern, "v1")
	registry.Register("GET", pattern, "v2")

	return router
}

func TestMiddleware_Ignore_DefaultRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	req, _ := http.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	router := setupTestRouter("/")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMiddleware_Ignore_SwaggerRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	req, _ := http.NewRequest("GET", "/swagger/index.html", nil)
	w := httptest.NewRecorder()
	router := setupTestRouter("/swagger/index.html")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMiddleware_Ignore_HealthRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	req, _ := http.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	router := setupTestRouter("/health")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMiddleware_Return_400_When_NoVersionHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	req, _ := http.NewRequest("GET", "/api/resource", nil)
	w := httptest.NewRecorder()
	router := setupTestRouter("/api/resource")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assertProblemDetail(t, w, "Missing API version")
}

func TestMiddleware_DefaultVersion_When_EmptyHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	req, _ := http.NewRequest("GET", "/api/resource", nil)
	req.Header.Set(DefaultVersionHeaderName, "")
	w := httptest.NewRecorder()
	router := setupTestRouter(fmt.Sprintf("/api/%s/resource", DefaultVersionValue))
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, DefaultVersionValue, w.Header().Get(DefaultVersionHeaderName))
}

func TestMiddleware_Return_400_When_InvalidVersion(t *testing.T) {
	gin.SetMode(gin.TestMode)
	req, _ := http.NewRequest("GET", "/api/resource", nil)
	req.Header.Set(DefaultVersionHeaderName, "invalid-version")
	w := httptest.NewRecorder()
	router := setupTestRouter("/api/resource")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assertProblemDetail(t, w, "Invalid API version format")
}

func TestMiddleware_ValidV1(t *testing.T) {
	gin.SetMode(gin.TestMode)
	req, _ := http.NewRequest("GET", "/api/resource", nil)
	req.Header.Set(DefaultVersionHeaderName, "v1")
	w := httptest.NewRecorder()
	router := setupTestRouter("/api/v1/resource")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "v1", w.Header().Get(DefaultVersionHeaderName))
}

func TestMiddleware_ValidV2(t *testing.T) {
	gin.SetMode(gin.TestMode)
	req, _ := http.NewRequest("GET", "/api/resource", nil)
	req.Header.Set(DefaultVersionHeaderName, "v2")
	w := httptest.NewRecorder()
	router := setupTestRouter("/api/v2/resource")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "v2", w.Header().Get(DefaultVersionHeaderName))
}

func TestMiddleware_UnsupportedVersion(t *testing.T) {
	gin.SetMode(gin.TestMode)
	req, _ := http.NewRequest("GET", "/api/resource", nil)
	req.Header.Set(DefaultVersionHeaderName, "v3")
	w := httptest.NewRecorder()
	router := setupTestRouter("/api/v3/resource")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assertProblemDetail(t, w, "Unsupported API version")
}

// --- Per-endpoint versioning tests ---

func TestMiddleware_PerEndpoint_UnsupportedVersionForEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	registry := NewRouteVersionRegistry()
	router.Use(Middleware(router, registry))

	v1Routes := NewVersionedGroup(router.Group("/api/v1"), registry, "v1")
	v1Routes.GET("/resource", func(c *gin.Context) {
		c.String(http.StatusOK, "v1")
	})

	req, _ := http.NewRequest("GET", "/api/resource", nil)
	req.Header.Set(DefaultVersionHeaderName, "v2")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assertProblemDetail(t, w, "Unsupported API version")
}

func TestMiddleware_PerEndpoint_SupportedV2(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	registry := NewRouteVersionRegistry()
	router.Use(Middleware(router, registry))

	v1Routes := NewVersionedGroup(router.Group("/api/v1"), registry, "v1")
	v1Routes.POST("/resource", func(c *gin.Context) { c.String(http.StatusOK, "v1") })

	v2Routes := NewVersionedGroup(router.Group("/api/v2"), registry, "v2")
	v2Routes.POST("/resource", func(c *gin.Context) { c.String(http.StatusOK, "v2") })

	req, _ := http.NewRequest("POST", "/api/resource", nil)
	req.Header.Set(DefaultVersionHeaderName, "v2")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMiddleware_PerEndpoint_NonExistentEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	registry := NewRouteVersionRegistry()
	router.Use(Middleware(router, registry))

	v1Routes := NewVersionedGroup(router.Group("/api/v1"), registry, "v1")
	v1Routes.GET("/resource", func(c *gin.Context) { c.String(http.StatusOK, "v1") })

	req, _ := http.NewRequest("GET", "/api/nonexistent", nil)
	req.Header.Set(DefaultVersionHeaderName, "v1")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestMiddleware_PerEndpoint_MixedVersions(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	registry := NewRouteVersionRegistry()
	router.Use(Middleware(router, registry))

	v1Routes := NewVersionedGroup(router.Group("/api/v1"), registry, "v1")
	v1Routes.POST("/domains", func(c *gin.Context) { c.String(http.StatusCreated, "created-v1") })
	v1Routes.GET("/domains", func(c *gin.Context) { c.String(http.StatusOK, "list-v1") })

	v2Routes := NewVersionedGroup(router.Group("/api/v2"), registry, "v2")
	v2Routes.POST("/domains", func(c *gin.Context) { c.String(http.StatusCreated, "created-v2") })

	// POST with v2 → should work
	req, _ := http.NewRequest("POST", "/api/domains", nil)
	req.Header.Set(DefaultVersionHeaderName, "v2")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	// GET with v2 → should return 400 (GET has no v2)
	req, _ = http.NewRequest("GET", "/api/domains", nil)
	req.Header.Set(DefaultVersionHeaderName, "v2")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// GET with v1 → should work
	req, _ = http.NewRequest("GET", "/api/domains", nil)
	req.Header.Set(DefaultVersionHeaderName, "v1")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMiddleware_NilRegistry_BackwardCompat(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(Middleware(router, nil))

	router.GET("/api/v1/resource", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	req, _ := http.NewRequest("GET", "/api/resource", nil)
	req.Header.Set(DefaultVersionHeaderName, "v1")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMiddleware_ReportApiVersions(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	registry := NewRouteVersionRegistry()
	cfg := DefaultConfig()
	cfg.ReportApiVersions = true
	router.Use(Middleware(router, registry, cfg))

	v1Routes := NewVersionedGroup(router.Group("/api/v1"), registry, "v1")
	v1Routes.POST("/domains", func(c *gin.Context) { c.String(http.StatusCreated, "ok") })

	v2Routes := NewVersionedGroup(router.Group("/api/v2"), registry, "v2")
	v2Routes.POST("/domains", func(c *gin.Context) { c.String(http.StatusCreated, "ok") })

	req, _ := http.NewRequest("POST", "/api/domains", nil)
	req.Header.Set(DefaultVersionHeaderName, "v1")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "v1, v2", w.Header().Get("api-supported-versions"))
}

func TestMiddleware_AssumeDefaultWhenUnspecified(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	registry := NewRouteVersionRegistry()
	cfg := DefaultConfig()
	cfg.AssumeDefaultVersionWhenUnspecified = true
	router.Use(Middleware(router, registry, cfg))

	v1Routes := NewVersionedGroup(router.Group("/api/v1"), registry, "v1")
	v1Routes.GET("/resource", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	req, _ := http.NewRequest("GET", "/api/resource", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "v1", w.Header().Get(DefaultVersionHeaderName))
}

func TestMiddleware_ProblemDetailsFormat(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	registry := NewRouteVersionRegistry()
	router.Use(Middleware(router, registry))

	v1Routes := NewVersionedGroup(router.Group("/api/v1"), registry, "v1")
	v1Routes.GET("/resource", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	req, _ := http.NewRequest("GET", "/api/resource", nil)
	req.Header.Set(DefaultVersionHeaderName, "v2")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/problem+json")

	body, _ := io.ReadAll(w.Body)
	var pd map[string]interface{}
	err := json.Unmarshal(body, &pd)
	assert.NoError(t, err)
	assert.Equal(t, "Bad Request", pd["title"])
	assert.Equal(t, float64(400), pd["status"])
	assert.Equal(t, "Unsupported API version", pd["detail"])
	assert.Equal(t, "/api/resource", pd["instance"])
}

func TestMiddleware_NilReaderDefaultsToHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	registry := NewRouteVersionRegistry()
	cfg := Config{
		DefaultVersion: "v1",
		VersionFormat:  DefaultVersionFormat,
		Reader:         nil, // should default to header strategy
	}
	router.Use(Middleware(router, registry, cfg))

	v1Routes := NewVersionedGroup(router.Group("/api/v1"), registry, "v1")
	v1Routes.GET("/resource", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	req, _ := http.NewRequest("GET", "/api/resource", nil)
	req.Header.Set(DefaultVersionHeaderName, "v1")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMiddleware_NonApiPath_SkipsVersioning(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	registry := NewRouteVersionRegistry()
	router.Use(Middleware(router, registry))

	router.GET("/metrics", func(c *gin.Context) { c.String(http.StatusOK, "metrics") })

	// No version header — should not get 400 since /metrics is not under /api
	req, _ := http.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMiddleware_AlreadyVersionedURL_RegistryCheck(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	registry := NewRouteVersionRegistry()
	router.Use(Middleware(router, registry))

	v1Routes := NewVersionedGroup(router.Group("/api/v1"), registry, "v1")
	v1Routes.GET("/resource", func(c *gin.Context) { c.String(http.StatusOK, "v1") })

	// Client sends already-versioned URL /api/v1/resource with x-version: v1
	req, _ := http.NewRequest("GET", "/api/v1/resource", nil)
	req.Header.Set(DefaultVersionHeaderName, "v1")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// assertProblemDetail checks that the response body contains the expected detail message.
func assertProblemDetail(t *testing.T, w *httptest.ResponseRecorder, expectedDetail string) {
	t.Helper()
	body, _ := io.ReadAll(w.Body)
	var pd map[string]interface{}
	if err := json.Unmarshal(body, &pd); err == nil {
		assert.Equal(t, expectedDetail, pd["detail"])
	}
}

package versioning

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRouteVersionRegistry_RegisterAndLookup(t *testing.T) {
	r := NewRouteVersionRegistry()
	r.Register("POST", "/domains", "v1")
	r.Register("POST", "/domains", "v2")
	r.Register("GET", "/domains/:id_or_name", "v1")

	exists, supported := r.Lookup("POST", "/domains", "v1")
	assert.True(t, exists)
	assert.True(t, supported)

	exists, supported = r.Lookup("POST", "/domains", "v2")
	assert.True(t, exists)
	assert.True(t, supported)

	exists, supported = r.Lookup("GET", "/domains/test.net", "v1")
	assert.True(t, exists)
	assert.True(t, supported)
}

func TestRouteVersionRegistry_UnsupportedVersion(t *testing.T) {
	r := NewRouteVersionRegistry()
	r.Register("GET", "/domains/:id_or_name", "v1")

	exists, supported := r.Lookup("GET", "/domains/test.net", "v2")
	assert.True(t, exists, "endpoint should exist")
	assert.False(t, supported, "v2 should not be supported")
}

func TestRouteVersionRegistry_NonExistentEndpoint(t *testing.T) {
	r := NewRouteVersionRegistry()
	r.Register("GET", "/domains/:id_or_name", "v1")

	exists, supported := r.Lookup("GET", "/contacts/123", "v1")
	assert.False(t, exists)
	assert.False(t, supported)
}

func TestRouteVersionRegistry_MethodMismatch(t *testing.T) {
	r := NewRouteVersionRegistry()
	r.Register("POST", "/domains", "v1")

	exists, supported := r.Lookup("GET", "/domains", "v1")
	assert.False(t, exists)
	assert.False(t, supported)
}

func TestRouteVersionRegistry_SupportedVersions(t *testing.T) {
	r := NewRouteVersionRegistry()
	r.Register("POST", "/domains", "v1")
	r.Register("POST", "/domains", "v2")

	versions := r.SupportedVersions("POST", "/domains")
	assert.Equal(t, []string{"v1", "v2"}, versions)
}

func TestRouteVersionRegistry_SupportedVersions_NoMatch(t *testing.T) {
	r := NewRouteVersionRegistry()
	versions := r.SupportedVersions("GET", "/nonexistent")
	assert.Nil(t, versions)
}

func TestRouteVersionRegistry_PrefersLiteralOverParam(t *testing.T) {
	r := NewRouteVersionRegistry()
	r.Register("POST", "/domains/search", "v1")
	r.Register("POST", "/domains/search", "v2")
	r.Register("POST", "/domains/:id_or_name", "v1")

	exists, supported := r.Lookup("POST", "/domains/search", "v2")
	assert.True(t, exists)
	assert.True(t, supported)
}

func TestRouteVersionRegistry_CaseInsensitiveMethod(t *testing.T) {
	r := NewRouteVersionRegistry()
	r.Register("post", "/domains", "v1")

	exists, supported := r.Lookup("POST", "/domains", "v1")
	assert.True(t, exists)
	assert.True(t, supported)
}

func TestRouteVersionRegistry_ConcurrentAccess(t *testing.T) {
	r := NewRouteVersionRegistry()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Register("GET", "/domains", "v1")
			r.Lookup("GET", "/domains", "v1")
			r.SupportedVersions("GET", "/domains")
		}()
	}
	wg.Wait()

	exists, supported := r.Lookup("GET", "/domains", "v1")
	assert.True(t, exists)
	assert.True(t, supported)
}

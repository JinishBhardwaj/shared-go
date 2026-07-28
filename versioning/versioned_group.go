package versioning

import "github.com/gin-gonic/gin"

// VersionedGroup wraps a gin.RouterGroup and records each route registration
// into a RouteVersionRegistry. This enables per-endpoint version tracking
// without changing the route registration pattern.
//
// Usage:
//
//	v1Group := apiGroup.Group("v1")
//	v1Routes := versioning.NewVersionedGroup(v1Group, registry, "v1")
//	v1Routes.POST("/domains", api.CreateDomainHandler)
type VersionedGroup struct {
	*gin.RouterGroup
	registry *RouteVersionRegistry
	version  string
}

// NewVersionedGroup creates a versioned wrapper around a gin route group.
// All route registrations (GET, POST, PUT, DELETE, PATCH) will be recorded
// in the registry with the given version.
// Panics if registry is nil — use a bare gin.RouterGroup if you don't need version tracking.
func NewVersionedGroup(group *gin.RouterGroup, registry *RouteVersionRegistry, version string) *VersionedGroup {
	if registry == nil {
		panic("versioning: NewVersionedGroup requires a non-nil RouteVersionRegistry")
	}
	return &VersionedGroup{
		RouterGroup: group,
		registry:    registry,
		version:     version,
	}
}

// POST registers a POST handler and records it in the version registry.
func (vg *VersionedGroup) POST(relativePath string, handlers ...gin.HandlerFunc) gin.IRoutes {
	vg.registry.Register("POST", relativePath, vg.version)
	return vg.RouterGroup.POST(relativePath, handlers...)
}

// GET registers a GET handler and records it in the version registry.
func (vg *VersionedGroup) GET(relativePath string, handlers ...gin.HandlerFunc) gin.IRoutes {
	vg.registry.Register("GET", relativePath, vg.version)
	return vg.RouterGroup.GET(relativePath, handlers...)
}

// PUT registers a PUT handler and records it in the version registry.
func (vg *VersionedGroup) PUT(relativePath string, handlers ...gin.HandlerFunc) gin.IRoutes {
	vg.registry.Register("PUT", relativePath, vg.version)
	return vg.RouterGroup.PUT(relativePath, handlers...)
}

// DELETE registers a DELETE handler and records it in the version registry.
func (vg *VersionedGroup) DELETE(relativePath string, handlers ...gin.HandlerFunc) gin.IRoutes {
	vg.registry.Register("DELETE", relativePath, vg.version)
	return vg.RouterGroup.DELETE(relativePath, handlers...)
}

// PATCH registers a PATCH handler and records it in the version registry.
func (vg *VersionedGroup) PATCH(relativePath string, handlers ...gin.HandlerFunc) gin.IRoutes {
	vg.registry.Register("PATCH", relativePath, vg.version)
	return vg.RouterGroup.PATCH(relativePath, handlers...)
}

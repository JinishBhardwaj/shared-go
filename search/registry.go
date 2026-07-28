package search

import (
	"fmt"
	"sync"
)

// Registry maps a resource name to its ResourceConfig. It is safe for
// concurrent use: register resources at startup, then read them per request.
type Registry struct {
	mu      sync.RWMutex
	configs map[string]*ResourceConfig
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{configs: make(map[string]*ResourceConfig)}
}

// Register adds a resource config under cfg.Name. It panics on a duplicate or
// empty name — these are startup misconfigurations that should fail loudly.
func (r *Registry) Register(cfg *ResourceConfig) {
	if cfg == nil || cfg.Name == "" {
		panic("search: Register requires a non-nil config with a non-empty Name")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.configs[cfg.Name]; exists {
		panic(fmt.Sprintf("search: resource %q already registered", cfg.Name))
	}
	r.configs[cfg.Name] = cfg
}

// Get returns the config for a resource, or *UnknownResourceError if absent.
func (r *Registry) Get(name string) (*ResourceConfig, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cfg, ok := r.configs[name]
	if !ok {
		return nil, &UnknownResourceError{Resource: name}
	}
	return cfg, nil
}

// Names returns the registered resource names (unordered).
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.configs))
	for n := range r.configs {
		names = append(names, n)
	}
	return names
}

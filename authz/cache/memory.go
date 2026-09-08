package cache

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dgraph-io/ristretto"
)

// MemoryCacheConfig configures the high-RPS in-memory cache.
type MemoryCacheConfig struct {
	// NumCounters is the number of 4-bit counters to track frequency of (recommend 10x MaxCost in items).
	// Default: 1,000,000 (tracks ~100k active keys).
	NumCounters int64

	// MaxCost is the upper memory bound in bytes.
	// Default: 128MB (128 << 20).
	MaxCost int64

	// BufferItems is the number of keys per Get buffer.
	// Default: 64.
	BufferItems int64
}

// DefaultMemoryCacheConfig returns production-ready high-RPS defaults.
func DefaultMemoryCacheConfig() MemoryCacheConfig {
	return MemoryCacheConfig{
		NumCounters: 1_000_000,
		MaxCost:     128 << 20, // 128 MB
		BufferItems: 64,
	}
}

// MemoryCacheProvider provides a concurrent, lock-free, memory-bounded in-memory cache
// powered by github.com/dgraph-io/ristretto (Sampled TinyLFU admission & eviction).
// Capable of tens of millions of operations per second with zero lock contention.
type MemoryCacheProvider struct {
	cache       *ristretto.Cache
	subMu       sync.Mutex
	subscribers map[chan string]struct{}
	closeOnce   sync.Once
}

// NewMemoryCacheProvider initializes a MemoryCacheProvider powered by Ristretto.
// If no config is passed, DefaultMemoryCacheConfig() is used.
func NewMemoryCacheProvider(cfg ...MemoryCacheConfig) (*MemoryCacheProvider, error) {
	c := DefaultMemoryCacheConfig()
	if len(cfg) > 0 {
		if cfg[0].NumCounters > 0 {
			c.NumCounters = cfg[0].NumCounters
		}
		if cfg[0].MaxCost > 0 {
			c.MaxCost = cfg[0].MaxCost
		}
		if cfg[0].BufferItems > 0 {
			c.BufferItems = cfg[0].BufferItems
		}
	}

	rCache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: c.NumCounters,
		MaxCost:     c.MaxCost,
		BufferItems: c.BufferItems,
	})
	if err != nil {
		return nil, fmt.Errorf("cache: failed initializing memory cache: %w", err)
	}

	return &MemoryCacheProvider{
		cache:       rCache,
		subscribers: make(map[chan string]struct{}),
	}, nil
}

// Get retrieves cached bytes for a key in tens of nanoseconds.
func (m *MemoryCacheProvider) Get(ctx context.Context, key string) ([]byte, error) {
	if key == "" {
		return nil, ErrInvalidKey
	}

	val, found := m.cache.Get(key)
	if !found {
		return nil, ErrCacheMiss
	}

	bytes, ok := val.([]byte)
	if !ok {
		return nil, ErrCacheMiss
	}

	// Return a copy to ensure immutability
	out := make([]byte, len(bytes))
	copy(out, bytes)
	return out, nil
}

// Set stores a byte slice with cost (byte length) and TTL.
func (m *MemoryCacheProvider) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if key == "" {
		return ErrInvalidKey
	}

	cost := int64(len(value))
	if cost == 0 {
		cost = 1
	}

	valCopy := make([]byte, len(value))
	copy(valCopy, value)

	if ttl > 0 {
		m.cache.SetWithTTL(key, valCopy, cost, ttl)
	} else {
		m.cache.Set(key, valCopy, cost)
	}

	return nil
}

// Delete removes a key from the cache.
func (m *MemoryCacheProvider) Delete(ctx context.Context, key string) error {
	if key == "" {
		return ErrInvalidKey
	}
	m.cache.Del(key)
	return nil
}

// Close gracefully closes the underlying cache and cleans up subscriber channels.
func (m *MemoryCacheProvider) Close() error {
	m.closeOnce.Do(func() {
		m.cache.Close()

		m.subMu.Lock()
		defer m.subMu.Unlock()
		for ch := range m.subscribers {
			close(ch)
			delete(m.subscribers, ch)
		}
	})
	return nil
}

// PublishRevocation broadcasts a principal ID to all active in-memory subscribers.
func (m *MemoryCacheProvider) PublishRevocation(ctx context.Context, principalID string) error {
	m.subMu.Lock()
	defer m.subMu.Unlock()

	for ch := range m.subscribers {
		select {
		case ch <- principalID:
		default:
		}
	}
	return nil
}

// SubscribeRevocations returns a channel delivering revocation events.
func (m *MemoryCacheProvider) SubscribeRevocations(ctx context.Context) (<-chan string, error) {
	ch := make(chan string, 100)

	m.subMu.Lock()
	m.subscribers[ch] = struct{}{}
	m.subMu.Unlock()

	go func() {
		<-ctx.Done()
		m.subMu.Lock()
		if _, exists := m.subscribers[ch]; exists {
			delete(m.subscribers, ch)
			close(ch)
		}
		m.subMu.Unlock()
	}()

	return ch, nil
}

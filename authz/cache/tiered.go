package cache

import (
	"context"
	"errors"
	"sync"
	"time"
)

// TieredCacheConfig configures the two-tier L1 memory + L2 distributed cache.
type TieredCacheConfig struct {
	// L1 is the ultra-low latency in-memory cache.
	L1 CacheProvider

	// L2 is the distributed cache (e.g. Redis).
	L2 CacheProvider

	// InvalidationBus receives instant revocation broadcasts.
	// If nil and L2 implements InvalidationBus, L2 will be used as the bus.
	InvalidationBus InvalidationBus

	// L1TTL is the duration items remain in L1 memory before re-syncing with L2.
	// Defaults to 60 seconds (accommodating the 60s grant propagation window).
	L1TTL time.Duration

	// KeyFormatter maps a revoked principal ID to the cache key format (e.g., "perm:" + principalID).
	// If nil, defaults to "perm:" + principalID.
	KeyFormatter func(principalID string) string
}

// TieredCacheProvider implements the Composite Pattern: L1 in-memory + L2 distributed cache.
// Achieves tens-of-nanoseconds read times for 10k+ RPS, with instant distributed revocation.
type TieredCacheProvider struct {
	l1           CacheProvider
	l2           CacheProvider
	bus          InvalidationBus
	l1TTL        time.Duration
	keyFormatter func(principalID string) string

	cancelListen context.CancelFunc
	wg           sync.WaitGroup
	closeOnce    sync.Once
}

// NewTieredCacheProvider creates an initialized two-tier cache provider.
func NewTieredCacheProvider(cfg TieredCacheConfig) (*TieredCacheProvider, error) {
	if cfg.L1 == nil {
		return nil, errors.New("cache: L1 cache provider cannot be nil")
	}
	if cfg.L2 == nil {
		return nil, errors.New("cache: L2 cache provider cannot be nil")
	}
	if cfg.L1TTL <= 0 {
		cfg.L1TTL = 60 * time.Second
	}
	if cfg.KeyFormatter == nil {
		cfg.KeyFormatter = func(principalID string) string {
			return "perm:" + principalID
		}
	}

	bus := cfg.InvalidationBus
	if bus == nil {
		if b, ok := cfg.L2.(InvalidationBus); ok {
			bus = b
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	t := &TieredCacheProvider{
		l1:           cfg.L1,
		l2:           cfg.L2,
		bus:          bus,
		l1TTL:        cfg.L1TTL,
		keyFormatter: cfg.KeyFormatter,
		cancelListen: cancel,
	}

	if t.bus != nil {
		if err := t.startRevocationListener(ctx); err != nil {
			cancel()
			return nil, err
		}
	}

	return t, nil
}

func (t *TieredCacheProvider) startRevocationListener(ctx context.Context) error {
	ch, err := t.bus.SubscribeRevocations(ctx)
	if err != nil {
		return err
	}

	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case principalID, ok := <-ch:
				if !ok {
					return
				}
				// Evict instantly from L1 memory!
				targetKey := t.keyFormatter(principalID)
				_ = t.l1.Delete(ctx, targetKey)
			}
		}
	}()

	return nil
}

// Get checks L1 memory first (< 50 ns). If missed, checks L2 Redis (< 1 ms).
// On an L2 hit, populates L1 with L1TTL (e.g. 60s).
func (t *TieredCacheProvider) Get(ctx context.Context, key string) ([]byte, error) {
	// 1. Fast-path: L1 in-memory check
	val, err := t.l1.Get(ctx, key)
	if err == nil {
		return val, nil
	}

	// 2. Fallback: L2 distributed check
	val, err = t.l2.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	// 3. Populate L1 with grant propagation TTL
	_ = t.l1.Set(ctx, key, val, t.l1TTL)
	return val, nil
}

// Set stores in both L1 and L2.
func (t *TieredCacheProvider) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	l1TTL := t.l1TTL
	if ttl > 0 && ttl < l1TTL {
		l1TTL = ttl
	}

	_ = t.l1.Set(ctx, key, value, l1TTL)
	return t.l2.Set(ctx, key, value, ttl)
}

// Delete removes from both L1 and L2.
func (t *TieredCacheProvider) Delete(ctx context.Context, key string) error {
	_ = t.l1.Delete(ctx, key)
	return t.l2.Delete(ctx, key)
}

// PublishRevocation broadcasts a revocation signal via the invalidation bus and evicts from local L1.
func (t *TieredCacheProvider) PublishRevocation(ctx context.Context, principalID string) error {
	targetKey := t.keyFormatter(principalID)
	_ = t.l1.Delete(ctx, targetKey)
	_ = t.l2.Delete(ctx, targetKey)

	if t.bus != nil {
		return t.bus.PublishRevocation(ctx, principalID)
	}
	return nil
}

// Close gracefully shuts down the invalidation subscriber and closes underlying caches.
func (t *TieredCacheProvider) Close() error {
	var err error
	t.closeOnce.Do(func() {
		t.cancelListen()
		t.wg.Wait()

		err1 := t.l1.Close()
		err2 := t.l2.Close()
		if err1 != nil {
			err = err1
		} else {
			err = err2
		}
	})
	return err
}

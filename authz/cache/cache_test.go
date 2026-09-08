package cache

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryCacheProvider_Basic(t *testing.T) {
	ctx := context.Background()
	c, err := NewMemoryCacheProvider()
	if err != nil {
		t.Fatalf("failed to create MemoryCacheProvider: %v", err)
	}
	defer c.Close()

	// 1. Get non-existent
	_, err = c.Get(ctx, "nonexistent")
	if !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("expected ErrCacheMiss, got %v", err)
	}

	// 2. Set and Get
	key := "user:123"
	val := []byte("permissions-data")
	if err := c.Set(ctx, key, val, 1*time.Minute); err != nil {
		t.Fatalf("failed to set: %v", err)
	}

	// Allow Ristretto ring buffer to drain
	time.Sleep(50 * time.Millisecond)

	got, err := c.Get(ctx, key)
	if err != nil {
		t.Fatalf("expected hit, got err: %v", err)
	}
	if string(got) != string(val) {
		t.Fatalf("expected %s, got %s", val, got)
	}

	// 3. Delete
	if err := c.Delete(ctx, key); err != nil {
		t.Fatalf("failed to delete: %v", err)
	}

	time.Sleep(20 * time.Millisecond)

	_, err = c.Get(ctx, key)
	if !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("expected ErrCacheMiss after delete, got %v", err)
	}
}

func TestMemoryCacheProvider_TTL(t *testing.T) {
	ctx := context.Background()
	c, err := NewMemoryCacheProvider()
	if err != nil {
		t.Fatalf("failed to create MemoryCacheProvider: %v", err)
	}
	defer c.Close()

	key := "short-lived"
	val := []byte("temp")
	if err := c.Set(ctx, key, val, 60*time.Millisecond); err != nil {
		t.Fatalf("set failed: %v", err)
	}

	time.Sleep(20 * time.Millisecond)

	// Before expiry
	got, err := c.Get(ctx, key)
	if err != nil || string(got) != "temp" {
		t.Fatalf("expected item before expiry, got %v", err)
	}

	// Wait for expiry
	time.Sleep(120 * time.Millisecond)

	_, err = c.Get(ctx, key)
	if !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("expected ErrCacheMiss after expiry, got %v", err)
	}
}

func TestTieredCacheProvider_L1L2AndInstantRevocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	l1, err := NewMemoryCacheProvider()
	if err != nil {
		t.Fatalf("failed to create L1 MemoryCacheProvider: %v", err)
	}
	defer l1.Close()

	l2, err := NewMemoryCacheProvider()
	if err != nil {
		t.Fatalf("failed to create L2 MemoryCacheProvider: %v", err)
	}
	defer l2.Close()

	tiered, err := NewTieredCacheProvider(TieredCacheConfig{
		L1:              l1,
		L2:              l2,
		InvalidationBus: l2,
		L1TTL:           60 * time.Second,
		KeyFormatter: func(principalID string) string {
			return "perm:" + principalID
		},
	})
	if err != nil {
		t.Fatalf("failed to create TieredCacheProvider: %v", err)
	}
	defer tiered.Close()

	principalID := "user_999"
	permKey := "perm:" + principalID
	permVal := []byte(`{"roles":["editor"],"actions":["read","write"]}`)

	// 1. Prime L2 only (simulating grant saved in database/L2)
	if err := l2.Set(ctx, permKey, permVal, 10*time.Minute); err != nil {
		t.Fatalf("failed to set L2: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	// Verify L1 is currently empty
	if _, err := l1.Get(ctx, permKey); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("expected L1 to be empty initially")
	}

	// 2. Read from Tiered -> should fetch from L2 and populate L1
	got, err := tiered.Get(ctx, permKey)
	if err != nil {
		t.Fatalf("expected hit on Tiered.Get: %v", err)
	}
	if string(got) != string(permVal) {
		t.Fatalf("expected %s, got %s", permVal, got)
	}

	time.Sleep(50 * time.Millisecond)

	// Verify L1 now contains the value!
	gotL1, err := l1.Get(ctx, permKey)
	if err != nil || string(gotL1) != string(permVal) {
		t.Fatalf("expected L1 to be populated after Tiered.Get")
	}

	// 3. Instant Revocation test:
	// When permission is revoked, publish revocation
	if err := tiered.PublishRevocation(ctx, principalID); err != nil {
		t.Fatalf("failed to publish revocation: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// L1 must be evicted immediately!
	_, err = l1.Get(ctx, permKey)
	if !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("expected L1 to be evicted instantly upon revocation, but found it present")
	}

	// L2 must also be removed
	_, err = l2.Get(ctx, permKey)
	if !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("expected L2 to be evicted after revocation, but found it present")
	}
}

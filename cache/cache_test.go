package cache_test

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/JinishBhardwaj/shared-go/cache"
	"github.com/JinishBhardwaj/shared-go/cache/memory"
	"github.com/JinishBhardwaj/shared-go/cache/rediscache"
)

// TestPerson is a small struct for testing JSON round-tripping with redis.
type TestPerson struct {
	Name string
	Age  int
}

// testCases defines behavioral test cases that should work identically
// on both cache implementations. Each test case is a function that
// exercises the cache through the cache.Cache[T] interface.
type testCase[T any] struct {
	name string
	test func(t *testing.T, c cache.Cache[T])
}

// sharedStringCases are the behavioral cases for string values.
func sharedStringCases() []testCase[string] {
	return []testCase[string]{
		{
			name: "Set then Get returns value",
			test: func(t *testing.T, c cache.Cache[string]) {
				err := c.Set(context.Background(), "key1", "value1", 0)
				require.NoError(t, err)

				val, found, err := c.Get(context.Background(), "key1")
				assert.NoError(t, err)
				assert.True(t, found)
				assert.Equal(t, "value1", val)
			},
		},
		{
			name: "Get on never-set key returns zero, found false, nil error",
			test: func(t *testing.T, c cache.Cache[string]) {
				val, found, err := c.Get(context.Background(), "nonexistent")
				assert.NoError(t, err, "a miss must not be an error")
				assert.False(t, found)
				assert.Equal(t, "", val)
			},
		},
		{
			name: "Set twice on same key - second value wins",
			test: func(t *testing.T, c cache.Cache[string]) {
				err := c.Set(context.Background(), "key2", "first", 0)
				require.NoError(t, err)
				err = c.Set(context.Background(), "key2", "second", 0)
				require.NoError(t, err)

				val, found, err := c.Get(context.Background(), "key2")
				assert.NoError(t, err)
				assert.True(t, found)
				assert.Equal(t, "second", val)
			},
		},
		{
			name: "Delete then Get returns miss",
			test: func(t *testing.T, c cache.Cache[string]) {
				err := c.Set(context.Background(), "key3", "value3", 0)
				require.NoError(t, err)

				err = c.Delete(context.Background(), "key3")
				require.NoError(t, err)

				val, found, err := c.Get(context.Background(), "key3")
				assert.NoError(t, err)
				assert.False(t, found)
				assert.Equal(t, "", val)
			},
		},
		{
			name: "Delete on never-set key returns nil",
			test: func(t *testing.T, c cache.Cache[string]) {
				err := c.Delete(context.Background(), "never-set")
				assert.NoError(t, err)
			},
		},
		{
			name: "Expiration zero means never expires",
			test: func(t *testing.T, c cache.Cache[string]) {
				err := c.Set(context.Background(), "key4", "value4", 0)
				require.NoError(t, err)

				val, found, err := c.Get(context.Background(), "key4")
				assert.NoError(t, err)
				assert.True(t, found)
				assert.Equal(t, "value4", val)
			},
		},
		{
			name: "Expiration negative means never expires",
			test: func(t *testing.T, c cache.Cache[string]) {
				err := c.Set(context.Background(), "key5", "value5", -1*time.Hour)
				require.NoError(t, err)

				val, found, err := c.Get(context.Background(), "key5")
				assert.NoError(t, err)
				assert.True(t, found)
				assert.Equal(t, "value5", val)
			},
		},
		{
			name: "Dispose called twice does not panic",
			test: func(t *testing.T, c cache.Cache[string]) {
				c.Dispose()
				c.Dispose() // Should not panic
			},
		},
	}
}

// sharedBoolCases tests with bool type to ensure the bool return value
// is genuinely used for miss detection, not relying on the zero value.
func sharedBoolCases() []testCase[bool] {
	return []testCase[bool]{
		{
			name: "Set false then Get returns false found true",
			test: func(t *testing.T, c cache.Cache[bool]) {
				err := c.Set(context.Background(), "bool-key", false, 0)
				require.NoError(t, err)

				val, found, err := c.Get(context.Background(), "bool-key")
				assert.NoError(t, err)
				assert.True(t, found, "should find the key")
				assert.False(t, val, "value should be false")
			},
		},
		{
			name: "Get missing bool key returns false found false nil error",
			test: func(t *testing.T, c cache.Cache[bool]) {
				val, found, err := c.Get(context.Background(), "missing-bool")
				assert.NoError(t, err, "a miss must not be an error")
				assert.False(t, found, "should not find the key")
				assert.False(t, val, "zero value for bool is false")
			},
		},
		{
			name: "Set true then Get returns true found true",
			test: func(t *testing.T, c cache.Cache[bool]) {
				err := c.Set(context.Background(), "bool-true", true, 0)
				require.NoError(t, err)

				val, found, err := c.Get(context.Background(), "bool-true")
				assert.NoError(t, err)
				assert.True(t, found)
				assert.True(t, val)
			},
		},
	}
}

// sharedStructCases tests with a struct type to exercise JSON round-tripping.
func sharedStructCases() []testCase[TestPerson] {
	return []testCase[TestPerson]{
		{
			name: "Set struct then Get returns struct",
			test: func(t *testing.T, c cache.Cache[TestPerson]) {
				person := TestPerson{Name: "Alice", Age: 30}
				err := c.Set(context.Background(), "person", person, 0)
				require.NoError(t, err)

				val, found, err := c.Get(context.Background(), "person")
				assert.NoError(t, err)
				assert.True(t, found)
				assert.Equal(t, person, val)
			},
		},
		{
			name: "Get missing struct returns zero struct found false nil error",
			test: func(t *testing.T, c cache.Cache[TestPerson]) {
				val, found, err := c.Get(context.Background(), "missing-person")
				assert.NoError(t, err, "a miss must not be an error")
				assert.False(t, found)
				assert.Equal(t, TestPerson{}, val)
			},
		},
		{
			name: "Set struct twice - second wins",
			test: func(t *testing.T, c cache.Cache[TestPerson]) {
				person1 := TestPerson{Name: "Alice", Age: 30}
				person2 := TestPerson{Name: "Bob", Age: 25}

				err := c.Set(context.Background(), "person2", person1, 0)
				require.NoError(t, err)
				err = c.Set(context.Background(), "person2", person2, 0)
				require.NoError(t, err)

				val, found, err := c.Get(context.Background(), "person2")
				assert.NoError(t, err)
				assert.True(t, found)
				assert.Equal(t, person2, val)
			},
		},
	}
}

// TestMemoryCacheString runs the shared string test cases against memory.Store.
func TestMemoryCacheString(t *testing.T) {
	for _, tc := range sharedStringCases() {
		t.Run(tc.name, func(t *testing.T) {
			c := memory.New[string](0)
			defer c.Dispose()
			tc.test(t, c)
		})
	}
}

// TestMemoryCacheBool runs the shared bool test cases against memory.Store.
func TestMemoryCacheBool(t *testing.T) {
	for _, tc := range sharedBoolCases() {
		t.Run(tc.name, func(t *testing.T) {
			c := memory.New[bool](0)
			defer c.Dispose()
			tc.test(t, c)
		})
	}
}

// TestMemoryCacheStruct runs the shared struct test cases against memory.Store.
func TestMemoryCacheStruct(t *testing.T) {
	for _, tc := range sharedStructCases() {
		t.Run(tc.name, func(t *testing.T) {
			c := memory.New[TestPerson](0)
			defer c.Dispose()
			tc.test(t, c)
		})
	}
}

// TestRedisCacheString runs the shared string test cases against rediscache.Store.
func TestRedisCacheString(t *testing.T) {
	for _, tc := range sharedStringCases() {
		t.Run(tc.name, func(t *testing.T) {
			mr := miniredis.RunT(t)
			client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
			defer func() { _ = client.Close() }()
			c := rediscache.New[string](client)
			defer c.Dispose()
			tc.test(t, c)
		})
	}
}

// TestRedisCacheBool runs the shared bool test cases against rediscache.Store.
func TestRedisCacheBool(t *testing.T) {
	for _, tc := range sharedBoolCases() {
		t.Run(tc.name, func(t *testing.T) {
			mr := miniredis.RunT(t)
			client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
			defer func() { _ = client.Close() }()
			c := rediscache.New[bool](client)
			defer c.Dispose()
			tc.test(t, c)
		})
	}
}

// TestRedisCacheStruct runs the shared struct test cases against rediscache.Store.
func TestRedisCacheStruct(t *testing.T) {
	for _, tc := range sharedStructCases() {
		t.Run(tc.name, func(t *testing.T) {
			mr := miniredis.RunT(t)
			client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
			defer func() { _ = client.Close() }()
			c := rediscache.New[TestPerson](client)
			defer c.Dispose()
			tc.test(t, c)
		})
	}
}

// TestMemoryShortExpiration verifies that short positive expirations expire.
func TestMemoryShortExpiration(t *testing.T) {
	c := memory.New[string](100 * time.Millisecond)
	defer c.Dispose()

	err := c.Set(context.Background(), "expiring", "value", 50*time.Millisecond)
	require.NoError(t, err)

	// Should be found immediately.
	val, found, err := c.Get(context.Background(), "expiring")
	assert.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "value", val)

	// Wait for expiration.
	time.Sleep(100 * time.Millisecond)

	// Should be gone.
	val, found, err = c.Get(context.Background(), "expiring")
	assert.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, "", val)
}

// TestRedisShortExpiration verifies that short positive expirations expire,
// using miniredis FastForward to avoid real sleep.
func TestRedisShortExpiration(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = client.Close() }()

	c := rediscache.New[string](client)
	defer c.Dispose()

	err := c.Set(context.Background(), "expiring", "value", 500*time.Millisecond)
	require.NoError(t, err)

	// Should be found immediately.
	val, found, err := c.Get(context.Background(), "expiring")
	assert.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "value", val)

	// Use FastForward to simulate time passage without sleeping.
	mr.FastForward(600 * time.Millisecond)

	// Should be gone.
	val, found, err = c.Get(context.Background(), "expiring")
	assert.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, "", val)
}

// TestMemoryConcurrency runs concurrent Set/Get/Delete operations against memory.Store.
func TestMemoryConcurrency(t *testing.T) {
	c := memory.New[string](0)
	defer c.Dispose()

	const numGoroutines = 50
	const opsPerGoroutine = 20
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				key := "key-" + string(rune(j%10))
				value := "value-" + string(rune(id))

				// Set
				err := c.Set(context.Background(), key, value, 0)
				assert.NoError(t, err)

				// Get
				_, _, err = c.Get(context.Background(), key)
				assert.NoError(t, err)

				// Delete
				err = c.Delete(context.Background(), key)
				assert.NoError(t, err)
			}
		}(i)
	}

	wg.Wait()
	// If we get here without a panic or data race, the test passes.
}

// TestRedisConcurrency runs concurrent Set/Get/Delete operations against rediscache.Store.
func TestRedisConcurrency(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = client.Close() }()

	c := rediscache.New[string](client)
	defer c.Dispose()

	const numGoroutines = 50
	const opsPerGoroutine = 20
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				key := "key-" + string(rune(j%10))
				value := "value-" + string(rune(id))

				// Set
				err := c.Set(context.Background(), key, value, 0)
				assert.NoError(t, err)

				// Get
				_, _, err = c.Get(context.Background(), key)
				assert.NoError(t, err)

				// Delete
				err = c.Delete(context.Background(), key)
				assert.NoError(t, err)
			}
		}(i)
	}

	wg.Wait()
	// If we get here without a panic or data race, the test passes.
}

// TestRedisCorruptData verifies that corrupt/non-JSON data in redis
// produces a real error from Get, not a silent miss.
func TestRedisCorruptData(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = client.Close() }()

	c := rediscache.New[TestPerson](client)
	defer c.Dispose()

	// Use miniredis's Set to plant bad (non-JSON) data directly.
	require.NoError(t, mr.Set("corrupt-key", "not json at all {{{"))

	// Get should return a real error, not a silent miss.
	val, found, err := c.Get(context.Background(), "corrupt-key")
	assert.Error(t, err, "corrupt data must produce an error")
	assert.False(t, found, "corrupt data should not be found")
	assert.Equal(t, TestPerson{}, val)

	// Verify the error is a JSON unmarshal error.
	var syntaxErr *json.SyntaxError
	assert.ErrorAs(t, err, &syntaxErr, "error should be a JSON syntax error")
}

package redis

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"

	"github.com/JinishBhardwaj/shared-go/health"
)

func TestCheck_NilClient(t *testing.T) {
	entry := Check(nil)(context.Background())

	assert.Equal(t, health.StatusUnhealthy, entry.Status)
	assert.Contains(t, entry.Description, "not initialized")
	assert.Equal(t, []string{"redis", "cache"}, entry.Tags)
	assert.NotEmpty(t, entry.Duration)
}

func TestCheck_CustomTags(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 50 * time.Millisecond})
	defer client.Close()

	entry := Check(client, "redis", "primary")(context.Background())
	assert.Equal(t, []string{"redis", "primary"}, entry.Tags)
}

func TestCheck_UnreachableRedis(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 50 * time.Millisecond})
	defer client.Close()

	entry := Check(client)(context.Background())

	assert.Equal(t, health.StatusUnhealthy, entry.Status)
	assert.NotEmpty(t, entry.Description)
	assert.Contains(t, entry.Data, "error")
}

package cache

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

const DefaultRevocationChannel = "authz:revocations"

// RedisCacheConfig holds options for RedisCacheProvider.
type RedisCacheConfig struct {
	Client            redis.UniversalClient
	KeyPrefix         string
	RevocationChannel string
}

// RedisCacheProvider implements CacheProvider and InvalidationBus using Redis (AWS ElastiCache / MemoryDB).
type RedisCacheProvider struct {
	client  redis.UniversalClient
	prefix  string
	channel string
}

// NewRedisCacheProvider initializes a Redis-backed cache provider.
func NewRedisCacheProvider(cfg RedisCacheConfig) *RedisCacheProvider {
	if cfg.RevocationChannel == "" {
		cfg.RevocationChannel = DefaultRevocationChannel
	}
	return &RedisCacheProvider{
		client:  cfg.Client,
		prefix:  cfg.KeyPrefix,
		channel: cfg.RevocationChannel,
	}
}

func (r *RedisCacheProvider) formatKey(key string) string {
	if r.prefix == "" {
		return key
	}
	return r.prefix + ":" + key
}

// Get fetches bytes from Redis for the specified key.
func (r *RedisCacheProvider) Get(ctx context.Context, key string) ([]byte, error) {
	if key == "" {
		return nil, ErrInvalidKey
	}

	val, err := r.client.Get(ctx, r.formatKey(key)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrCacheMiss
		}
		return nil, err
	}
	return val, nil
}

// Set stores bytes in Redis with a specified TTL.
func (r *RedisCacheProvider) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if key == "" {
		return ErrInvalidKey
	}
	return r.client.Set(ctx, r.formatKey(key), value, ttl).Err()
}

// Delete removes a key from Redis.
func (r *RedisCacheProvider) Delete(ctx context.Context, key string) error {
	if key == "" {
		return ErrInvalidKey
	}
	return r.client.Del(ctx, r.formatKey(key)).Err()
}

// Close closes the underlying Redis client.
func (r *RedisCacheProvider) Close() error {
	if r.client != nil {
		return r.client.Close()
	}
	return nil
}

// PublishRevocation broadcasts a revocation event across all Redis subscribers.
func (r *RedisCacheProvider) PublishRevocation(ctx context.Context, principalID string) error {
	if principalID == "" {
		return errors.New("cache: principalID cannot be empty")
	}
	return r.client.Publish(ctx, r.channel, principalID).Err()
}

// SubscribeRevocations subscribes to the revocation channel and returns a stream of revoked principal IDs.
func (r *RedisCacheProvider) SubscribeRevocations(ctx context.Context) (<-chan string, error) {
	pubsub := r.client.Subscribe(ctx, r.channel)

	// Verify connection
	_, err := pubsub.Receive(ctx)
	if err != nil {
		_ = pubsub.Close()
		return nil, err
	}

	out := make(chan string, 100)
	go func() {
		defer pubsub.Close()
		defer close(out)

		msgChan := pubsub.Channel()
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-msgChan:
				if !ok {
					return
				}
				select {
				case out <- msg.Payload:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return out, nil
}

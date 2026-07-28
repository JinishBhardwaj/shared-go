package bus

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/JinishBhardwaj/shared-go/health"
)

type fakeConnection struct {
	err error
}

func (f fakeConnection) Connect(ctx context.Context) error {
	return f.err
}

func TestCheck_NilConnection(t *testing.T) {
	entry := Check(nil)(context.Background())

	assert.Equal(t, health.StatusUnhealthy, entry.Status)
	assert.Contains(t, entry.Description, "not initialized")
	assert.Equal(t, []string{"bus", "messaging"}, entry.Tags)
	assert.NotEmpty(t, entry.Duration)
}

func TestCheck_CustomTags(t *testing.T) {
	entry := Check(fakeConnection{}, "rabbitmq", "primary")(context.Background())
	assert.Equal(t, []string{"rabbitmq", "primary"}, entry.Tags)
}

func TestCheck_ConnectError(t *testing.T) {
	entry := Check(fakeConnection{err: errors.New("dial tcp: connection refused")})(context.Background())

	assert.Equal(t, health.StatusUnhealthy, entry.Status)
	assert.Contains(t, entry.Description, "connection refused")
	assert.Contains(t, entry.Data, "error")
}

func TestCheck_Healthy(t *testing.T) {
	entry := Check(fakeConnection{})(context.Background())

	assert.Equal(t, health.StatusHealthy, entry.Status)
	assert.NotEmpty(t, entry.Duration)
}

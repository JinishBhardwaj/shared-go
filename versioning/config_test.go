package versioning

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, DefaultVersionValue, cfg.DefaultVersion)
	assert.False(t, cfg.AssumeDefaultVersionWhenUnspecified)
	assert.False(t, cfg.ReportApiVersions)
	assert.Equal(t, DefaultVersionFormat, cfg.VersionFormat)
	assert.NotNil(t, cfg.Reader)

	// Reader should be a HeaderVersionStrategy for x-version
	header, ok := cfg.Reader.(*HeaderVersionStrategy)
	assert.True(t, ok, "default reader should be HeaderVersionStrategy")
	assert.Equal(t, DefaultVersionHeaderName, header.HeaderName)
}

func TestDefaultConfig_Constants(t *testing.T) {
	assert.Equal(t, "x-version", DefaultVersionHeaderName)
	assert.Equal(t, "v1", DefaultVersionValue)
	assert.Equal(t, `^v\d+(b\d+)?$`, DefaultVersionFormat)
}

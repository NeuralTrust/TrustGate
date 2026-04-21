package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_ErrorPassthrough_DefaultTrue(t *testing.T) {
	t.Setenv("UPSTREAM_ERROR_PASSTHROUGH", "")

	cfg, err := Load()
	require.NoError(t, err)
	assert.True(t, cfg.Upstream.ErrorPassthrough)
}

func TestLoad_ErrorPassthrough_Enabled(t *testing.T) {
	t.Setenv("UPSTREAM_ERROR_PASSTHROUGH", "true")

	cfg, err := Load()
	require.NoError(t, err)
	assert.True(t, cfg.Upstream.ErrorPassthrough)
}

func TestLoad_ErrorPassthrough_ExplicitFalse(t *testing.T) {
	t.Setenv("UPSTREAM_ERROR_PASSTHROUGH", "false")

	cfg, err := Load()
	require.NoError(t, err)
	assert.False(t, cfg.Upstream.ErrorPassthrough)
}

func TestLoad_ErrorPassthrough_InvalidValue(t *testing.T) {
	t.Setenv("UPSTREAM_ERROR_PASSTHROUGH", "notabool")

	cfg, err := Load()
	require.NoError(t, err)
	assert.True(t, cfg.Upstream.ErrorPassthrough, "invalid value should fall back to default true")
}

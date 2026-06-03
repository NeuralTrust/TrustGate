package ratelimit

import (
	"context"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestPlugin(t *testing.T) (*Plugin, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	fixed := time.Unix(1_700_000_000, 0)
	seq := 0
	p := New(rdb,
		WithClock(func() time.Time { return fixed }),
		WithIDGenerator(func() string { seq++; return string(rune('a' + seq)) }),
	)
	return p, mr
}

func execInput(settings map[string]any, req *infracontext.RequestContext) appplugins.ExecInput {
	return appplugins.ExecInput{
		Stage:    policy.StagePreRequest,
		Config:   policy.PluginConfig{ID: "plugin-1", Slug: PluginName, Name: PluginName, Settings: settings},
		Request:  req,
		Response: &infracontext.ResponseContext{},
	}
}

func TestPlugin_Stages(t *testing.T) {
	p := New(nil)
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, p.MandatoryStages())
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, p.SupportedStages())
	assert.Equal(t, PluginName, p.Name())
}

func TestPlugin_ValidateConfig(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
		wantErr  bool
	}{
		{
			name:     "valid",
			settings: map[string]any{"limits": map[string]any{"per_ip": map[string]any{"limit": 5, "window": "1m"}}},
		},
		{
			name:     "no limits",
			settings: map[string]any{"limits": map[string]any{}},
			wantErr:  true,
		},
		{
			name:     "non-positive limit",
			settings: map[string]any{"limits": map[string]any{"global": map[string]any{"limit": 0, "window": "1m"}}},
			wantErr:  true,
		},
		{
			name:     "bad window",
			settings: map[string]any{"limits": map[string]any{"global": map[string]any{"limit": 5, "window": "nope"}}},
			wantErr:  true,
		},
		{
			name:     "bad action type",
			settings: map[string]any{"limits": map[string]any{"global": map[string]any{"limit": 5, "window": "1m"}}, "actions": map[string]any{"type": "explode"}},
			wantErr:  true,
		},
	}
	p := New(nil)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.ValidateConfig(tt.settings)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestPlugin_Execute_AllowsUnderLimit(t *testing.T) {
	p, _ := newTestPlugin(t)
	settings := map[string]any{"limits": map[string]any{"per_ip": map[string]any{"limit": 3, "window": "1m"}}}
	req := &infracontext.RequestContext{IP: "1.2.3.4"}

	res, err := p.Execute(context.Background(), execInput(settings, req))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, []string{"3"}, res.Headers["X-RateLimit-per_ip-Limit"])
	assert.Equal(t, []string{"3"}, res.Headers["X-RateLimit-per_ip-Remaining"])
}

func TestPlugin_Execute_RejectsOverLimit(t *testing.T) {
	p, _ := newTestPlugin(t)
	settings := map[string]any{
		"limits":  map[string]any{"per_ip": map[string]any{"limit": 2, "window": "1m"}},
		"actions": map[string]any{"type": "reject", "retry_after": "30"},
	}
	req := &infracontext.RequestContext{IP: "1.2.3.4"}

	for i := 0; i < 2; i++ {
		_, err := p.Execute(context.Background(), execInput(settings, req))
		require.NoError(t, err, "request %d should pass", i)
	}

	_, err := p.Execute(context.Background(), execInput(settings, req))
	require.Error(t, err)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, 429, pe.StatusCode)
	assert.Equal(t, []string{"30"}, pe.Headers["Retry-After"])
	assert.Equal(t, []string{"0"}, pe.Headers["X-RateLimit-per_ip-Remaining"])
}

func TestPlugin_Execute_PerFingerprintFromContext(t *testing.T) {
	p, _ := newTestPlugin(t)
	settings := map[string]any{"limits": map[string]any{"per_fingerprint": map[string]any{"limit": 1, "window": "1m"}}}
	ctx := context.WithValue(context.Background(), infracontext.FingerprintIDContextKey, "fp-123")
	req := &infracontext.RequestContext{}

	_, err := p.Execute(ctx, execInput(settings, req))
	require.NoError(t, err)
	_, err = p.Execute(ctx, execInput(settings, req))
	require.Error(t, err)
	pe, _ := appplugins.AsPluginError(err)
	assert.Equal(t, 429, pe.StatusCode)
}

func TestPlugin_Execute_SkipsAnonymousPerUser(t *testing.T) {
	p, _ := newTestPlugin(t)
	settings := map[string]any{"limits": map[string]any{"per_user": map[string]any{"limit": 1, "window": "1m"}}}
	req := &infracontext.RequestContext{}

	// No user header -> anonymous -> limit skipped, so repeated calls always pass.
	for i := 0; i < 5; i++ {
		_, err := p.Execute(context.Background(), execInput(settings, req))
		require.NoError(t, err)
	}
}

func TestPlugin_Execute_DefaultRetryAfter(t *testing.T) {
	p, _ := newTestPlugin(t)
	settings := map[string]any{"limits": map[string]any{"global": map[string]any{"limit": 1, "window": "1m"}}}
	req := &infracontext.RequestContext{}

	_, err := p.Execute(context.Background(), execInput(settings, req))
	require.NoError(t, err)
	_, err = p.Execute(context.Background(), execInput(settings, req))
	require.Error(t, err)
	pe, _ := appplugins.AsPluginError(err)
	assert.Equal(t, []string{"60"}, pe.Headers["Retry-After"])
}

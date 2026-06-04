package tokenratelimit

import (
	"context"
	"testing"

	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestPlugin(t *testing.T) *Plugin {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return New(rdb, adapter.NewRegistry())
}

func input(stage policy.Stage, settings map[string]any, req *infracontext.RequestContext, resp *infracontext.ResponseContext) appplugins.ExecInput {
	return appplugins.ExecInput{
		Stage:    stage,
		Config:   policy.PluginConfig{ID: "tk-1", Slug: PluginName, Name: PluginName, Settings: settings},
		Request:  req,
		Response: resp,
	}
}

func TestPlugin_Stages(t *testing.T) {
	p := New(nil, nil)
	assert.Equal(t, []policy.Stage{policy.StagePreRequest, policy.StagePostResponse}, p.MandatoryStages())
	assert.Equal(t, []policy.Stage{policy.StagePreRequest, policy.StagePostResponse}, p.SupportedStages())
	assert.Equal(t, PluginName, p.Name())
}

func TestPlugin_ValidateConfig(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
		wantErr  bool
	}{
		{name: "valid", settings: map[string]any{"window": map[string]any{"unit": "minute", "max": 100}}},
		{name: "zero max", settings: map[string]any{"window": map[string]any{"unit": "minute", "max": 0}}, wantErr: true},
		{name: "bad unit", settings: map[string]any{"window": map[string]any{"unit": "fortnight", "max": 100}}, wantErr: true},
	}
	p := New(nil, nil)
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

func TestPlugin_Execute_SkipsWhenNoProvider(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{"window": map[string]any{"unit": "minute", "max": 10}}
	res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, &infracontext.RequestContext{}, &infracontext.ResponseContext{}))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Empty(t, res.Headers)
}

func TestPlugin_PreRequest_AllowsAndReports(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{"window": map[string]any{"unit": "minute", "max": 100}}
	req := &infracontext.RequestContext{Provider: "openai", IP: "1.1.1.1"}

	res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}))
	require.NoError(t, err)
	assert.Equal(t, []string{"100"}, res.Headers["X-Ratelimit-Limit-Tokens"])
	assert.Equal(t, []string{"100"}, res.Headers["X-Ratelimit-Remaining-Tokens"])
}

func TestPlugin_PostResponse_RecordsTokensAndPreRequestRejects(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{"window": map[string]any{"unit": "minute", "max": 10}}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", IP: "1.1.1.1"}

	body := []byte(`{"id":"x","model":"gpt","choices":[{"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`)
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: body}

	res, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, req, resp))
	require.NoError(t, err)
	assert.Equal(t, []string{"15"}, res.Headers["X-Tokens-Consumed"])
	assert.Equal(t, []string{"0"}, res.Headers["X-Ratelimit-Remaining-Tokens"])

	// Now the next PreRequest must reject (15 consumed >= 10 limit).
	_, err = p.Execute(context.Background(), input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}))
	require.Error(t, err)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, 429, pe.StatusCode)
}

func TestPlugin_PostResponse_StreamingUsesObservedUsage(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{"window": map[string]any{"unit": "minute", "max": 100}}
	req := &infracontext.RequestContext{
		Provider: "openai",
		Metadata: map[string]interface{}{adapter.MetadataUsageKey: &adapter.CanonicalUsage{TotalTokens: 42}},
	}
	resp := &infracontext.ResponseContext{StatusCode: 200, Streaming: true}

	res, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, req, resp))
	require.NoError(t, err)
	assert.Equal(t, []string{"42"}, res.Headers["X-Tokens-Consumed"])
}

func TestPlugin_PostResponse_NoTokensNoRecord(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{"window": map[string]any{"unit": "minute", "max": 100}}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai"}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{}`)}

	res, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, req, resp))
	require.NoError(t, err)
	assert.Empty(t, res.Headers["X-Tokens-Consumed"])
}

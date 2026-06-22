// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tokenratelimit

import (
	"context"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
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
		Scope:    appplugins.RuntimeScope{ConsumerID: "c-1", GatewayID: "gw-1"},
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

func TestPlugin_PreRequest_ObserveDoesNotReject(t *testing.T) {
	p := newTestPlugin(t)
	assert.Equal(t, []policy.Mode{policy.ModeEnforce, policy.ModeThrottle, policy.ModeObserve}, p.SupportedModes())

	settings := map[string]any{"window": map[string]any{"unit": "minute", "max": 10}}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", IP: "2.2.2.2"}

	body := []byte(`{"id":"x","model":"gpt","choices":[{"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`)
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: body}
	_, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, req, resp))
	require.NoError(t, err)

	in := input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{})
	in.Mode = policy.ModeObserve
	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err, "observe must not reject an over-budget request")
	require.NotNil(t, res)
	assert.Equal(t, 200, res.StatusCode)
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

func scopedInput(stage policy.Stage, settings map[string]any, req *infracontext.RequestContext, resp *infracontext.ResponseContext, scope appplugins.RuntimeScope) appplugins.ExecInput {
	in := input(stage, settings, req, resp)
	in.Scope = scope
	return in
}

// A non-global policy must give each consumer an independent token budget even
// when they share the same policy (same Config.ID).
func TestPlugin_ConsumerScopeIsolatesBudgets(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{"window": map[string]any{"unit": "minute", "max": 10}}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai"}
	body := []byte(`{"id":"x","model":"gpt","choices":[{"message":{"role":"assistant","content":"hi"}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`)
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: body}

	c1 := appplugins.RuntimeScope{ConsumerID: "c-1", GatewayID: "gw-1"}
	c2 := appplugins.RuntimeScope{ConsumerID: "c-2", GatewayID: "gw-1"}

	_, err := p.Execute(context.Background(), scopedInput(policy.StagePostResponse, settings, req, resp, c1))
	require.NoError(t, err)

	// c-1 is over budget now.
	_, err = p.Execute(context.Background(), scopedInput(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}, c1))
	require.Error(t, err)

	// c-2 shares the policy but keeps its own budget.
	_, err = p.Execute(context.Background(), scopedInput(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}, c2))
	require.NoError(t, err, "a sibling consumer must not inherit another consumer's token usage")
}

// A global policy shares one token counter across consumers of the gateway.
func TestPlugin_GlobalScopeSharesBudget(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{"window": map[string]any{"unit": "minute", "max": 10}}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai"}
	body := []byte(`{"id":"x","model":"gpt","choices":[{"message":{"role":"assistant","content":"hi"}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`)
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: body}

	global := appplugins.RuntimeScope{GatewayID: "gw-1", Global: true}

	_, err := p.Execute(context.Background(), scopedInput(policy.StagePostResponse, settings, req, resp, global))
	require.NoError(t, err)

	_, err = p.Execute(context.Background(), scopedInput(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}, global))
	require.Error(t, err, "the shared global budget must gate the next request from any consumer")
}

// With a group_by_header configured, the token budget is sub-partitioned by
// header value within the policy scope: distinct values get independent budgets.
func TestPlugin_GroupByHeaderIsolatesBudgets(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"window":          map[string]any{"unit": "minute", "max": 10},
		"group_by_header": "X-User-Id",
	}
	scope := appplugins.RuntimeScope{ConsumerID: "c-1", GatewayID: "gw-1"}
	body := []byte(`{"id":"x","model":"gpt","choices":[{"message":{"role":"assistant","content":"hi"}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`)

	reqU1 := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Headers: map[string][]string{"X-User-Id": {"user-1"}}}
	reqU2 := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Headers: map[string][]string{"X-User-Id": {"user-2"}}}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: body}

	// user-1 consumes its whole budget.
	_, err := p.Execute(context.Background(), scopedInput(policy.StagePostResponse, settings, reqU1, resp, scope))
	require.NoError(t, err)

	// user-1 is now over budget.
	_, err = p.Execute(context.Background(), scopedInput(policy.StagePreRequest, settings, reqU1, &infracontext.ResponseContext{}, scope))
	require.Error(t, err)

	// user-2 has an independent budget within the same consumer.
	_, err = p.Execute(context.Background(), scopedInput(policy.StagePreRequest, settings, reqU2, &infracontext.ResponseContext{}, scope))
	require.NoError(t, err, "a different header value must have an independent token budget")
}

func TestPlugin_ConsumerScopeRequiresConsumerID(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{"window": map[string]any{"unit": "minute", "max": 10}}
	req := &infracontext.RequestContext{Provider: "openai"}

	_, err := p.Execute(context.Background(), scopedInput(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}, appplugins.RuntimeScope{GatewayID: "gw-1"}))
	require.Error(t, err)
}

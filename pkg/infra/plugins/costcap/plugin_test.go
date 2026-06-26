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

package costcap

import (
	"context"
	"encoding/json"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/llmcost"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type costCapErrorBody struct {
	Error struct {
		Type        string  `json:"type"`
		Model       string  `json:"model"`
		InputPrice  float64 `json:"input_price"`
		OutputPrice float64 `json:"output_price"`
		MaxInput    float64 `json:"max_input"`
		MaxOutput   float64 `json:"max_output"`
	} `json:"error"`
}

func newTestPlugin(t *testing.T) *Plugin {
	t.Helper()
	return New(nil)
}

func input(stage policy.Stage, settings map[string]any, req *infracontext.RequestContext) appplugins.ExecInput {
	return appplugins.ExecInput{
		Stage:   stage,
		Config:  policy.PluginConfig{ID: "cc-1", Slug: PluginName, Name: PluginName, Settings: settings},
		Scope:   appplugins.RuntimeScope{ConsumerID: "c-1", GatewayID: "gw-1"},
		Request: req,
	}
}

func TestPlugin_Stages(t *testing.T) {
	p := New(nil)
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, p.MandatoryStages())
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, p.SupportedStages())
	assert.Equal(t, []policy.Mode{policy.ModeEnforce, policy.ModeObserve}, p.SupportedModes())
	assert.Equal(t, PluginName, p.Name())
}

func TestPlugin_ValidateConfig(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
		wantErr  bool
	}{
		{name: "valid global ceiling", settings: map[string]any{"max_input_cost_per_1k_tokens": 0.5}},
		{
			name: "valid per-model override only",
			settings: map[string]any{
				"per_model_overrides": map[string]any{
					"gpt-4o": map[string]any{"max_input_cost_per_1k_tokens": 1},
				},
			},
		},
		{name: "no ceiling configured", settings: map[string]any{}, wantErr: true},
		{name: "bad behavior", settings: map[string]any{"max_input_cost_per_1k_tokens": 1, "behavior_on_violation": "explode"}, wantErr: true},
		{name: "downgrade without target", settings: map[string]any{"max_input_cost_per_1k_tokens": 1, "behavior_on_violation": "downgrade"}, wantErr: true},
		{name: "bad unknown model", settings: map[string]any{"max_input_cost_per_1k_tokens": 1, "unknown_model": "maybe"}, wantErr: true},
		{name: "negative ceiling", settings: map[string]any{"max_input_cost_per_1k_tokens": -1}, wantErr: true},
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

func TestPlugin_SkipsWhenNoProvider(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{"max_input_cost_per_1k_tokens": 0.5}
	res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, &infracontext.RequestContext{}))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, 200, res.StatusCode)
}

func TestPlugin_RejectsOverCeilingWithBody(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"custom_pricing":                map[string]any{"gpt-4o": map[string]any{"input": 0.001, "output": 0.002}},
		"max_input_cost_per_1k_tokens":  0.5,
		"max_output_cost_per_1k_tokens": 0.5,
		"behavior_on_violation":         "reject",
	}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"gpt-4o"}`)}

	_, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, req))
	require.Error(t, err)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, 403, pe.StatusCode)

	var parsed costCapErrorBody
	require.NoError(t, json.Unmarshal(pe.Body, &parsed))
	assert.Equal(t, "model_too_expensive", parsed.Error.Type)
	assert.Equal(t, "gpt-4o", parsed.Error.Model)
	assert.InDelta(t, 1.0, parsed.Error.InputPrice, 1e-9)
	assert.InDelta(t, 2.0, parsed.Error.OutputPrice, 1e-9)
	assert.InDelta(t, 0.5, parsed.Error.MaxInput, 1e-9)
	assert.InDelta(t, 0.5, parsed.Error.MaxOutput, 1e-9)
}

func TestPlugin_PerModelOverrideAllows(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"custom_pricing":                map[string]any{"claude-opus-4": map[string]any{"input": 0.001, "output": 0.001}},
		"max_input_cost_per_1k_tokens":  0.5,
		"max_output_cost_per_1k_tokens": 0.5,
		"per_model_overrides": map[string]any{
			"claude-opus-*": map[string]any{
				"max_input_cost_per_1k_tokens":  100,
				"max_output_cost_per_1k_tokens": 100,
			},
		},
	}
	req := &infracontext.RequestContext{Provider: "anthropic", SourceFormat: "openai", Body: []byte(`{"model":"claude-opus-4"}`)}

	res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, req))
	require.NoError(t, err, "the per-model override must raise the ceiling above the model price")
	require.NotNil(t, res)
	assert.Equal(t, 200, res.StatusCode)
}

func TestPlugin_DatedModelUsesBaseOverride(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"custom_pricing":                map[string]any{"gpt-4o": map[string]any{"input": 0.001, "output": 0.001}},
		"max_input_cost_per_1k_tokens":  0.5,
		"max_output_cost_per_1k_tokens": 0.5,
		"per_model_overrides": map[string]any{
			"gpt-4o": map[string]any{
				"max_input_cost_per_1k_tokens":  100,
				"max_output_cost_per_1k_tokens": 100,
			},
		},
	}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"gpt-4o-2024-08-06"}`)}

	res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, req))
	require.NoError(t, err, "a dated model must match its base-slug per_model_override, not fall back to the global ceiling")
	require.NotNil(t, res)
	assert.Equal(t, 200, res.StatusCode)
}

func TestPlugin_UnknownModelPolicies(t *testing.T) {
	tests := []struct {
		name    string
		unknown string
		wantErr bool
	}{
		{name: "reject", unknown: "reject", wantErr: true},
		{name: "assume_max", unknown: "assume_max", wantErr: true},
		{name: "pass_through", unknown: "pass_through"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestPlugin(t)
			settings := map[string]any{
				"max_input_cost_per_1k_tokens": 1,
				"unknown_model":                tt.unknown,
			}
			req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"mystery-model"}`)}

			res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, req))
			if tt.wantErr {
				require.Error(t, err)
				pe, ok := appplugins.AsPluginError(err)
				require.True(t, ok)
				assert.Equal(t, 403, pe.StatusCode)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, res)
			assert.Equal(t, 200, res.StatusCode)
		})
	}
}

func TestPlugin_ThrottleDoesNotReject(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"custom_pricing":               map[string]any{"gpt-4o": map[string]any{"input": 0.001, "output": 0.002}},
		"max_input_cost_per_1k_tokens": 0.5,
		"behavior_on_violation":        "reject",
	}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"gpt-4o"}`)}

	in := input(policy.StagePreRequest, settings, req)
	in.Mode = policy.ModeThrottle
	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err, "throttle must not 403 a stateless cost-cap violation; only enforce rejects")
	require.NotNil(t, res)
	assert.Equal(t, 200, res.StatusCode)
}

func TestPlugin_ObserveDoesNotReject(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"custom_pricing":               map[string]any{"gpt-4o": map[string]any{"input": 0.001, "output": 0.002}},
		"max_input_cost_per_1k_tokens": 0.5,
		"behavior_on_violation":        "reject",
	}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"gpt-4o"}`)}

	in := input(policy.StagePreRequest, settings, req)
	in.Mode = policy.ModeObserve
	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err, "observe must not reject an over-priced model")
	require.NotNil(t, res)
	assert.Equal(t, 200, res.StatusCode)
}

func TestPlugin_ObserveViolationExtrasSurvive(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"custom_pricing":               map[string]any{"gpt-4o": map[string]any{"input": 0.001, "output": 0.002}},
		"max_input_cost_per_1k_tokens": 0.5,
		"behavior_on_violation":        "reject",
	}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"gpt-4o"}`)}

	span := &trace.Span{}
	in := input(policy.StagePreRequest, settings, req)
	in.Mode = policy.ModeObserve
	in.Event = metrics.NewEventContext(span)

	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, 200, res.StatusCode)

	require.NotNil(t, span.Plugin)
	data, ok := span.Plugin.Extras.(CostCapData)
	require.True(t, ok)
	assert.True(t, data.Violation, "cost-cap telemetry must survive when the request proceeds")
	assert.InDelta(t, 1.0, data.InputPricePer1k, 1e-9)
	assert.InDelta(t, 0.5, data.MaxInputPer1k, 1e-9)
}

func TestPlugin_DowngradeRewritesModel(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"custom_pricing":               map[string]any{"gpt-4o": map[string]any{"input": 0.001, "output": 0.002}},
		"max_input_cost_per_1k_tokens": 0.5,
		"behavior_on_violation":        "downgrade",
		"downgrade_to":                 "gpt-4o-mini",
	}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"gpt-4o"}`)}

	res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, req))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, []string{"gpt-4o→gpt-4o-mini"}, res.Headers[llmcost.DowngradeHeader])
	require.NotNil(t, res.RequestBody)
	assert.Contains(t, string(res.RequestBody), `"model":"gpt-4o-mini"`, "the outbound body must carry the downgraded model")
	assert.Contains(t, string(req.Body), `"model":"gpt-4o"`, "the downgrade must not mutate the context body in place")
}

func TestPlugin_DowngradeCrossProviderRejects(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"custom_pricing":               map[string]any{"gpt-4o": map[string]any{"input": 0.001, "output": 0.002}},
		"max_input_cost_per_1k_tokens": 0.5,
		"behavior_on_violation":        "downgrade",
		"downgrade_to":                 "@anthropic/claude-3-haiku",
	}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"gpt-4o"}`)}

	_, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, req))
	require.Error(t, err)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, 403, pe.StatusCode)
	assert.Contains(t, string(req.Body), `"model":"gpt-4o"`, "a rejected downgrade must not rewrite the body")
}

func TestPlugin_DowngradeNotAllowedRejects(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"custom_pricing":               map[string]any{"gpt-4o": map[string]any{"input": 0.001, "output": 0.002}},
		"max_input_cost_per_1k_tokens": 0.5,
		"behavior_on_violation":        "downgrade",
		"downgrade_to":                 "gpt-4o-mini",
	}
	req := &infracontext.RequestContext{
		Provider:      "openai",
		SourceFormat:  "openai",
		Body:          []byte(`{"model":"gpt-4o"}`),
		AllowedModels: []string{"gpt-4o"},
	}

	_, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, req))
	require.Error(t, err)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, 403, pe.StatusCode, "a target outside AllowedModels must fall back to reject")
}

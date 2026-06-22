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
	"encoding/json"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
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

func TestEvaluateCeiling(t *testing.T) {
	cc := &costCapConfig{
		MaxInputCostPer1k:  1,
		MaxOutputCostPer1k: 2,
		PerModelOverrides: map[string]costCeiling{
			"claude-opus-*": {MaxInputCostPer1k: 10, MaxOutputCostPer1k: 20},
			"claude-opus-4": {MaxInputCostPer1k: 30, MaxOutputCostPer1k: 40},
		},
	}
	t.Run("falls back to global", func(t *testing.T) {
		c := evaluateCeiling(cc, "gpt-4o")
		assert.Equal(t, float64(1), c.MaxInputCostPer1k)
		assert.Equal(t, float64(2), c.MaxOutputCostPer1k)
	})
	t.Run("glob override applies", func(t *testing.T) {
		c := evaluateCeiling(cc, "claude-opus-3")
		assert.Equal(t, float64(10), c.MaxInputCostPer1k)
	})
	t.Run("exact beats glob", func(t *testing.T) {
		c := evaluateCeiling(cc, "claude-opus-4")
		assert.Equal(t, float64(30), c.MaxInputCostPer1k)
		assert.Equal(t, float64(40), c.MaxOutputCostPer1k)
	})
}

func TestCostCapDecision(t *testing.T) {
	tests := []struct {
		name         string
		costCap      *costCapConfig
		pricing      map[string]customPrice
		model        string
		wantKind     decisionKind
		wantUnknown  bool
		wantMaxInput float64
	}{
		{
			name:         "under global ceiling allows",
			costCap:      &costCapConfig{Enabled: true, MaxInputCostPer1k: 5, MaxOutputCostPer1k: 5},
			pricing:      map[string]customPrice{"gpt-4o": {Input: 0.001, Output: 0.001}},
			model:        "gpt-4o",
			wantKind:     decisionAllow,
			wantMaxInput: 5,
		},
		{
			name:         "over global input ceiling violates",
			costCap:      &costCapConfig{Enabled: true, MaxInputCostPer1k: 0.5, MaxOutputCostPer1k: 5},
			pricing:      map[string]customPrice{"gpt-4o": {Input: 0.001, Output: 0.001}},
			model:        "gpt-4o",
			wantKind:     decisionViolation,
			wantMaxInput: 0.5,
		},
		{
			name: "per-model override raises ceiling and allows",
			costCap: &costCapConfig{
				Enabled:            true,
				MaxInputCostPer1k:  0.5,
				MaxOutputCostPer1k: 0.5,
				PerModelOverrides:  map[string]costCeiling{"claude-opus-*": {MaxInputCostPer1k: 100, MaxOutputCostPer1k: 100}},
			},
			pricing:      map[string]customPrice{"claude-opus-4": {Input: 0.001, Output: 0.001}},
			model:        "claude-opus-4",
			wantKind:     decisionAllow,
			wantMaxInput: 100,
		},
		{
			name: "dated model resolves base-slug override not global",
			costCap: &costCapConfig{
				Enabled:            true,
				MaxInputCostPer1k:  0.5,
				MaxOutputCostPer1k: 0.5,
				PerModelOverrides:  map[string]costCeiling{"gpt-4o": {MaxInputCostPer1k: 100, MaxOutputCostPer1k: 100}},
			},
			pricing:      map[string]customPrice{"gpt-4o": {Input: 0.001, Output: 0.001}},
			model:        "gpt-4o-2024-08-06",
			wantKind:     decisionAllow,
			wantMaxInput: 100,
		},
		{
			name:         "unknown reject violates",
			costCap:      &costCapConfig{Enabled: true, MaxInputCostPer1k: 1, UnknownModel: unknownReject},
			model:        "mystery",
			wantKind:     decisionViolation,
			wantUnknown:  true,
			wantMaxInput: 1,
		},
		{
			name:         "unknown assume_max violates",
			costCap:      &costCapConfig{Enabled: true, MaxInputCostPer1k: 1, UnknownModel: unknownAssumeMax},
			model:        "mystery",
			wantKind:     decisionViolation,
			wantUnknown:  true,
			wantMaxInput: 1,
		},
		{
			name:         "unknown pass_through allows",
			costCap:      &costCapConfig{Enabled: true, MaxInputCostPer1k: 1, UnknownModel: unknownPassThrough},
			model:        "mystery",
			wantKind:     decisionAllow,
			wantUnknown:  true,
			wantMaxInput: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Plugin{}
			cfg := &config{CostCap: tt.costCap, CustomPricing: tt.pricing}
			dec := p.costCapDecision(context.Background(), cfg, "openai", tt.model)
			assert.Equal(t, tt.wantKind, dec.kind)
			assert.Equal(t, tt.wantUnknown, dec.unknown)
			assert.Equal(t, tt.model, dec.model)
			assert.Equal(t, tt.wantMaxInput, dec.maxInput)
		})
	}
}

func TestPlugin_CostCap_RejectsOverCeilingWithBody(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"pricing_table":  "custom",
		"custom_pricing": map[string]any{"gpt-4o": map[string]any{"input": 0.001, "output": 0.002}},
		"cost_cap": map[string]any{
			"enabled":                       true,
			"max_input_cost_per_1k_tokens":  0.5,
			"max_output_cost_per_1k_tokens": 0.5,
			"behavior_on_violation":         "reject",
		},
	}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"gpt-4o"}`)}

	_, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}))
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

func TestPlugin_CostCap_PerModelOverrideAllows(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"pricing_table":  "custom",
		"custom_pricing": map[string]any{"claude-opus-4": map[string]any{"input": 0.001, "output": 0.001}},
		"cost_cap": map[string]any{
			"enabled":                       true,
			"max_input_cost_per_1k_tokens":  0.5,
			"max_output_cost_per_1k_tokens": 0.5,
			"per_model_overrides": map[string]any{
				"claude-opus-*": map[string]any{
					"max_input_cost_per_1k_tokens":  100,
					"max_output_cost_per_1k_tokens": 100,
				},
			},
		},
	}
	req := &infracontext.RequestContext{Provider: "anthropic", SourceFormat: "openai", Body: []byte(`{"model":"claude-opus-4"}`)}

	res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}))
	require.NoError(t, err, "the per-model override must raise the ceiling above the model price")
	require.NotNil(t, res)
	assert.Equal(t, 200, res.StatusCode)
}

func TestPlugin_CostCap_UnknownModelPolicies(t *testing.T) {
	tests := []struct {
		name      string
		unknown   string
		wantErr   bool
		wantAllow bool
	}{
		{name: "reject", unknown: "reject", wantErr: true},
		{name: "assume_max", unknown: "assume_max", wantErr: true},
		{name: "pass_through", unknown: "pass_through", wantAllow: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestPlugin(t)
			settings := map[string]any{
				"cost_cap": map[string]any{
					"enabled":                      true,
					"max_input_cost_per_1k_tokens": 1,
					"unknown_model":                tt.unknown,
				},
			}
			req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"mystery-model"}`)}

			res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}))
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

func TestPlugin_CostCap_RunsBeforeBudgetGate(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"pricing_table":  "custom",
		"custom_pricing": map[string]any{"gpt-4o": map[string]any{"input": 0.001, "output": 0}},
		"aggregate":      map[string]any{"max": 10, "time_window": "1m"},
		"cost_cap": map[string]any{
			"enabled":                      true,
			"max_input_cost_per_1k_tokens": 0.5,
			"behavior_on_violation":        "reject",
		},
	}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"gpt-4o"}`)}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: usageResponseBody()}

	_, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, req, resp))
	require.NoError(t, err)

	_, err = p.Execute(context.Background(), input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}))
	require.Error(t, err)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, 403, pe.StatusCode, "the cost cap must short-circuit with 403 before the 429 budget gate is read")

	var parsed costCapErrorBody
	require.NoError(t, json.Unmarshal(pe.Body, &parsed))
	assert.Equal(t, "model_too_expensive", parsed.Error.Type)
}

func TestPlugin_CostCap_ThrottleDoesNotReject(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"pricing_table":  "custom",
		"custom_pricing": map[string]any{"gpt-4o": map[string]any{"input": 0.001, "output": 0.002}},
		"cost_cap": map[string]any{
			"enabled":                      true,
			"max_input_cost_per_1k_tokens": 0.5,
			"behavior_on_violation":        "reject",
		},
	}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"gpt-4o"}`)}

	in := input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{})
	in.Mode = policy.ModeThrottle
	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err, "throttle must not 403 a stateless cost-cap violation; only enforce rejects")
	require.NotNil(t, res)
	assert.Equal(t, 200, res.StatusCode)
}

func TestPlugin_CostCap_DatedModelUsesBaseOverride(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"pricing_table":  "custom",
		"custom_pricing": map[string]any{"gpt-4o": map[string]any{"input": 0.001, "output": 0.001}},
		"cost_cap": map[string]any{
			"enabled":                       true,
			"max_input_cost_per_1k_tokens":  0.5,
			"max_output_cost_per_1k_tokens": 0.5,
			"per_model_overrides": map[string]any{
				"gpt-4o": map[string]any{
					"max_input_cost_per_1k_tokens":  100,
					"max_output_cost_per_1k_tokens": 100,
				},
			},
		},
	}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"gpt-4o-2024-08-06"}`)}

	res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}))
	require.NoError(t, err, "a dated model must match its base-slug per_model_override, not fall back to the global ceiling")
	require.NotNil(t, res)
	assert.Equal(t, 200, res.StatusCode)
}

func TestPlugin_CostCap_ObserveViolationExtrasSurvive(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"pricing_table":  "custom",
		"custom_pricing": map[string]any{"gpt-4o": map[string]any{"input": 0.001, "output": 0.002}},
		"aggregate":      map[string]any{"max": 1000, "time_window": "1m"},
		"cost_cap": map[string]any{
			"enabled":                      true,
			"max_input_cost_per_1k_tokens": 0.5,
			"behavior_on_violation":        "reject",
		},
	}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"gpt-4o"}`)}

	span := &trace.Span{}
	in := input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{})
	in.Mode = policy.ModeObserve
	in.Event = metrics.NewEventContext(span)

	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, 200, res.StatusCode)

	require.NotNil(t, span.Plugin)
	data, ok := span.Plugin.Extras.(TokenRateLimiterData)
	require.True(t, ok, "pre_request must emit a single TokenRateLimiterData extras payload")
	assert.True(t, data.CostCapViolation, "cost-cap telemetry must survive when the request proceeds")
	assert.InDelta(t, 1.0, data.InputPricePer1k, 1e-9)
	assert.InDelta(t, 0.5, data.MaxInputPer1k, 1e-9)
	assert.Equal(t, 1000, data.WindowMax, "the same payload must also carry the budget fields")
}

func TestPlugin_CostCap_ObserveDoesNotReject(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"pricing_table":  "custom",
		"custom_pricing": map[string]any{"gpt-4o": map[string]any{"input": 0.001, "output": 0.002}},
		"cost_cap": map[string]any{
			"enabled":                      true,
			"max_input_cost_per_1k_tokens": 0.5,
			"behavior_on_violation":        "reject",
		},
	}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"gpt-4o"}`)}

	in := input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{})
	in.Mode = policy.ModeObserve
	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err, "observe must not reject an over-priced model")
	require.NotNil(t, res)
	assert.Equal(t, 200, res.StatusCode)
}

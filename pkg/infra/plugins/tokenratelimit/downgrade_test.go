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
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/llmcost"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type budgetErrorBody struct {
	Error struct {
		Type   string `json:"type"`
		Scope  string `json:"scope"`
		Window string `json:"window"`
	} `json:"error"`
}

func TestPlugin_CostCap_DowngradeRewritesModel(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"pricing_table":  "custom",
		"custom_pricing": map[string]any{"gpt-4o": map[string]any{"input": 0.001, "output": 0.002}},
		"cost_cap": map[string]any{
			"enabled":                      true,
			"max_input_cost_per_1k_tokens": 0.5,
			"behavior_on_violation":        "downgrade",
			"downgrade_to":                 "gpt-4o-mini",
		},
	}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"gpt-4o"}`)}

	res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, []string{"gpt-4o→gpt-4o-mini"}, res.Headers[llmcost.DowngradeHeader])
	require.NotNil(t, res.RequestBody)
	assert.Contains(t, string(res.RequestBody), `"model":"gpt-4o-mini"`, "the outbound body must carry the downgraded model")
	assert.Contains(t, string(req.Body), `"model":"gpt-4o"`, "the downgrade must not mutate the context body in place")
}

func TestPlugin_CostCap_DowngradeCrossProviderRejects(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"pricing_table":  "custom",
		"custom_pricing": map[string]any{"gpt-4o": map[string]any{"input": 0.001, "output": 0.002}},
		"cost_cap": map[string]any{
			"enabled":                      true,
			"max_input_cost_per_1k_tokens": 0.5,
			"behavior_on_violation":        "downgrade",
			"downgrade_to":                 "@anthropic/claude-3-haiku",
		},
	}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"gpt-4o"}`)}

	_, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}))
	require.Error(t, err)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, 403, pe.StatusCode)
	assert.Contains(t, string(req.Body), `"model":"gpt-4o"`, "a rejected downgrade must not rewrite the body")
}

func TestPlugin_CostCap_DowngradeNotAllowedRejects(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"pricing_table":  "custom",
		"custom_pricing": map[string]any{"gpt-4o": map[string]any{"input": 0.001, "output": 0.002}},
		"cost_cap": map[string]any{
			"enabled":                      true,
			"max_input_cost_per_1k_tokens": 0.5,
			"behavior_on_violation":        "downgrade",
			"downgrade_to":                 "gpt-4o-mini",
		},
	}
	req := &infracontext.RequestContext{
		Provider:      "openai",
		SourceFormat:  "openai",
		Body:          []byte(`{"model":"gpt-4o"}`),
		AllowedModels: []string{"gpt-4o"},
	}

	_, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}))
	require.Error(t, err)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, 403, pe.StatusCode, "a target outside AllowedModels must fall back to reject")
}

func TestPlugin_Budget_DowngradeModelOnExceed(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"aggregate":            map[string]any{"max": 10, "time_window": "1m"},
		"behavior_on_exceeded": "downgrade_model",
		"downgrade_to":         "gpt-4o-mini",
	}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"gpt-4o"}`)}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: usageResponseBody()}

	_, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, req, resp))
	require.NoError(t, err)

	res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}))
	require.NoError(t, err, "a downgradeable budget breach must pass through")
	require.NotNil(t, res)
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, []string{"gpt-4o→gpt-4o-mini"}, res.Headers[llmcost.DowngradeHeader])
	require.NotNil(t, res.RequestBody)
	assert.Contains(t, string(res.RequestBody), `"model":"gpt-4o-mini"`)
	assert.Contains(t, string(req.Body), `"model":"gpt-4o"`, "the downgrade must not mutate the context body in place")
}

func TestPlugin_Budget_TokenExceededBodyAndHeaders(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"aggregate": map[string]any{"max": 10, "time_window": "1m"},
	}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"gpt-4o"}`)}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: usageResponseBody()}

	_, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, req, resp))
	require.NoError(t, err)

	_, err = p.Execute(context.Background(), input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}))
	require.Error(t, err)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, 429, pe.StatusCode)
	assert.Equal(t, []string{"10"}, pe.Headers["X-Ratelimit-Limit-Tokens"], "the token path must keep its rate-limit headers")
	assert.Equal(t, []string{"tokens"}, pe.Headers[headerBudgetUnit])
	assert.Equal(t, []string{"consumer"}, pe.Headers[headerBudgetScope])
	assert.Equal(t, []string{"1m"}, pe.Headers[headerBudgetWindow])

	var parsed budgetErrorBody
	require.NoError(t, json.Unmarshal(pe.Body, &parsed))
	assert.Equal(t, tokenBudgetExceeded, parsed.Error.Type)
	assert.Equal(t, "consumer", parsed.Error.Scope)
	assert.Equal(t, "1m", parsed.Error.Window)
}

func TestPlugin_Budget_DollarExceededBodyAndHeaders(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"unit":          "dollars",
		"pricing_table": "custom",
		"custom_pricing": map[string]any{
			"gpt-4o-mini": map[string]any{"input": 0.001, "output": 0},
		},
		"aggregate": map[string]any{"max": 0.005, "time_window": "1m"},
	}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"gpt-4o-mini"}`)}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: usageResponseBody()}

	_, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, req, resp))
	require.NoError(t, err)

	_, err = p.Execute(context.Background(), input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}))
	require.Error(t, err)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, 429, pe.StatusCode)
	assert.Equal(t, []string{"dollars"}, pe.Headers[headerBudgetUnit])
	assert.Equal(t, []string{"0.005000"}, pe.Headers[headerBudgetLimitUSD])
	_, hasTokenHeader := pe.Headers["X-Ratelimit-Limit-Tokens"]
	assert.False(t, hasTokenHeader, "the dollar path must not leak token-style headers")

	var parsed budgetErrorBody
	require.NoError(t, json.Unmarshal(pe.Body, &parsed))
	assert.Equal(t, dollarBudgetExceeded, parsed.Error.Type)
	assert.Equal(t, "consumer", parsed.Error.Scope)
	assert.Equal(t, "1m", parsed.Error.Window)
}

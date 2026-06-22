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

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	catalogmocks "github.com/NeuralTrust/TrustGate/pkg/app/catalog/mocks"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func usageResponseBody() []byte {
	return []byte(`{"id":"x","model":"m","choices":[{"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`)
}

func TestPlugin_PerModel_IsolatesBudgets(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"per_model": true,
		"rules": []map[string]any{
			{"model": "model-a", "max": 10, "time_window": "1m"},
			{"model": "model-b", "max": 10, "time_window": "1m"},
		},
	}
	reqA := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"model-a"}`)}
	reqB := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"model-b"}`)}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: usageResponseBody()}

	_, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, reqA, resp))
	require.NoError(t, err)

	_, err = p.Execute(context.Background(), input(policy.StagePreRequest, settings, reqA, &infracontext.ResponseContext{}))
	require.Error(t, err, "model-a is over its own budget")
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, 429, pe.StatusCode)

	_, err = p.Execute(context.Background(), input(policy.StagePreRequest, settings, reqB, &infracontext.ResponseContext{}))
	require.NoError(t, err, "model-b keeps an independent budget")
}

func TestPlugin_PerModel_HeadersReflectBreachedWindow(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"per_model": true,
		"rules":     []map[string]any{{"model": "model-a", "max": 5, "time_window": "1m"}},
		"aggregate": map[string]any{"max": 1000, "time_window": "1m"},
	}
	reqA := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"model-a"}`)}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: usageResponseBody()}

	_, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, reqA, resp))
	require.NoError(t, err)

	_, err = p.Execute(context.Background(), input(policy.StagePreRequest, settings, reqA, &infracontext.ResponseContext{}))
	require.Error(t, err)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, 429, pe.StatusCode)
	assert.Equal(t, []string{"5"}, pe.Headers["X-Ratelimit-Limit-Tokens"],
		"headers must reflect the breached per-model window (max 5), not the aggregate (max 1000)")
	assert.Equal(t, []string{"0"}, pe.Headers["X-Ratelimit-Remaining-Tokens"])
}

func TestPlugin_DollarBudget_AccrualAndGate(t *testing.T) {
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

	_, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}))
	require.NoError(t, err, "the first request must pass while the dollar counter is empty")

	_, err = p.Execute(context.Background(), input(policy.StagePostResponse, settings, req, resp))
	require.NoError(t, err)

	_, err = p.Execute(context.Background(), input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}))
	require.Error(t, err, "10 input tokens * $0.001 = $0.01 exceeds the $0.005 dollar budget")
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, 429, pe.StatusCode)
}

func TestPlugin_DollarBudget_PricesServedModelFromResponse(t *testing.T) {
	resolver := catalogmocks.NewPricingResolver(t)
	resolver.EXPECT().Resolve(mock.Anything, "openai", "gpt-4o-mini").
		Return(appcatalog.Pricing{}).Once()
	resolver.EXPECT().Resolve(mock.Anything, "openai", "gpt-4o-2024-08-06").
		Return(appcatalog.Pricing{Found: true, InputPrice: 0.001}).Once()
	p := newTestPluginWithPricing(t, resolver)

	settings := map[string]any{
		"unit":      "dollars",
		"aggregate": map[string]any{"max": 0.005, "time_window": "1m"},
	}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"gpt-4o-mini"}`)}
	respBody := []byte(`{"id":"x","model":"gpt-4o-2024-08-06","choices":[{"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":0,"total_tokens":10}}`)
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: respBody}

	_, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, req, resp))
	require.NoError(t, err)

	_, err = p.Execute(context.Background(), input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}))
	require.Error(t, err, "cost must accrue against the served response model (gpt-4o-2024-08-06), not be treated as unpriced")
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, 429, pe.StatusCode)
}

func TestPlugin_DollarBudget_UnpricedModelAccruesZero(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"unit":      "dollars",
		"aggregate": map[string]any{"max": 0.005, "time_window": "1m"},
	}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"gpt-4o-mini"}`)}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: usageResponseBody()}

	_, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, req, resp))
	require.NoError(t, err)

	_, err = p.Execute(context.Background(), input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}))
	require.NoError(t, err, "an unpriced model must accrue zero so the dollar gate never trips")
}

func TestPlugin_PerModel_CountingOutput(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"per_model": true,
		"counting":  "output",
		"rules": []map[string]any{
			{"model": "model-a", "max": 6, "time_window": "1m"},
		},
	}
	reqA := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"model-a"}`)}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: usageResponseBody()}

	res, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, reqA, resp))
	require.NoError(t, err)
	assert.Equal(t, []string{"5"}, res.Headers["X-Tokens-Consumed"], "only output tokens are counted")
}

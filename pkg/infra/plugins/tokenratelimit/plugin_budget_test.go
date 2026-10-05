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
	"net/http"
	"testing"
	"time"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	catalogmocks "github.com/NeuralTrust/TrustGate/pkg/app/catalog/mocks"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
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

func TestPlugin_DollarBudget_UsesRegistryOverride(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"unit":      "dollars",
		"aggregate": map[string]any{"max": 0.005, "time_window": "1m"},
	}
	req := &infracontext.RequestContext{
		Provider:     "openai",
		SourceFormat: "openai",
		Body:         []byte(`{"model":"gpt-4o-mini"}`),
		RegistryPricing: &domain.Pricing{
			Overrides: map[string]domain.PriceOverride{
				"gpt-4o-mini": {Input: 0.001, Output: 0},
			},
		},
	}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: usageResponseBody()}

	_, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, req, resp))
	require.NoError(t, err)

	_, err = p.Execute(context.Background(), input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}))
	require.Error(t, err, "10 input tokens * registry $0.001 = $0.01 exceeds the $0.005 dollar budget")
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

	_, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, reqA, resp))
	require.NoError(t, err)

	res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, reqA, &infracontext.ResponseContext{}))
	require.NoError(t, err)
	assert.Equal(t, []string{"1"}, res.Headers["X-Ratelimit-Remaining-Tokens"], "only output tokens are counted")
}

type keyOutcome struct {
	status   int
	errType  string
	scope    string
	decision string
	reason   string
	failure  string
}

func execKey(ctx context.Context, t *testing.T, p *Plugin, stage policy.Stage, mode policy.Mode, settings map[string]any, req *infracontext.RequestContext, resp *infracontext.ResponseContext) keyOutcome {
	t.Helper()
	span := trace.New("t", trace.Metadata{}).StartSpan(trace.SpanPlugin, PluginName)
	in := scopedInput(stage, settings, req, resp, aliceScope)
	in.Mode = mode
	in.Event = metrics.NewEventContext(span)
	res, err := p.Execute(ctx, in)
	attrs := span.PluginAttrsCopy()
	out := keyOutcome{decision: attrs.Decision}
	if data, ok := attrs.Extras.(TokenRateLimiterData); ok {
		out.reason, out.failure = data.FailureReason, data.FailureDetail
	}
	if pe, ok := appplugins.AsPluginError(err); ok {
		var body struct {
			Error struct {
				Type  string `json:"type"`
				Scope string `json:"scope"`
			} `json:"error"`
		}
		require.NoError(t, json.Unmarshal(pe.Body, &body))
		out.status, out.errType, out.scope = pe.StatusCode, body.Error.Type, body.Error.Scope
		return out
	}
	if err != nil {
		out.status = http.StatusInternalServerError
		return out
	}
	out.status = res.StatusCode
	return out
}

func newDownPlugin(t *testing.T) *Plugin {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1, DialerRetries: 1})
	t.Cleanup(func() { _ = rdb.Close() })
	mr.Close()
	return New(rdb, adapter.NewRegistry(), nil)
}

func keyDollarBudget(maxUSD float64) map[string]any {
	return map[string]any{"partition": "key", "unit": "dollars", "aggregate": map[string]any{"max": maxUSD, "time_window": "24h"}}
}

func registryPriced(model string) *infracontext.RequestContext {
	req := llmRequest(`{"model":"`+model+`"}`, nil)
	req.RegistryPricing = &domain.Pricing{Overrides: map[string]domain.PriceOverride{model: {Input: 0.001}}}
	return req
}

func TestPlugin_KeyPartition_CounterStoreDown(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	tokens := keyBudget("24h", 1000)
	unpriced := llmRequest(`{"model":"gpt-4o-mini"}`, nil)
	none := &infracontext.ResponseContext{}
	usage := &infracontext.ResponseContext{StatusCode: http.StatusOK, Body: usageResponseBody()}
	unavailable := string(appplugins.FailureCounterUnavailable)
	tests := []struct {
		name     string
		ctx      context.Context
		settings map[string]any
		stage    policy.Stage
		mode     policy.Mode
		req      *infracontext.RequestContext
		resp     *infracontext.ResponseContext
		want     keyOutcome
	}{
		{name: "enforce read fails closed", ctx: context.Background(), settings: tokens, stage: policy.StagePreRequest, mode: policy.ModeEnforce, req: unpriced, resp: none, want: keyOutcome{status: http.StatusServiceUnavailable, errType: budgetUnavailable, scope: partitionKey, decision: decisionFailedClosed, reason: unavailable, failure: "read_counter"}},
		{name: "observe read fails open", ctx: context.Background(), settings: tokens, stage: policy.StagePreRequest, mode: policy.ModeObserve, req: unpriced, resp: none, want: keyOutcome{status: http.StatusOK, decision: "failed_open", reason: unavailable, failure: "read_counter"}},
		{name: "enforce unpriced dollars rejects before the read", ctx: context.Background(), settings: keyDollarBudget(1), stage: policy.StagePreRequest, mode: policy.ModeEnforce, req: unpriced, resp: none, want: keyOutcome{status: http.StatusForbidden, errType: modelUnpriced, scope: partitionKey, decision: "block"}},
		{name: "observe unpriced dollars fails open", ctx: context.Background(), settings: keyDollarBudget(1), stage: policy.StagePreRequest, mode: policy.ModeObserve, req: unpriced, resp: none, want: keyOutcome{status: http.StatusOK, decision: "failed_open", reason: unavailable, failure: "read_counter"}},
		{name: "default partition fails open in enforce", ctx: context.Background(), settings: map[string]any{"aggregate": map[string]any{"max": 1000, "time_window": "24h"}}, stage: policy.StagePreRequest, mode: policy.ModeEnforce, req: unpriced, resp: none, want: keyOutcome{status: http.StatusOK, decision: "failed_open", reason: unavailable, failure: "read_counter"}},
		{name: "enforce token accrual logs and passes", ctx: context.Background(), settings: tokens, stage: policy.StagePostResponse, mode: policy.ModeEnforce, req: unpriced, resp: usage, want: keyOutcome{status: http.StatusOK, decision: "failed_open", reason: unavailable, failure: "record_tokens"}},
		{name: "enforce dollar accrual logs and passes", ctx: context.Background(), settings: keyDollarBudget(1), stage: policy.StagePostResponse, mode: policy.ModeEnforce, req: registryPriced("gpt-4o-mini"), resp: usage, want: keyOutcome{status: http.StatusOK, decision: "failed_open", reason: unavailable, failure: "record_cost"}},
		{name: "cancelled request keeps its error", ctx: cancelled, settings: tokens, stage: policy.StagePreRequest, mode: policy.ModeEnforce, req: unpriced, resp: none, want: keyOutcome{status: http.StatusInternalServerError}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := execKey(tt.ctx, t, newDownPlugin(t), tt.stage, tt.mode, tt.settings, tt.req, tt.resp)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPlugin_KeyPartition_UnpricedModel(t *testing.T) {
	unpriced := llmRequest(`{"model":"gpt-4o-mini"}`, nil)
	tests := []struct {
		name     string
		settings map[string]any
		mode     policy.Mode
		req      *infracontext.RequestContext
		want     keyOutcome
	}{
		{name: "dollars in enforce rejects", settings: keyDollarBudget(1), mode: policy.ModeEnforce, req: unpriced, want: keyOutcome{status: http.StatusForbidden, errType: modelUnpriced, scope: partitionKey, decision: "block"}},
		{name: "dollars in observe passes", settings: keyDollarBudget(1), mode: policy.ModeObserve, req: unpriced, want: keyOutcome{status: http.StatusOK, decision: "observe"}},
		{name: "tokens pass", settings: keyBudget("24h", 1000), mode: policy.ModeEnforce, req: unpriced, want: keyOutcome{status: http.StatusOK}},
		{name: "registry rate is priced", settings: keyDollarBudget(1), mode: policy.ModeEnforce, req: registryPriced("gpt-4o-mini"), want: keyOutcome{status: http.StatusOK}},
		{name: "no rule matches the model", settings: map[string]any{"partition": "key", "unit": "dollars", "rules": []map[string]any{{"model": "claude-*", "max": 1, "time_window": "24h"}}}, mode: policy.ModeEnforce, req: unpriced, want: keyOutcome{status: http.StatusOK}},
		{name: "cost cap only keeps its unknown model pass through", settings: map[string]any{"partition": "key", "unit": "dollars", "cost_cap": map[string]any{"enabled": true, "max_input_cost_per_1k_tokens": 0.5, "unknown_model": "pass_through"}}, mode: policy.ModeEnforce, req: unpriced, want: keyOutcome{status: http.StatusOK}},
		{name: "default partition passes", settings: map[string]any{"unit": "dollars", "aggregate": map[string]any{"max": 1, "time_window": "24h"}}, mode: policy.ModeEnforce, req: unpriced, want: keyOutcome{status: http.StatusOK}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := execKey(context.Background(), t, newTestPlugin(t), policy.StagePreRequest, tt.mode, tt.settings, tt.req, &infracontext.ResponseContext{})
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPlugin_KeyPartition_OverBudgetAnswers429WithKeyScope(t *testing.T) {
	tests := []struct {
		name      string
		settings  map[string]any
		req       *infracontext.RequestContext
		tokens    int
		counter   string
		wantSpent string
		wantType  string
	}{
		{name: "tokens", settings: keyBudget(windowCalendarMonth, 1000), req: llmRequest("", nil), tokens: 1000, counter: "trl:tk-1:key:owner:alice:p:2026-10", wantSpent: "1000", wantType: tokenBudgetExceeded},
		{name: "dollars priced by the registry", settings: keyDollarBudget(0.005), req: registryPriced("gpt-4o-mini"), tokens: 10, counter: "trl:tk-1:key:owner:alice", wantSpent: "10000", wantType: dollarBudgetExceeded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
			p, mr := newClockedPlugin(t, &now)
			spend(t, p, tt.settings, aliceScope, tt.req, tt.tokens)
			mr.CheckGet(t, tt.counter, tt.wantSpent)

			got := execKey(context.Background(), t, p, policy.StagePreRequest, policy.ModeEnforce, tt.settings, tt.req, &infracontext.ResponseContext{})
			assert.Equal(t, keyOutcome{status: http.StatusTooManyRequests, errType: tt.wantType, scope: partitionKey, decision: "block"}, got)
		})
	}
}

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

package metrics

import (
	"context"
	"testing"
	"time"

	appcatalog "github.com/NeuralTrust/AgentGateway/pkg/app/catalog"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubPricing struct {
	price appcatalog.Pricing
	byKey map[string]appcatalog.Pricing
}

func (s stubPricing) Resolve(_ context.Context, providerCode, slug string) appcatalog.Pricing {
	if s.byKey != nil {
		if p, ok := s.byKey[providerCode+":"+slug]; ok {
			return p
		}
	}
	return s.price
}

func newBuilder(price appcatalog.Pricing) *Builder {
	return NewBuilder(adapter.NewRegistry(), stubPricing{price: price})
}

func newBuilderWithPricing(byKey map[string]appcatalog.Pricing) *Builder {
	return NewBuilder(adapter.NewRegistry(), stubPricing{byKey: byKey})
}

func llmSpan(name string, attrs *trace.LLMAttrs, statusCode int, latency time.Duration, errMsg string) *trace.Span {
	span := &trace.Span{Type: trace.SpanLLM, Name: name, LLM: attrs}
	span.SetStatusCode(statusCode)
	span.SetLatency(latency)
	if errMsg != "" {
		span.SetError(errMsg)
	}
	return span
}

func pluginSpan(name string, attrs *trace.PluginAttrs, statusCode int, latency time.Duration, errMsg string) *trace.Span {
	span := &trace.Span{Type: trace.SpanPlugin, Name: name, Plugin: attrs}
	span.SetStatusCode(statusCode)
	span.SetLatency(latency)
	if errMsg != "" {
		span.SetError(errMsg)
	}
	return span
}

const openAIRequestBody = `{"model":"gpt-4o","temperature":0.7,"max_tokens":100,"stream":false,` +
	`"messages":[{"role":"user","content":"hello"}]}`

func TestBuilder_SetsTeamIDFromMetadata(t *testing.T) {
	rt := trace.New("trace-team", trace.Metadata{GatewayID: "gw-1", TeamID: "team-123"})

	req := &infracontext.RequestContext{GatewayID: "gw-1", Method: "POST", Path: "/v1/chat/completions"}
	resp := &infracontext.ResponseContext{StatusCode: 200}

	start := time.UnixMilli(1_000_000)
	evt := newBuilder(appcatalog.Pricing{}).Build(context.Background(), rt, req, resp, start, start.Add(time.Millisecond))

	assert.Equal(t, "team-123", evt.TeamID)
}

func TestBuilder_SyncSuccessFoldsCostAndLatency(t *testing.T) {
	rt := trace.New("trace-1", trace.Metadata{
		GatewayID:    "gw-1",
		ConsumerID:   "c-1",
		ConsumerName: "support-bot",
		SessionID:    "sess-1",
		IP:           "10.0.0.1",
	})
	_ = rt.AddSpan(pluginSpan("rate_limiter",
		&trace.PluginAttrs{Stage: "pre_request", Decision: "allow"}, 200, 6*time.Millisecond, ""))
	_ = rt.AddSpan(llmSpan("openai",
		&trace.LLMAttrs{
			RegistryID:   "reg-1",
			Provider:     "openai",
			Model:        "gpt-4o-2024-08-06",
			FinishReason: "stop",
			TurnID:       "chatcmpl-abc",
			Attempt:      1,
			Outcome:      "success",
			Usage:        &adapter.CanonicalUsage{InputTokens: 10, OutputTokens: 20, TotalTokens: 30},
		}, 200, 300*time.Millisecond, ""))

	req := &infracontext.RequestContext{
		GatewayID:    "gw-1",
		Method:       "POST",
		Path:         "/v1/chat/completions",
		Body:         []byte(openAIRequestBody),
		SourceFormat: string(adapter.FormatOpenAI),
	}
	respBody := `{"id":"x","choices":[]}`
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(respBody)}

	start := time.UnixMilli(1_000_000)
	end := start.Add(320 * time.Millisecond)

	b := newBuilder(appcatalog.Pricing{
		ModelLabel:  "GPT-4o",
		InputPrice:  0.0000025,
		OutputPrice: 0.00001,
		Found:       true,
	})
	evt := b.Build(context.Background(), rt, req, resp, start, end)

	assert.Equal(t, 2, evt.SchemaVersion)
	assert.Equal(t, "trace-1", evt.TraceID)
	assert.Equal(t, "gw-1", evt.GatewayID)
	assert.Equal(t, "c-1", evt.Consumer.ID)
	assert.Equal(t, "support-bot", evt.Consumer.Name)
	assert.Equal(t, "sess-1", evt.SessionID)
	assert.Equal(t, "chatcmpl-abc", evt.TurnID)

	assert.Equal(t, "openai", evt.Request.Provider)
	assert.Equal(t, "reg-1", evt.Request.RegistryID)
	assert.Equal(t, "gpt-4o-2024-08-06", evt.Request.Model)
	assert.Equal(t, "GPT-4o", evt.Request.ModelLabel)
	require.NotNil(t, evt.Request.Temperature)
	assert.InDelta(t, 0.7, *evt.Request.Temperature, 1e-9)
	assert.Equal(t, 100, evt.Request.MaxTokens)
	assert.False(t, evt.Request.Stream)
	assert.Equal(t, 10, evt.Request.PromptTokens)

	assert.Equal(t, 200, evt.Response.StatusCode)
	assert.Equal(t, "stop", evt.Response.FinishReason)
	assert.Equal(t, 20, evt.Response.CompletionTokens)
	require.NotNil(t, evt.Response.Body)
	assert.Equal(t, respBody, *evt.Response.Body)

	require.NotNil(t, evt.Usage)
	assert.Equal(t, 30, evt.Usage.TotalTokens)

	require.NotNil(t, evt.Cost)
	assert.InDelta(t, 10*0.0000025, float64(evt.Cost.PromptUsd), 1e-12)
	assert.InDelta(t, 20*0.00001, float64(evt.Cost.CompletionUsd), 1e-12)
	assert.InDelta(t, 10*0.0000025+20*0.00001, float64(evt.Cost.TotalUsd), 1e-12)
	assert.Equal(t, "USD", evt.Cost.Currency)

	assert.Equal(t, int64(320), evt.Latency.TotalMs)
	assert.Equal(t, int64(300), evt.Latency.ProviderMs)
	assert.Equal(t, int64(6), evt.Latency.PoliciesMs)
	assert.Equal(t, int64(14), evt.Latency.RoutingMs)
	assert.Equal(t, int64(20), evt.Latency.GatewayMs)

	require.Len(t, evt.Attempts, 1)
	assert.Equal(t, "openai", evt.Attempts[0].Provider)
	require.Len(t, evt.PolicyChain, 1)
	assert.Equal(t, "rate_limiter", evt.PolicyChain[0].Name)
	assert.False(t, evt.PolicyChain[0].Flagged)
	assert.False(t, evt.IsFlagged)
}

func TestBuilder_CostUsesRequestedModelForPricingLookup(t *testing.T) {
	rt := trace.New("trace-pricing", trace.Metadata{GatewayID: "gw-1"})
	_ = rt.AddSpan(llmSpan("openai",
		&trace.LLMAttrs{
			Provider:       "openai",
			Model:          "gpt-4o-mini-2024-07-18",
			RequestedModel: "gpt-4o-mini",
			FinishReason:   "stop",
			Attempt:        1,
			Outcome:        "success",
			Usage:          &adapter.CanonicalUsage{InputTokens: 11, OutputTokens: 12, TotalTokens: 23},
		}, 200, 300*time.Millisecond, ""))

	req := &infracontext.RequestContext{
		GatewayID:      "gw-1",
		Method:         "POST",
		Path:           "/v1/chat/completions",
		RequestedModel: "gpt-4o-mini",
		Body:           []byte(openAIRequestBody),
		SourceFormat:   string(adapter.FormatOpenAI),
	}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"id":"x","choices":[]}`)}

	start := time.UnixMilli(1_000_000)
	end := start.Add(320 * time.Millisecond)

	b := newBuilder(appcatalog.Pricing{
		InputPrice:  0.00000015,
		OutputPrice: 0.0000006,
		Found:       true,
	})
	evt := b.Build(context.Background(), rt, req, resp, start, end)

	require.NotNil(t, evt.Cost)
	assert.InDelta(t, 11*0.00000015, float64(evt.Cost.PromptUsd), 1e-12)
	assert.InDelta(t, 12*0.0000006, float64(evt.Cost.CompletionUsd), 1e-12)
	assert.Equal(t, "gpt-4o-mini-2024-07-18", evt.Request.Model)
	assert.Equal(t, "gpt-4o-mini", evt.Request.RequestedModel)
}

func TestBuilder_CostUsesServedModelWhenLBChangesModel(t *testing.T) {
	rt := trace.New("trace-lb", trace.Metadata{GatewayID: "gw-1"})
	_ = rt.AddSpan(llmSpan("openai",
		&trace.LLMAttrs{
			Provider:       "openai",
			Model:          "gpt-4o-2024-08-06",
			RequestedModel: "gpt-4o-mini",
			FinishReason:   "stop",
			Attempt:        1,
			Outcome:        "success",
			Usage:          &adapter.CanonicalUsage{InputTokens: 10, OutputTokens: 20, TotalTokens: 30},
		}, 200, 300*time.Millisecond, ""))

	req := &infracontext.RequestContext{
		GatewayID:      "gw-1",
		RequestedModel: "gpt-4o-mini",
		Body:           []byte(openAIRequestBody),
		SourceFormat:   string(adapter.FormatOpenAI),
	}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"id":"x","choices":[]}`)}

	b := newBuilderWithPricing(map[string]appcatalog.Pricing{
		"openai:gpt-4o-mini": {Found: false},
		"openai:gpt-4o-2024-08-06": {
			Found:       true,
			InputPrice:  0.0000025,
			OutputPrice: 0.00001,
		},
	})
	evt := b.Build(context.Background(), rt, req, resp, time.UnixMilli(1), time.UnixMilli(2))

	require.NotNil(t, evt.Cost)
	assert.InDelta(t, 10*0.0000025, float64(evt.Cost.PromptUsd), 1e-12)
	assert.InDelta(t, 20*0.00001, float64(evt.Cost.CompletionUsd), 1e-12)
}

func TestBuilder_CostUsesServedModelForPoolRouting(t *testing.T) {
	rt := trace.New("trace-pool", trace.Metadata{GatewayID: "gw-1"})
	_ = rt.AddSpan(llmSpan("openai",
		&trace.LLMAttrs{
			Provider:       "openai",
			Model:          "gpt-4o-mini-2024-07-18",
			RequestedModel: "pool:fast-chat",
			FinishReason:   "stop",
			Attempt:        1,
			Outcome:        "success",
			Usage:          &adapter.CanonicalUsage{InputTokens: 11, OutputTokens: 12, TotalTokens: 23},
		}, 200, 300*time.Millisecond, ""))

	req := &infracontext.RequestContext{
		GatewayID:      "gw-1",
		RequestedModel: "pool:fast-chat",
		Body:           []byte(openAIRequestBody),
		SourceFormat:   string(adapter.FormatOpenAI),
	}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"id":"x","choices":[]}`)}

	b := newBuilderWithPricing(map[string]appcatalog.Pricing{
		"openai:pool:fast-chat": {Found: false},
		"openai:gpt-4o-mini-2024-07-18": {Found: false},
		"openai:gpt-4o-mini": {
			Found:       true,
			InputPrice:  0.00000015,
			OutputPrice: 0.0000006,
		},
	})
	evt := b.Build(context.Background(), rt, req, resp, time.UnixMilli(1), time.UnixMilli(2))

	require.NotNil(t, evt.Cost)
	assert.InDelta(t, 11*0.00000015, float64(evt.Cost.PromptUsd), 1e-12)
}

func TestBuilder_TimeoutHasNilBody(t *testing.T) {
	rt := trace.New("trace-2", trace.Metadata{GatewayID: "gw-1"})
	_ = rt.AddSpan(llmSpan("openai",
		&trace.LLMAttrs{Provider: "openai", Attempt: 1, Outcome: "timeout"},
		408, 30*time.Second, "deadline exceeded"))

	req := &infracontext.RequestContext{GatewayID: "gw-1", Body: []byte(openAIRequestBody), SourceFormat: string(adapter.FormatOpenAI)}
	resp := &infracontext.ResponseContext{StatusCode: 408, Body: nil}

	start := time.UnixMilli(2_000_000)
	end := start.Add(30 * time.Second)

	evt := newBuilder(appcatalog.Pricing{}).Build(context.Background(), rt, req, resp, start, end)

	assert.Nil(t, evt.Response.Body)
	assert.True(t, evt.Status.IsTimeout)
	assert.Equal(t, 408, evt.Status.Code)
	assert.Nil(t, evt.Usage)
	assert.Nil(t, evt.Cost)
}

func TestBuilder_FailoverAttemptsAndFlaggedPlugin(t *testing.T) {
	rt := trace.New("trace-3", trace.Metadata{GatewayID: "gw-1"})
	_ = rt.AddSpan(llmSpan("openai",
		&trace.LLMAttrs{Provider: "openai", RegistryID: "reg-1", Attempt: 1, Fallback: false, Outcome: "error"},
		500, 100*time.Millisecond, "upstream 500"))
	_ = rt.AddSpan(llmSpan("anthropic",
		&trace.LLMAttrs{
			Provider: "anthropic", RegistryID: "reg-2", Model: "claude", Attempt: 2, Fallback: true, Outcome: "success",
			Usage: &adapter.CanonicalUsage{InputTokens: 5, OutputTokens: 5, TotalTokens: 10},
		}, 200, 200*time.Millisecond, ""))
	_ = rt.AddSpan(pluginSpan("toxicity_guard",
		&trace.PluginAttrs{Stage: "pre_request", Decision: "block", ScoreLabel: "toxicity"}, 200, 8*time.Millisecond, ""))

	req := &infracontext.RequestContext{GatewayID: "gw-1", Body: []byte(openAIRequestBody), SourceFormat: string(adapter.FormatOpenAI)}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"ok":true}`)}

	start := time.UnixMilli(3_000_000)
	end := start.Add(330 * time.Millisecond)

	evt := newBuilder(appcatalog.Pricing{}).Build(context.Background(), rt, req, resp, start, end)

	require.Len(t, evt.Attempts, 2)
	assert.True(t, evt.Attempts[1].Fallback)
	assert.Equal(t, int64(300), evt.Latency.ProviderMs)

	require.Len(t, evt.PolicyChain, 1)
	assert.True(t, evt.PolicyChain[0].Flagged)
	assert.True(t, evt.IsFlagged)
	assert.Equal(t, []string{"toxicity"}, evt.Security)

	assert.Equal(t, "anthropic", evt.Request.Provider)
	assert.Equal(t, "claude", evt.Request.Model)
}

func TestBuilder_PinnedAttemptIsVisible(t *testing.T) {
	rt := trace.New("trace-4", trace.Metadata{GatewayID: "gw-1"})
	_ = rt.AddSpan(llmSpan("anthropic",
		&trace.LLMAttrs{Provider: "anthropic", RegistryID: "reg-1", Attempt: 1, Pinned: true, Outcome: "success"},
		200, 50*time.Millisecond, ""))

	req := &infracontext.RequestContext{GatewayID: "gw-1", Body: []byte(openAIRequestBody), SourceFormat: string(adapter.FormatOpenAI)}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"ok":true}`)}

	start := time.UnixMilli(4_000_000)
	evt := newBuilder(appcatalog.Pricing{}).Build(context.Background(), rt, req, resp, start, start.Add(60*time.Millisecond))

	require.Len(t, evt.Attempts, 1)
	assert.True(t, evt.Attempts[0].Pinned)
}

func TestBuilder_StatusReasonFromTrace(t *testing.T) {
	rt := trace.New("trace-5", trace.Metadata{GatewayID: "gw-1"})
	rt.SetStatusReason("model_not_allowed")

	req := &infracontext.RequestContext{GatewayID: "gw-1", Body: []byte(openAIRequestBody), SourceFormat: string(adapter.FormatOpenAI)}
	resp := &infracontext.ResponseContext{StatusCode: 403}

	start := time.UnixMilli(5_000_000)
	evt := newBuilder(appcatalog.Pricing{}).Build(context.Background(), rt, req, resp, start, start.Add(5*time.Millisecond))

	assert.Equal(t, 403, evt.Status.Code)
	assert.Equal(t, "model_not_allowed", evt.Status.Reason)
}

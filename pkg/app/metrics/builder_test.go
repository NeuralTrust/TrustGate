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
}

func (s stubPricing) Resolve(_ context.Context, _ string, _ string) appcatalog.Pricing {
	return s.price
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

func newBuilder(price appcatalog.Pricing) *Builder {
	return NewBuilder(adapter.NewRegistry(), stubPricing{price: price})
}

const openAIRequestBody = `{"model":"gpt-4o","temperature":0.7,"max_tokens":100,"stream":false,` +
	`"messages":[{"role":"user","content":"hello"}]}`

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
		Headers:      map[string][]string{"X-Conversation-Id": {"conv-9"}},
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
	assert.Equal(t, "conv-9", evt.ConversationID)

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
	assert.InDelta(t, 10*0.0000025, evt.Cost.PromptUsd, 1e-12)
	assert.InDelta(t, 20*0.00001, evt.Cost.CompletionUsd, 1e-12)
	assert.InDelta(t, 10*0.0000025+20*0.00001, evt.Cost.TotalUsd, 1e-12)
	assert.Equal(t, "USD", evt.Cost.Currency)

	assert.Equal(t, int64(320), evt.Latency.TotalMs)
	assert.Equal(t, int64(300), evt.Latency.ProviderMs)
	assert.Equal(t, int64(6), evt.Latency.PluginsMs)
	assert.Equal(t, int64(14), evt.Latency.RoutingMs)
	assert.Equal(t, int64(20), evt.Latency.GatewayMs)

	require.Len(t, evt.Attempts, 1)
	assert.Equal(t, "openai", evt.Attempts[0].Provider)
	require.Len(t, evt.PluginChain, 1)
	assert.Equal(t, "rate_limiter", evt.PluginChain[0].Name)
	assert.False(t, evt.PluginChain[0].Flagged)
	assert.False(t, evt.IsFlagged)
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

	require.Len(t, evt.PluginChain, 1)
	assert.True(t, evt.PluginChain[0].Flagged)
	assert.True(t, evt.IsFlagged)
	assert.Equal(t, []string{"toxicity"}, evt.Security)

	assert.Equal(t, "anthropic", evt.Request.Provider)
	assert.Equal(t, "claude", evt.Request.Model)
}

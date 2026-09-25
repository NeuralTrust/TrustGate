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

package adapter

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const openRouterResponseWithProvider = `{
  "id": "gen-or-1",
  "object": "chat.completion",
  "model": "anthropic/claude-sonnet-4",
  "provider": "Anthropic",
  "choices": [{
    "index": 0,
    "message": {"role": "assistant", "content": "hello"},
    "finish_reason": "stop"
  }],
  "usage": {
    "prompt_tokens": 10,
    "completion_tokens": 5,
    "total_tokens": 15
  }
}`

const openRouterStreamFinalChunk = `{
  "id": "gen-or-stream",
  "object": "chat.completion.chunk",
  "model": "anthropic/claude-sonnet-4",
  "provider": "Anthropic",
  "choices": [{
    "index": 0,
    "delta": {},
    "finish_reason": "stop"
  }],
  "usage": {
    "prompt_tokens": 10,
    "completion_tokens": 5,
    "total_tokens": 15
  }
}`

const openRouterChatRequest = `{
  "model": "anthropic/claude-sonnet-4",
  "messages": [{"role": "user", "content": "hi"}],
  "provider": {"order": ["Anthropic"]},
  "models": ["anthropic/claude-sonnet-4", "openai/gpt-4o"],
  "transforms": ["middle-out"],
  "route": "fallback",
  "max_tokens": 128
}`

func openRouterAdapter(t *testing.T) ProviderAdapter {
	t.Helper()
	a, err := NewRegistry().GetAdapter(FormatOpenRouter)
	require.NoError(t, err)
	return a
}

func TestOpenRouterAdapter_FormatRegistration(t *testing.T) {
	assert.Equal(t, Format("openrouter"), FormatOpenRouter)

	reg := NewRegistry()
	_, err := reg.GetAdapter(FormatOpenRouter)
	require.NoError(t, err)

	assert.Equal(t, FormatOpenRouter, ResolveTargetFormat("openrouter", nil))

	got, err := ResolveAgentFormat("openrouter", "", nil)
	require.NoError(t, err)
	assert.Equal(t, FormatOpenRouter, got)

	assert.True(t, IsSameWireFormat(FormatOpenRouter, FormatOpenAI))
	assert.True(t, IsSameWireFormat(FormatOpenAI, FormatOpenRouter))

	assert.True(t, ShouldPassthroughSameWireFormat(FormatOpenRouter, FormatOpenRouter))
	assert.False(t, ShouldPassthroughSameWireFormat(FormatOpenAI, FormatOpenRouter))
	assert.False(t, ShouldPassthroughSameWireFormat(FormatOpenRouter, FormatOpenAI))
	assert.True(t, ShouldPassthroughRequest(FormatOpenAI, FormatOpenRouter))
	assert.False(t, ShouldPassthroughRequest(FormatAnthropic, FormatOpenRouter))

	opts := map[string]any{"api": "responses"}
	assert.Equal(t, FormatOpenAIResponses, ResolveTargetFormat("openai", opts))
	assert.Equal(t, FormatOpenRouter, ResolveTargetFormat("openrouter", opts))
}

func TestOpenRouterAdapter_RoundTripPreservesRequestExtensions(t *testing.T) {
	a := openRouterAdapter(t)

	cr, err := a.DecodeRequest([]byte(openRouterChatRequest))
	require.NoError(t, err)
	require.NotNil(t, cr.RequestExtensions["provider"])
	require.NotNil(t, cr.RequestExtensions["models"])
	require.NotNil(t, cr.RequestExtensions["transforms"])
	require.NotNil(t, cr.RequestExtensions["route"])

	encoded, err := a.EncodeRequest(cr)
	require.NoError(t, err)

	var parsed map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encoded, &parsed))
	require.NotNil(t, parsed["provider"])
	require.NotNil(t, parsed["models"])
	require.NotNil(t, parsed["transforms"])
	require.NotNil(t, parsed["route"])
}

func TestOpenRouterAdapter_RoundTripPreservesProviderMetadata(t *testing.T) {
	a := openRouterAdapter(t)

	canonical, err := a.DecodeResponse([]byte(openRouterResponseWithProvider))
	require.NoError(t, err)
	require.NotNil(t, canonical.ProviderExtensions["provider"])

	encoded, err := a.EncodeResponse(canonical)
	require.NoError(t, err)

	var parsed map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encoded, &parsed))
	require.NotNil(t, parsed["provider"])

	var provider string
	require.NoError(t, json.Unmarshal(parsed["provider"], &provider))
	assert.Equal(t, "Anthropic", provider)
}

func TestOpenRouterAdapter_StreamFinalChunkPreservesProvider(t *testing.T) {
	a := openRouterAdapter(t)

	canonical, err := a.DecodeStreamChunk([]byte(openRouterStreamFinalChunk))
	require.NoError(t, err)
	require.NotNil(t, canonical)
	require.NotNil(t, canonical.Usage)
	assert.Equal(t, 15, canonical.Usage.TotalTokens)
	require.NotNil(t, canonical.ProviderExtensions["provider"])

	lines, err := a.EncodeStreamChunk(canonical)
	require.NoError(t, err)
	require.NotEmpty(t, lines)

	var dataLine string
	for _, line := range lines {
		if bytes.HasPrefix(line, []byte("data: ")) {
			dataLine = string(line)
			break
		}
	}
	require.NotEmpty(t, dataLine)
	payload := strings.TrimPrefix(dataLine, "data: ")

	var parsed map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(payload), &parsed))
	require.NotNil(t, parsed["provider"])
	require.NotNil(t, parsed["usage"])
}

func TestOpenRouterAdapter_ReportedCostIsLoggedNotBilled(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	const usage = `{"prompt_tokens":1000,"completion_tokens":10,"total_tokens":1010,"cost":0.0042,"cache_discount":0.0021,"prompt_tokens_details":{"cached_tokens":900}}`
	want := &CanonicalUsage{InputTokens: 1000, OutputTokens: 10, TotalTokens: 1010, CachedInputTokens: 900}
	a := openRouterAdapter(t)

	cr, err := a.DecodeResponse([]byte(`{"id":"gen-1","object":"chat.completion","model":"anthropic/claude-sonnet-4","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":` + usage + `}`))
	require.NoError(t, err)
	assert.Equal(t, want, cr.Usage)

	sc, err := a.DecodeStreamChunk([]byte(`data: {"id":"gen-1","object":"chat.completion.chunk","choices":[],"usage":` + usage + `}`))
	require.NoError(t, err)
	require.NotNil(t, sc)
	assert.Equal(t, want, sc.Usage)

	assert.Equal(t, 2, strings.Count(logs.String(), "openrouter reported billing"))
	assert.Contains(t, logs.String(), "cost=0.0042")
	assert.Contains(t, logs.String(), "cache_discount=0.0021")
}

func TestOpenRouterAdapter_TopLevelCacheDiscountIsLogged(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	a := openRouterAdapter(t)
	cr, err := a.DecodeResponse([]byte(`{"id":"gen-1","object":"chat.completion","model":"anthropic/claude-sonnet-4","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"cache_discount":0.0017,"usage":{"prompt_tokens":1000,"completion_tokens":10,"total_tokens":1010}}`))
	require.NoError(t, err)
	assert.Equal(t, &CanonicalUsage{InputTokens: 1000, OutputTokens: 10, TotalTokens: 1010}, cr.Usage)

	assert.Equal(t, 1, strings.Count(logs.String(), "openrouter reported billing"))
	assert.Contains(t, logs.String(), "cache_discount=0.0017")
	assert.NotContains(t, logs.String(), "cost=")
}

func TestOpenRouterAdapter_NoBillingFieldsNoLog(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	const usage = `{"prompt_tokens":1000,"completion_tokens":10,"total_tokens":1010}`
	a := openRouterAdapter(t)
	cr, err := a.DecodeResponse([]byte(`{"id":"gen-1","object":"chat.completion","model":"anthropic/claude-sonnet-4","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":` + usage + `}`))
	require.NoError(t, err)
	require.NotNil(t, cr.Usage)

	sc, err := a.DecodeStreamChunk([]byte(`data: {"id":"gen-1","object":"chat.completion.chunk","choices":[],"usage":` + usage + `}`))
	require.NoError(t, err)
	require.NotNil(t, sc)
	require.NotNil(t, sc.Usage)

	assert.NotContains(t, logs.String(), "openrouter reported billing")
}

func TestOpenRouterAdapter_DecodeStreamChunk_SkipsSSEComments(t *testing.T) {
	a := openRouterAdapter(t)

	for _, line := range []string{
		": OPENROUTER PROCESSING",
		": ping",
		" : ping ",
	} {
		sc, err := a.DecodeStreamChunk([]byte(line))
		require.NoError(t, err)
		assert.Nil(t, sc, "line %q", line)
	}

	sc, err := a.DecodeStreamChunk([]byte(`data: {"choices":[{"delta":{"content":"ok"}}]}`))
	require.NoError(t, err)
	require.NotNil(t, sc)
	assert.Equal(t, "ok", sc.Delta)
}

func TestOpenRouterAdapter_CrossFormatDropsRequestExtensions(t *testing.T) {
	out, err := NewRegistry().AdaptRequest([]byte(openRouterChatRequest), FormatAnthropic, FormatOpenRouter)
	require.NoError(t, err)
	assert.NotContains(t, string(out), `"models"`)
	assert.NotContains(t, string(out), `"transforms"`)
	assert.NotContains(t, string(out), `"route"`)

	var probe struct {
		Provider json.RawMessage `json:"provider"`
	}
	require.NoError(t, json.Unmarshal(out, &probe))
	assert.Nil(t, probe.Provider)
}

func TestOpenRouterAdapter_CrossFormatDropsProviderMetadata(t *testing.T) {
	out, err := NewRegistry().AdaptResponse([]byte(openRouterResponseWithProvider), FormatAnthropic, FormatOpenRouter)
	require.NoError(t, err)
	assert.NotContains(t, string(out), `"provider"`)

	var probe struct {
		Type string `json:"type"`
	}
	require.NoError(t, json.Unmarshal(out, &probe))
	assert.Equal(t, "message", probe.Type)
}

func TestOpenRouterAdapter_CrossFormatDropsProviderMetadataToOpenAI(t *testing.T) {
	out, err := NewRegistry().AdaptResponse([]byte(openRouterResponseWithProvider), FormatOpenAI, FormatOpenRouter)
	require.NoError(t, err)
	assert.NotContains(t, string(out), `"provider"`)

	var parsed struct {
		Object  string          `json:"object"`
		Choices json.RawMessage `json:"choices"`
	}
	require.NoError(t, json.Unmarshal(out, &parsed))
	assert.Equal(t, "chat.completion", parsed.Object)
	require.NotNil(t, parsed.Choices)
}

func TestOpenRouterAdapter_CrossFormatDropsProviderMetadataStream(t *testing.T) {
	lines, err := NewRegistry().AdaptStreamChunk([]byte(openRouterStreamFinalChunk), FormatOpenAI, FormatOpenRouter)
	require.NoError(t, err)
	require.NotEmpty(t, lines)

	combined := ""
	for _, line := range lines {
		combined += string(line) + "\n"
	}
	assert.NotContains(t, combined, `"provider"`)
	assert.Contains(t, combined, "usage")
	assert.Contains(t, combined, "data: ")
}

func TestOpenRouterAdapter_RequestMappings(t *testing.T) {
	reg := NewRegistry()
	a, err := reg.GetAdapter(FormatOpenRouter)
	require.NoError(t, err)

	t.Run("provider to canonical request", func(t *testing.T) {
		cr, err := a.DecodeRequest([]byte(openRouterChatRequest))
		require.NoError(t, err)
		assert.Equal(t, "anthropic/claude-sonnet-4", cr.Model)
		require.Len(t, cr.Messages, 1)
		assert.Equal(t, "user", cr.Messages[0].Role)
		require.NotNil(t, cr.RequestExtensions["route"])
	})

	t.Run("canonical to provider request", func(t *testing.T) {
		cr, err := a.DecodeRequest([]byte(openRouterChatRequest))
		require.NoError(t, err)

		encoded, err := a.EncodeRequest(cr)
		require.NoError(t, err)

		var parsed map[string]any
		require.NoError(t, json.Unmarshal(encoded, &parsed))
		assert.Equal(t, "anthropic/claude-sonnet-4", parsed["model"])
		assert.Equal(t, "fallback", parsed["route"])
	})

	t.Run("provider to canonical response", func(t *testing.T) {
		cr, err := a.DecodeResponse([]byte(openRouterResponseWithProvider))
		require.NoError(t, err)
		require.NotNil(t, cr.ProviderExtensions["provider"])
		assert.Equal(t, "hello", cr.Content)
	})

	t.Run("canonical to provider response", func(t *testing.T) {
		cr, err := a.DecodeResponse([]byte(openRouterResponseWithProvider))
		require.NoError(t, err)

		encoded, err := a.EncodeResponse(cr)
		require.NoError(t, err)
		assert.Contains(t, string(encoded), `"provider"`)
	})

	t.Run("provider to canonical stream", func(t *testing.T) {
		sc, err := a.DecodeStreamChunk([]byte(openRouterStreamFinalChunk))
		require.NoError(t, err)
		require.NotNil(t, sc)
		require.NotNil(t, sc.ProviderExtensions["provider"])
		require.NotNil(t, sc.Usage)
	})

	t.Run("canonical to provider stream", func(t *testing.T) {
		sc, err := a.DecodeStreamChunk([]byte(openRouterStreamFinalChunk))
		require.NoError(t, err)

		lines, err := a.EncodeStreamChunk(sc)
		require.NoError(t, err)
		combined := string(lines[0])
		for _, line := range lines[1:] {
			combined += string(line)
		}
		assert.Contains(t, combined, `"provider"`)
	})
}

func TestOpenRouterAdapter_OpenAIRequestPassesThroughUnchanged(t *testing.T) {
	body := []byte(`{"model":"anthropic/claude-sonnet-4","session_id":"s-1","seed":3,"cache_control":{"type":"ephemeral"},` +
		`"provider":{"order":["Anthropic"],"allow_fallbacks":false},"models":["anthropic/claude-sonnet-4","openai/gpt-4o"],"transforms":["middle-out"],"route":"fallback",` +
		`"messages":[{"role":"system","content":[{"type":"text","text":"Long prefix.","cache_control":{"type":"ephemeral","ttl":"1h"}}]},{"role":"user","content":"hi"}]}`)

	out, err := NewRegistry().AdaptRequestForProvider(body, FormatOpenAI, FormatOpenRouter, "openrouter", "")
	require.NoError(t, err)
	assert.Equal(t, string(body), string(out))
}

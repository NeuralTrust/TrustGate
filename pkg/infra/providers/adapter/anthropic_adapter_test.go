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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Canonical roundtrip: Anthropic → Canonical → Anthropic
// ---------------------------------------------------------------------------

func TestCanonical_Anthropic_Roundtrip(t *testing.T) {
	input := `{
		"model": "claude-3-sonnet",
		"system": "You are helpful.",
		"messages": [
			{"role": "user", "content": "Hello"}
		],
		"max_tokens": 100,
		"temperature": 0.7
	}`

	adapter := &AnthropicAdapter{}

	canonical, err := adapter.DecodeRequest([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, "claude-3-sonnet", canonical.Model)
	assert.Equal(t, "You are helpful.", canonical.System)
	assert.Len(t, canonical.Messages, 1)
	assert.Equal(t, 100, canonical.MaxTokens)

	encoded, err := adapter.EncodeRequest(canonical)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(encoded, &result))
	assert.Equal(t, "You are helpful.", result["system"])
	msgs := result["messages"].([]interface{})
	assert.Len(t, msgs, 1)
}

// ---------------------------------------------------------------------------
// Real Anthropic request with stream + tools
// ---------------------------------------------------------------------------

func TestCanonical_Anthropic_RealRequest_WithStreamAndTools(t *testing.T) {
	input := `{
		"max_tokens": 64000,
		"messages": [{"role": "user", "content": "buscame en la base de datos el cliente Juan"}],
		"model": "claude-sonnet-4-20250514",
		"stream": true,
		"system": "You are an orchestrator.",
		"tools": [
			{
				"name": "database_agent",
				"input_schema": {
					"properties": {"query": {"type": "string"}},
					"required": ["query"],
					"type": "object"
				},
				"description": "Query the Postgres database."
			}
		]
	}`

	adapter := &AnthropicAdapter{}

	canonical, err := adapter.DecodeRequest([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, "claude-sonnet-4-20250514", canonical.Model)
	assert.Equal(t, "You are an orchestrator.", canonical.System)
	assert.True(t, canonical.Stream, "stream should be true")
	assert.Equal(t, 64000, canonical.MaxTokens)
	assert.Len(t, canonical.Messages, 1)
	assert.Equal(t, "buscame en la base de datos el cliente Juan", canonical.Messages[0].Content)
	assert.Len(t, canonical.Tools, 1)
	assert.Equal(t, "database_agent", canonical.Tools[0].Name)

	// Roundtrip: encode back to Anthropic
	encoded, err := adapter.EncodeRequest(canonical)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(encoded, &result))

	assert.Equal(t, "claude-sonnet-4-20250514", result["model"])
	assert.Equal(t, "You are an orchestrator.", result["system"])
	assert.Equal(t, true, result["stream"])
	assert.Equal(t, float64(64000), result["max_tokens"])

	// Cross-provider: Anthropic → OpenAI (should preserve stream)
	openaiBody, err := testRegistry().AdaptRequest([]byte(input), FormatAnthropic, FormatOpenAI)
	require.NoError(t, err)

	var openaiResult map[string]interface{}
	require.NoError(t, json.Unmarshal(openaiBody, &openaiResult))

	assert.Equal(t, true, openaiResult["stream"])
	msgs := openaiResult["messages"].([]interface{})
	assert.Len(t, msgs, 2) // system re-injected + user
	tools := openaiResult["tools"].([]interface{})
	assert.Len(t, tools, 1)
	tool := tools[0].(map[string]interface{})
	assert.Equal(t, "function", tool["type"])
}

// ---------------------------------------------------------------------------
// Anthropic tool_use response: real-world payload
// ---------------------------------------------------------------------------

func TestAnthropic_DecodeResponse_ToolUse_RealPayload(t *testing.T) {
	// Exact payload from Anthropic Claude.
	body := `{
		"model": "claude-sonnet-4-20250514",
		"id": "msg_015uW5QLWaDeLdqegC29faCw",
		"type": "message",
		"role": "assistant",
		"content": [{
			"type": "tool_use",
			"id": "toolu_016u41qZE8fBygCBmSxapu7x",
			"name": "database_agent",
			"input": {
				"query": "Buscar cliente con nombre Juan"
			}
		}],
		"stop_reason": "tool_use",
		"stop_sequence": null,
		"usage": {
			"input_tokens": 1030,
			"cache_creation_input_tokens": 0,
			"cache_read_input_tokens": 0,
			"cache_creation": {
				"ephemeral_5m_input_tokens": 0,
				"ephemeral_1h_input_tokens": 0
			},
			"output_tokens": 86,
			"service_tier": "standard",
			"inference_geo": "not_available"
		}
	}`

	adapter := &AnthropicAdapter{}

	// Decode to canonical
	cr, err := adapter.DecodeResponse([]byte(body))
	require.NoError(t, err)

	// ID, Model, Role
	assert.Equal(t, "msg_015uW5QLWaDeLdqegC29faCw", cr.ID)
	assert.Equal(t, "claude-sonnet-4-20250514", cr.Model)
	assert.Equal(t, "assistant", cr.Role)

	// Content should be empty (no text blocks)
	assert.Equal(t, "", cr.Content)

	// Tool calls
	require.Len(t, cr.ToolCalls, 1)
	assert.Equal(t, "toolu_016u41qZE8fBygCBmSxapu7x", cr.ToolCalls[0].ID)
	assert.Equal(t, "database_agent", cr.ToolCalls[0].Name)
	assert.Contains(t, cr.ToolCalls[0].Arguments, "Buscar cliente con nombre Juan")

	// FinishReason: tool_use → tool_calls
	assert.Equal(t, "tool_calls", cr.FinishReason)

	// Usage — core tokens
	require.NotNil(t, cr.Usage)
	assert.Equal(t, 1030, cr.Usage.InputTokens)
	assert.Equal(t, 86, cr.Usage.OutputTokens)
	assert.Equal(t, 1116, cr.Usage.TotalTokens)

	// Usage — cache/billing pass-through
	assert.Equal(t, 0, cr.Usage.CacheWriteInputTokens)
	assert.Equal(t, 0, cr.Usage.CachedInputTokens)
	assert.Equal(t, "standard", cr.Usage.ServiceTier)

	// Roundtrip: canonical → Anthropic → canonical
	encoded, err := adapter.EncodeResponse(cr)
	require.NoError(t, err)

	cr2, err := adapter.DecodeResponse(encoded)
	require.NoError(t, err)

	assert.Equal(t, cr.ID, cr2.ID)
	assert.Equal(t, cr.Model, cr2.Model)
	assert.Equal(t, cr.FinishReason, cr2.FinishReason)
	require.Len(t, cr2.ToolCalls, 1)
	assert.Equal(t, cr.ToolCalls[0].ID, cr2.ToolCalls[0].ID)
	assert.Equal(t, cr.ToolCalls[0].Name, cr2.ToolCalls[0].Name)
	assert.Equal(t, cr.Usage.ServiceTier, cr2.Usage.ServiceTier)
	assert.Equal(t, cr.Usage.CacheWriteInputTokens, cr2.Usage.CacheWriteInputTokens)
	assert.Equal(t, cr.Usage.CachedInputTokens, cr2.Usage.CachedInputTokens)

	// Cross-format: canonical → OpenAI
	openaiAdapter := &OpenAIAdapter{}
	openaiBody, err := openaiAdapter.EncodeResponse(cr)
	require.NoError(t, err)

	var openaiResult map[string]interface{}
	require.NoError(t, json.Unmarshal(openaiBody, &openaiResult))

	assert.Equal(t, "chat.completion", openaiResult["object"])
	choices := openaiResult["choices"].([]interface{})
	require.Len(t, choices, 1)
	choice := choices[0].(map[string]interface{})
	assert.Equal(t, "tool_calls", choice["finish_reason"])
	msg := choice["message"].(map[string]interface{})
	toolCalls := msg["tool_calls"].([]interface{})
	require.Len(t, toolCalls, 1)
	tc := toolCalls[0].(map[string]interface{})
	assert.Equal(t, "function", tc["type"])
	fn := tc["function"].(map[string]interface{})
	assert.Equal(t, "database_agent", fn["name"])
}

func TestUsageExtraction_Anthropic(t *testing.T) {
	runUsageCases(t, &AnthropicAdapter{}, []usageCase{
		{
			name:      "response with usage",
			body:      []byte(`{"id":"msg_1","type":"message","role":"assistant","model":"claude","content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn","usage":{"input_tokens":30,"output_tokens":15}}`),
			path:      "response",
			wantUsage: &CanonicalUsage{InputTokens: 30, OutputTokens: 15, TotalTokens: 45},
		},
		{
			name:      "response no usage",
			body:      []byte(`{"id":"msg_1","type":"message","role":"assistant","model":"claude","content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn"}`),
			path:      "response",
			wantUsage: nil,
		},
		{
			// Anthropic emits both cumulative input_tokens and output_tokens
			// on message_delta, so a single decode reconstructs the totals.
			name:      "stream message_delta with usage",
			body:      []byte(`{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"input_tokens":10,"output_tokens":20}}`),
			path:      "stream",
			wantUsage: &CanonicalUsage{InputTokens: 10, OutputTokens: 20, TotalTokens: 30},
		},
		{
			name:      "stream content_block_delta no usage",
			body:      []byte(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}`),
			path:      "stream",
			wantUsage: nil,
		},
	})
}

func TestAnthropicSSE_CacheFieldRoundTrip_MessageDelta(t *testing.T) {
	adapter := &AnthropicAdapter{}
	chunk := &CanonicalStreamChunk{
		FinishReason: "stop",
		Usage: &CanonicalUsage{
			InputTokens:           14,
			OutputTokens:          1,
			TotalTokens:           15,
			CacheWriteInputTokens: 4,
			CachedInputTokens:     9,
		},
	}

	lines, err := adapter.EncodeStreamChunk(chunk)
	require.NoError(t, err)
	require.NotEmpty(t, lines)

	var decoded *CanonicalStreamChunk
	for _, line := range lines {
		payload := bytes.TrimPrefix(line, []byte("data: "))
		if len(payload) == len(line) {
			continue
		}
		if !bytes.Contains(payload, []byte("message_delta")) {
			continue
		}
		decoded, err = adapter.DecodeStreamChunk(payload)
		require.NoError(t, err)
		break
	}
	require.NotNil(t, decoded, "message_delta event must round-trip")
	require.NotNil(t, decoded.Usage)
	assert.Equal(t, 4, decoded.Usage.CacheWriteInputTokens)
	assert.Equal(t, 9, decoded.Usage.CachedInputTokens)
}

func TestAnthropicSSE_CacheFieldRoundTrip_MessageStart(t *testing.T) {
	adapter := &AnthropicAdapter{}
	chunk := &CanonicalStreamChunk{
		ID:    "msg_round_trip",
		Model: "claude-3-sonnet",
		Role:  "assistant",
		Usage: &CanonicalUsage{
			InputTokens:           14,
			OutputTokens:          1,
			TotalTokens:           15,
			CacheWriteInputTokens: 4,
			CachedInputTokens:     9,
		},
	}

	lines, err := adapter.EncodeStreamChunk(chunk)
	require.NoError(t, err)
	require.NotEmpty(t, lines)

	var decoded *CanonicalStreamChunk
	for _, line := range lines {
		payload := bytes.TrimPrefix(line, []byte("data: "))
		if len(payload) == len(line) {
			continue
		}
		if !bytes.Contains(payload, []byte(`"type":"message_start"`)) {
			continue
		}
		decoded, err = adapter.DecodeStreamChunk(payload)
		require.NoError(t, err)
		break
	}
	require.NotNil(t, decoded, "message_start event must round-trip")
	require.NotNil(t, decoded.Usage)
	assert.Equal(t, 4, decoded.Usage.CacheWriteInputTokens)
	assert.Equal(t, 9, decoded.Usage.CachedInputTokens)
}

func TestCanonical_Anthropic_SystemArrayAndToolResultBlocks(t *testing.T) {
	input := `{
		"model": "claude-sonnet-4-5",
		"max_tokens": 1024,
		"system": [{"type":"text","text":"Be concise."}],
		"messages": [
			{"role":"user","content":[{"type":"text","text":"Weather?"}]},
			{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"get_lat_lng","input":{"location_description":"Beijing"}}]},
			{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","is_error":true,"content":[{"type":"text","text":"timeout"}]}]}
		]
	}`
	a := &AnthropicAdapter{}
	cr, err := a.DecodeRequest([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, "Be concise.", cr.System)
	require.GreaterOrEqual(t, len(cr.Messages), 2)
	var tool *CanonicalMessage
	for i := range cr.Messages {
		if cr.Messages[i].Role == "tool" {
			tool = &cr.Messages[i]
			break
		}
	}
	require.NotNil(t, tool)
	assert.Equal(t, "error: timeout", tool.Content)
	assert.Equal(t, "t1", tool.ToolCallID)
}

func TestAnthropicDecodeStreamChunk_ThinkingDelta(t *testing.T) {
	tests := []struct {
		name          string
		body          string
		wantReasoning string
		wantText      string
		wantNil       bool
	}{
		{
			name:          "thinking_delta becomes a reasoning delta",
			body:          `{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"Let me think"}}`,
			wantReasoning: "Let me think",
		},
		{
			name:     "text_delta stays plain content",
			body:     `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}`,
			wantText: "Hi",
		},
		{
			name:    "empty thinking_delta yields nothing",
			body:    `{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":""}}`,
			wantNil: true,
		},
		{
			name:    "signature_delta is still ignored",
			body:    `{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"abc"}}`,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (&AnthropicAdapter{}).DecodeStreamChunk([]byte(tt.body))
			require.NoError(t, err)
			if tt.wantNil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tt.wantReasoning, got.ReasoningDelta)
			assert.Equal(t, tt.wantText, got.Delta)
		})
	}
}

func TestAnthropicThinkingDeltaReachesOpenAIStream(t *testing.T) {
	input := `{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"step one"}}`

	lines, err := NewRegistry().AdaptStreamChunk([]byte(input), FormatOpenAI, FormatAnthropic)
	require.NoError(t, err)
	require.NotEmpty(t, lines, "thinking delta must produce SSE output")

	var payload []byte
	for _, l := range lines {
		if p, ok := bytes.CutPrefix(l, []byte("data: ")); ok {
			payload = p
			break
		}
	}
	require.NotNil(t, payload)

	var chunk struct {
		Choices []struct {
			Delta struct {
				Content          string `json:"content"`
				ReasoningContent string `json:"reasoning_content"`
			} `json:"delta"`
		} `json:"choices"`
	}
	require.NoError(t, json.Unmarshal(payload, &chunk))
	require.Len(t, chunk.Choices, 1)
	assert.Equal(t, "step one", chunk.Choices[0].Delta.ReasoningContent)
	assert.Empty(t, chunk.Choices[0].Delta.Content, "reasoning must not leak into content")
}

func TestAnthropicEncodeRequest_MaxTokensDefault(t *testing.T) {
	tests := []struct {
		name      string
		maxTokens int
		want      int
	}{
		{name: "caller value is respected", maxTokens: 512, want: 512},
		{name: "absent value falls back to the default", maxTokens: 0, want: defaultAnthropicMaxTokens},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := (&AnthropicAdapter{}).EncodeRequest(&CanonicalRequest{
				Model:     "claude-opus-4-5",
				MaxTokens: tt.maxTokens,
				Messages:  []CanonicalMessage{{Role: "user", Content: "hi"}},
			})
			require.NoError(t, err)

			var out struct {
				MaxTokens int `json:"max_tokens"`
			}
			require.NoError(t, json.Unmarshal(body, &out))
			assert.Equal(t, tt.want, out.MaxTokens)
		})
	}
}

// Anthropic's input_tokens is the uncached remainder: the real prompt is
// input_tokens + cache_read_input_tokens + cache_creation_input_tokens. Cost
// prices InputTokens, so the adapter folds the cache buckets in and keeps them
// as subsets. The numbers below are the worked example from Anthropic's
// prompt-caching documentation.
func TestAnthropicUsage_FoldsDisjointCacheCountsIntoTheParent(t *testing.T) {
	body := []byte(`{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-4-5",` +
		`"content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn",` +
		`"usage":{"input_tokens":2048,"output_tokens":64,` +
		`"cache_read_input_tokens":1800,"cache_creation_input_tokens":248,` +
		`"cache_creation":{"ephemeral_5m_input_tokens":148,"ephemeral_1h_input_tokens":100}}}`)

	cr, err := (&AnthropicAdapter{}).DecodeResponse(body)
	require.NoError(t, err)
	require.NotNil(t, cr.Usage)
	u := cr.Usage

	assert.Equal(t, 2048+1800+248, u.InputTokens, "the whole prompt, not the uncached remainder")
	assert.Equal(t, 64, u.OutputTokens)
	assert.Equal(t, u.InputTokens+u.OutputTokens, u.TotalTokens)
	assert.Equal(t, 1800, u.CachedInputTokens)
	assert.Equal(t, 248, u.CacheWriteInputTokens)
	assert.Equal(t, 100, u.CacheWrite1hInputTokens, "the 1h share bills at 2x, not 1.25x")

	assert.Equal(t, 2048, u.PlainInputTokens(), "what is left once both cache buckets are removed")
	assert.LessOrEqual(t, u.CachedInputTokens+u.CacheWriteInputTokens, u.InputTokens)
	assert.LessOrEqual(t, u.CacheWrite1hInputTokens, u.CacheWriteInputTokens)
}

// A prompt served entirely from cache reports input_tokens 0. Before the fold
// that made newCanonicalUsage return nil and the request lost its usage
// entirely; the cache counts now keep it alive.
func TestAnthropicUsage_FullyCachedPromptStillReportsUsage(t *testing.T) {
	body := []byte(`{"id":"msg_2","type":"message","role":"assistant","model":"claude-sonnet-4-5",` +
		`"content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn",` +
		`"usage":{"input_tokens":0,"output_tokens":12,"cache_read_input_tokens":40000}}`)

	cr, err := (&AnthropicAdapter{}).DecodeResponse(body)
	require.NoError(t, err)
	require.NotNil(t, cr.Usage, "a fully cached prompt must not vanish from billing")
	assert.Equal(t, 40000, cr.Usage.InputTokens)
	assert.Equal(t, 40000, cr.Usage.CachedInputTokens)
	assert.Equal(t, 0, cr.Usage.PlainInputTokens())
}

// Encoding back to Anthropic must undo the fold, or a passthrough client sees an
// input_tokens that double-counts its own cache buckets.
func TestAnthropicUsage_EncodeRestoresTheDisjointWireShape(t *testing.T) {
	body := []byte(`{"id":"msg_3","type":"message","role":"assistant","model":"claude-sonnet-4-5",` +
		`"content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn",` +
		`"usage":{"input_tokens":2048,"output_tokens":64,` +
		`"cache_read_input_tokens":1800,"cache_creation_input_tokens":248}}`)
	a := &AnthropicAdapter{}
	cr, err := a.DecodeResponse(body)
	require.NoError(t, err)

	out, err := a.EncodeResponse(cr)
	require.NoError(t, err)

	var got struct {
		Usage struct {
			InputTokens              int `json:"input_tokens"`
			OutputTokens             int `json:"output_tokens"`
			CacheReadInputTokens     int `json:"cache_read_input_tokens"`
			CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
		} `json:"usage"`
	}
	require.NoError(t, json.Unmarshal(out, &got))

	assert.Equal(t, 2048, got.Usage.InputTokens, "the wire carries the uncached remainder again")
	assert.Equal(t, 1800, got.Usage.CacheReadInputTokens)
	assert.Equal(t, 248, got.Usage.CacheCreationInputTokens)
	assert.Equal(t, 64, got.Usage.OutputTokens)
}

// Captured from the live API. message_delta repeats input_tokens and both cache
// totals, but it does NOT repeat the cache_creation object that splits the write
// into its 5m and 1h shares — and the 1h share bills at a premium. Overwriting on
// the later event therefore loses the premium and under-bills the write.
func TestAnthropicStreaming_MergeKeepsTheOneHourShareTheDeltaOmits(t *testing.T) {
	a := &AnthropicAdapter{}
	start := []byte(`{"type":"message_start","message":{"id":"msg_1","type":"message",` +
		`"role":"assistant","model":"claude-sonnet-4-6","content":[],` +
		`"usage":{"input_tokens":9,"cache_creation_input_tokens":6723,` +
		`"cache_read_input_tokens":0,` +
		`"cache_creation":{"ephemeral_5m_input_tokens":0,"ephemeral_1h_input_tokens":6723},` +
		`"output_tokens":1,"service_tier":"standard"}}}`)
	delta := []byte(`{"type":"message_delta","delta":{"stop_reason":"end_turn"},` +
		`"usage":{"input_tokens":9,"cache_creation_input_tokens":6723,` +
		`"cache_read_input_tokens":0,"output_tokens":5}}`)

	first, err := a.DecodeStreamChunk(start)
	require.NoError(t, err)
	require.NotNil(t, first.Usage)
	assert.Equal(t, 6732, first.Usage.InputTokens, "9 fresh + 6723 written, folded")
	assert.Equal(t, 6723, first.Usage.CacheWrite1hInputTokens)

	last, err := a.DecodeStreamChunk(delta)
	require.NoError(t, err)
	require.NotNil(t, last.Usage)
	assert.Equal(t, 6723, last.Usage.CacheWriteInputTokens, "the delta does repeat the write total")
	assert.Equal(t, 0, last.Usage.CacheWrite1hInputTokens, "but not the TTL split")

	merged := MergeUsage(first.Usage, last.Usage)
	require.NotNil(t, merged)
	assert.Equal(t, 6732, merged.InputTokens)
	assert.Equal(t, 6723, merged.CacheWriteInputTokens)
	assert.Equal(t, 6723, merged.CacheWrite1hInputTokens,
		"the premium share survives an event that does not repeat it")
	assert.Equal(t, 5, merged.OutputTokens)
}

// Anthropic's own published streaming example shows a delta carrying only
// output_tokens. The live API is more generous, but the merge has to hold for
// either shape, because which one arrives is not ours to control.
func TestAnthropicStreaming_MergeSurvivesAnOutputOnlyDelta(t *testing.T) {
	a := &AnthropicAdapter{}
	start := []byte(`{"type":"message_start","message":{"id":"msg_2","type":"message",` +
		`"role":"assistant","model":"claude-sonnet-4-6","content":[],` +
		`"usage":{"input_tokens":13,"cache_read_input_tokens":8403,"output_tokens":1}}}`)
	delta := []byte(`{"type":"message_delta","delta":{"stop_reason":"end_turn"},` +
		`"usage":{"output_tokens":15}}`)

	first, err := a.DecodeStreamChunk(start)
	require.NoError(t, err)
	last, err := a.DecodeStreamChunk(delta)
	require.NoError(t, err)

	merged := MergeUsage(first.Usage, last.Usage)
	require.NotNil(t, merged)
	assert.Equal(t, 8416, merged.InputTokens, "the whole prompt survives")
	assert.Equal(t, 8403, merged.CachedInputTokens, "and the discount that applies to it")
	assert.Equal(t, 15, merged.OutputTokens)
}

func TestMergeUsage_KeepsTheLargerOfEveryCount(t *testing.T) {
	prev := &CanonicalUsage{
		InputTokens: 100, OutputTokens: 1, TotalTokens: 101,
		CachedInputTokens: 60, CacheWriteInputTokens: 20,
		CacheWrite1hInputTokens: 5, ToolUseInputTokens: 3,
		ReasoningOutputTokens: 0, ServiceTier: "standard",
	}
	next := &CanonicalUsage{OutputTokens: 40, ReasoningOutputTokens: 25}

	got := MergeUsage(prev, next)
	assert.Equal(t, 100, got.InputTokens)
	assert.Equal(t, 40, got.OutputTokens)
	assert.Equal(t, 140, got.TotalTokens, "total is raised to at least in+out")
	assert.Equal(t, 60, got.CachedInputTokens)
	assert.Equal(t, 20, got.CacheWriteInputTokens)
	assert.Equal(t, 5, got.CacheWrite1hInputTokens)
	assert.Equal(t, 3, got.ToolUseInputTokens)
	assert.Equal(t, 25, got.ReasoningOutputTokens)
	assert.Equal(t, "standard", got.ServiceTier)

	assert.Same(t, prev, MergeUsage(prev, nil))
	assert.Same(t, next, MergeUsage(nil, next))
}

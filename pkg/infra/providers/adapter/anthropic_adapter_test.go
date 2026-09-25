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
	"strings"
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

func TestAnthropicEncode_ToolUseInput(t *testing.T) {
	tests := []struct {
		name      string
		arguments string
		want      string
	}{
		{name: "no arguments", arguments: "", want: `{}`},
		{name: "blank arguments", arguments: "  ", want: `{}`},
		{name: "object", arguments: `{"city":"Paris"}`, want: `{"city":"Paris"}`},
		{name: "invalid JSON", arguments: `{"city":"Par`, want: `{}`},
		{name: "array", arguments: `["Paris"]`, want: `{}`},
		{name: "string", arguments: `"Paris"`, want: `{}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := (&AnthropicAdapter{}).EncodeRequest(&CanonicalRequest{
				Model: "claude-opus-4-5",
				Messages: []CanonicalMessage{
					{Role: "user", Content: "hi"},
					{Role: "assistant", ToolCalls: []CanonicalToolCall{{ID: "toolu_1", Name: "now", Arguments: tt.arguments}}},
					{Role: "tool", ToolCallID: "toolu_1", Content: "noon"},
				},
			})
			require.NoError(t, err)

			var out struct {
				Messages []struct {
					Content json.RawMessage `json:"content"`
				} `json:"messages"`
			}
			require.NoError(t, json.Unmarshal(body, &out))
			require.Len(t, out.Messages, 3)
			var blocks []struct {
				Type  string          `json:"type"`
				Input json.RawMessage `json:"input"`
			}
			require.NoError(t, json.Unmarshal(out.Messages[1].Content, &blocks))
			require.Len(t, blocks, 1)
			assert.Equal(t, "tool_use", blocks[0].Type)
			assert.JSONEq(t, tt.want, string(blocks[0].Input))

			resp, err := (&AnthropicAdapter{}).EncodeResponse(&CanonicalResponse{
				Role:      "assistant",
				ToolCalls: []CanonicalToolCall{{ID: "toolu_1", Name: "now", Arguments: tt.arguments}},
			})
			require.NoError(t, err)
			var encoded struct {
				Content []struct {
					Input json.RawMessage `json:"input"`
				} `json:"content"`
			}
			require.NoError(t, json.Unmarshal(resp, &encoded))
			require.Len(t, encoded.Content, 1)
			assert.JSONEq(t, tt.want, string(encoded.Content[0].Input))
		})
	}
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

func TestMergeUsage_KeepsCacheTTLKnown(t *testing.T) {
	known := &CanonicalUsage{InputTokens: 400, CacheWriteInputTokens: 300, CacheWrite1hInputTokens: 200, cacheTTLKnown: true}
	unknown := &CanonicalUsage{OutputTokens: 7}

	assert.True(t, MergeUsage(known, unknown).cacheTTLKnown)
	assert.True(t, MergeUsage(unknown, known).cacheTTLKnown)
	assert.False(t, MergeUsage(unknown, &CanonicalUsage{OutputTokens: 9}).cacheTTLKnown)
}

func TestAnthropicEncodeRequest_Images(t *testing.T) {
	t.Parallel()

	const pngData = "iVBORw0KGgo="

	tests := []struct {
		name        string
		message     CanonicalMessage
		wantContent string
		wantErr     bool
		secrets     []string
	}{
		{
			name: "base64 image before text",
			message: CanonicalMessage{
				Role:    "user",
				Content: "describe",
				Images:  []CanonicalImage{{MediaType: "image/png", Data: pngData, Detail: "high"}},
			},
			wantContent: `[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0KGgo="}},{"type":"text","text":"describe"}]`,
		},
		{
			name: "https url",
			message: CanonicalMessage{
				Role:    "user",
				Content: "describe",
				Images:  []CanonicalImage{{URL: "https://example.com/cat.jpg"}},
			},
			wantContent: `[{"type":"image","source":{"type":"url","url":"https://example.com/cat.jpg"}},{"type":"text","text":"describe"}]`,
		},
		{
			name: "image only has no text block",
			message: CanonicalMessage{
				Role:   "user",
				Images: []CanonicalImage{{MediaType: "image/webp", Data: pngData}},
			},
			wantContent: `[{"type":"image","source":{"type":"base64","media_type":"image/webp","data":"iVBORw0KGgo="}}]`,
		},
		{
			name: "media type left for anthropic to validate",
			message: CanonicalMessage{
				Role:   "user",
				Images: []CanonicalImage{{MediaType: "image/tiff", Data: "U0VDUkVUREFUQQ=="}},
			},
			wantContent: `[{"type":"image","source":{"type":"base64","media_type":"image/tiff","data":"U0VDUkVUREFUQQ=="}}]`,
		},
		{
			name: "ftp url",
			message: CanonicalMessage{
				Role:   "user",
				Images: []CanonicalImage{{URL: "ftp://example.com/secret-path.png"}},
			},
			wantErr: true,
			secrets: []string{"secret-path"},
		},
		{
			name: "malformed data uri",
			message: CanonicalMessage{
				Role:   "user",
				Images: []CanonicalImage{{URL: "data:image/png,U0VDUkVUREFUQQ=="}},
			},
			wantErr: true,
			secrets: []string{"U0VDUkVUREFUQQ=="},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a := &AnthropicAdapter{}
			out, err := a.EncodeRequest(&CanonicalRequest{
				Model:    "claude",
				Messages: []CanonicalMessage{tt.message},
			})

			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrUnsupportedContent)
				var contentErr *UnsupportedContentError
				require.ErrorAs(t, err, &contentErr)
				assert.NotContains(t, err.Error(), "anthropic")
				for _, secret := range tt.secrets {
					assert.NotContains(t, err.Error(), secret)
				}
				return
			}
			require.NoError(t, err)
			var got anthropicRequest
			require.NoError(t, json.Unmarshal(out, &got))
			require.Len(t, got.Messages, 1)
			assert.JSONEq(t, tt.wantContent, string(got.Messages[0].Content))
		})
	}
}

func TestAnthropicEncodeRequest_ImagesOnlyOnUserMessages(t *testing.T) {
	t.Parallel()

	a := &AnthropicAdapter{}
	out, err := a.EncodeRequest(&CanonicalRequest{
		Model: "claude",
		Messages: []CanonicalMessage{{
			Role:    "assistant",
			Content: "ok",
			Images:  []CanonicalImage{{URL: "ftp://example.com/a.png"}},
		}},
	})

	require.NoError(t, err)
	var got anthropicRequest
	require.NoError(t, json.Unmarshal(out, &got))
	require.Len(t, got.Messages, 1)
	assert.JSONEq(t, `"ok"`, string(got.Messages[0].Content))
}

func TestDecodeAnthropicMessageContent_Images(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		role    string
		content string
		want    []CanonicalMessage
	}{
		{
			name:    "base64 normalizes media type",
			role:    "user",
			content: `[{"type":"text","text":"what is this"},{"type":"image","source":{"type":"base64","media_type":"IMAGE/JPG","data":"/9j/4AAQ"}}]`,
			want: []CanonicalMessage{{
				Role:    "user",
				Content: "what is this",
				Images:  []CanonicalImage{{MediaType: "image/jpeg", Data: "/9j/4AAQ"}},
			}},
		},
		{
			name:    "url",
			role:    "user",
			content: `[{"type":"image","source":{"type":"url","url":"https://example.com/cat.jpg"}},{"type":"text","text":"cat?"}]`,
			want: []CanonicalMessage{{
				Role:    "user",
				Content: "cat?",
				Images:  []CanonicalImage{{URL: "https://example.com/cat.jpg"}},
			}},
		},
		{
			name:    "file source ignored",
			role:    "user",
			content: `[{"type":"image","source":{"type":"file","file_id":"file_1"}},{"type":"text","text":"hi"}]`,
			want:    []CanonicalMessage{{Role: "user", Content: "hi"}},
		},
		{
			name:    "image only produces a message",
			role:    "user",
			content: `[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0KGgo="}}]`,
			want: []CanonicalMessage{{
				Role:   "user",
				Images: []CanonicalImage{{MediaType: "image/png", Data: "iVBORw0KGgo="}},
			}},
		},
		{
			name:    "tool result before image turn",
			role:    "user",
			content: `[{"type":"tool_result","tool_use_id":"toolu_1","content":"42"},{"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0KGgo="}}]`,
			want: []CanonicalMessage{
				{Role: "tool", ToolCallID: "toolu_1", Content: "42"},
				{Role: "user", Images: []CanonicalImage{{MediaType: "image/png", Data: "iVBORw0KGgo="}}},
			},
		},
		{
			name:    "tool result before text turn",
			role:    "user",
			content: `[{"type":"text","text":"thanks"},{"type":"tool_result","tool_use_id":"toolu_1","content":"42"}]`,
			want: []CanonicalMessage{
				{Role: "tool", ToolCallID: "toolu_1", Content: "42"},
				{Role: "user", Content: "thanks"},
			},
		},
		{
			name:    "non-object source on another block keeps the tool result",
			role:    "user",
			content: `[{"type":"tool_result","tool_use_id":"t1","content":"42"},{"type":"search_result","source":"https://example.com/doc","title":"doc","content":[{"type":"text","text":"x"}]},{"type":"text","text":"thanks"}]`,
			want: []CanonicalMessage{
				{Role: "tool", ToolCallID: "t1", Content: "42"},
				{Role: "user", Content: "thanks"},
			},
		},
		{
			name:    "non-http url source kept for the encoder to reject",
			role:    "user",
			content: `[{"type":"image","source":{"type":"url","url":"ftp://example.com/a.png"}}]`,
			want:    []CanonicalMessage{{Role: "user", Images: []CanonicalImage{{URL: "ftp://example.com/a.png"}}}},
		},
		{
			name:    "assistant images ignored",
			role:    "assistant",
			content: `[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0KGgo="}},{"type":"text","text":"ok"}]`,
			want:    []CanonicalMessage{{Role: "assistant", Content: "ok"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := decodeAnthropicMessageContent(tt.role, json.RawMessage(tt.content))

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAnthropicRequest_NoCacheMarkersLeaveNoIntent(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"model": "claude-sonnet-4-5",
		"max_tokens": 64,
		"system": [{"type": "text", "text": "Be brief."}],
		"tools": [{"name": "lookup", "input_schema": {"type": "object"}}],
		"messages": [
			{"role": "user", "content": [{"type": "text", "text": "hi"}]},
			{"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "lookup", "input": {}}]},
			{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "ok"}]}
		]
	}`)
	a := &AnthropicAdapter{}
	cr, err := a.DecodeRequest(body)
	require.NoError(t, err)

	assert.Nil(t, cr.SystemCache)
	assert.Nil(t, cr.CacheOptions)
	assert.Equal(t, []any{nil}, toolTTLs(cr.Tools))
	assert.Equal(t, []any{nil, nil, nil}, messageTTLs(cr.Messages))

	out, err := a.EncodeRequest(cr)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "cache_control")
	assert.Contains(t, string(out), `"system":"Be brief."`)
}

type anthropicCachedBody struct {
	Stream       *bool                  `json:"stream"`
	CacheControl *anthropicCacheControl `json:"cache_control"`
	System       []struct {
		Text         string                 `json:"text"`
		CacheControl *anthropicCacheControl `json:"cache_control"`
	} `json:"system"`
	Tools []struct {
		Name         string                 `json:"name"`
		CacheControl *anthropicCacheControl `json:"cache_control"`
	} `json:"tools"`
	Messages []struct {
		Role    string                  `json:"role"`
		Content []anthropicContentBlock `json:"content"`
	} `json:"messages"`
}

func TestAnthropicRequest_CacheMarkersRoundTrip(t *testing.T) {
	t.Parallel()

	for _, stream := range []bool{false, true} {
		t.Run(map[bool]string{false: "buffered", true: "stream"}[stream], func(t *testing.T) {
			t.Parallel()
			body := []byte(`{
				"model": "claude-sonnet-4-5",
				"max_tokens": 64,
				"stream": ` + map[bool]string{false: "false", true: "true"}[stream] + `,
				"cache_control": {"type": "ephemeral"},
				"system": [
					{"type": "text", "text": "Part one."},
					{"type": "text", "text": "Part two.", "cache_control": {"type": "ephemeral", "ttl": "1h"}}
				],
				"tools": [
					{"name": "a", "input_schema": {"type": "object"}},
					{"name": "b", "input_schema": {"type": "object"}, "cache_control": {"type": "ephemeral", "ttl": "1h"}}
				],
				"messages": [
					{"role": "user", "content": [{"type": "text", "text": "hi", "cache_control": {"type": "ephemeral", "ttl": "1h"}}]},
					{"role": "assistant", "content": [
						{"type": "text", "text": "calling"},
						{"type": "tool_use", "id": "t1", "name": "b", "input": {}, "cache_control": {"type": "ephemeral"}}
					]},
					{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "ok", "cache_control": {"type": "ephemeral", "ttl": "5m"}}]}
				]
			}`)
			a := &AnthropicAdapter{}
			cr, err := a.DecodeRequest(body)
			require.NoError(t, err)

			assert.Equal(t, "Part one.\nPart two.", cr.System)
			assert.Equal(t, CacheTTL1h, ttlOf(cr.SystemCache))
			require.NotNil(t, cr.CacheOptions)
			assert.Equal(t, CacheTTL(""), ttlOf(cr.CacheOptions.Auto))
			assert.Equal(t, []any{nil, CacheTTL1h}, toolTTLs(cr.Tools))
			assert.Equal(t, []any{CacheTTL1h, CacheTTL(""), CacheTTL5m}, messageTTLs(cr.Messages))
			assert.Equal(t, "tool", cr.Messages[2].Role)

			out, err := a.EncodeRequest(cr)
			require.NoError(t, err)
			var got anthropicCachedBody
			require.NoError(t, json.Unmarshal(out, &got))

			assert.Equal(t, stream, got.Stream != nil && *got.Stream)
			assert.Equal(t, &anthropicCacheControl{Type: "ephemeral"}, got.CacheControl)
			require.Len(t, got.System, 1)
			assert.Equal(t, "Part one.\nPart two.", got.System[0].Text)
			assert.Equal(t, &anthropicCacheControl{Type: "ephemeral", TTL: "1h"}, got.System[0].CacheControl)
			require.Len(t, got.Tools, 2)
			assert.Nil(t, got.Tools[0].CacheControl)
			assert.Equal(t, &anthropicCacheControl{Type: "ephemeral", TTL: "1h"}, got.Tools[1].CacheControl)
			require.Len(t, got.Messages, 3)
			assert.Equal(t, &anthropicCacheControl{Type: "ephemeral", TTL: "1h"}, got.Messages[0].Content[0].CacheControl)
			require.Len(t, got.Messages[1].Content, 2)
			assert.Nil(t, got.Messages[1].Content[0].CacheControl)
			assert.Equal(t, "tool_use", got.Messages[1].Content[1].Type)
			assert.Equal(t, &anthropicCacheControl{Type: "ephemeral"}, got.Messages[1].Content[1].CacheControl)
			assert.Equal(t, "tool_result", got.Messages[2].Content[0].Type)
			assert.Equal(t, &anthropicCacheControl{Type: "ephemeral", TTL: "5m"}, got.Messages[2].Content[0].CacheControl)
		})
	}
}

func TestAnthropicRequest_MarkedImageBlockMarksTheMessage(t *testing.T) {
	t.Parallel()

	cr, err := (&AnthropicAdapter{}).DecodeRequest([]byte(`{
		"model": "claude-sonnet-4-5",
		"max_tokens": 64,
		"messages": [{"role": "user", "content": [
			{"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo="}, "cache_control": {"type": "ephemeral"}},
			{"type": "text", "text": "describe"}
		]}]
	}`))
	require.NoError(t, err)
	require.Len(t, cr.Messages, 1)
	assert.Equal(t, []any{CacheTTL("")}, messageTTLs(cr.Messages))
}

func TestAnthropicEncodeRequest_CacheMarkerGoesOnTheLastBlock(t *testing.T) {
	t.Parallel()

	img := CanonicalImage{MediaType: "image/png", Data: "iVBORw0KGgo="}
	tests := []struct {
		name        string
		message     CanonicalMessage
		wantContent string
	}{
		{
			name:        "image then text",
			message:     CanonicalMessage{Role: "user", Content: "describe", Images: []CanonicalImage{img}, Cache: bp(CacheTTL5m)},
			wantContent: `[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0KGgo="}},{"type":"text","text":"describe","cache_control":{"type":"ephemeral","ttl":"5m"}}]`,
		},
		{
			name:        "image only",
			message:     CanonicalMessage{Role: "user", Images: []CanonicalImage{img}, Cache: bp("")},
			wantContent: `[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0KGgo="},"cache_control":{"type":"ephemeral"}}]`,
		},
		{
			name:        "string content becomes a text block",
			message:     CanonicalMessage{Role: "assistant", Content: "done", Cache: bp(CacheTTL1h)},
			wantContent: `[{"type":"text","text":"done","cache_control":{"type":"ephemeral","ttl":"1h"}}]`,
		},
		{
			name:        "empty content drops the marker",
			message:     CanonicalMessage{Role: "user", Cache: bp("")},
			wantContent: `""`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, err := (&AnthropicAdapter{}).EncodeRequest(&CanonicalRequest{Model: "claude-sonnet-4-5", Messages: []CanonicalMessage{tt.message}})
			require.NoError(t, err)
			var got struct {
				Messages []anthropicMessage `json:"messages"`
			}
			require.NoError(t, json.Unmarshal(out, &got))
			require.Len(t, got.Messages, 1)
			assert.JSONEq(t, tt.wantContent, string(got.Messages[0].Content))
		})
	}
}

func TestAnthropicEncodeRequest_NormalizedSixBreakpointsKeepFour(t *testing.T) {
	t.Parallel()

	req := cachedRequest(1, 4, "")
	req.Model = "claude-sonnet-4-5"
	normalizeCacheIntent(req, FormatAnthropic)
	out, err := (&AnthropicAdapter{}).EncodeRequest(req)
	require.NoError(t, err)
	assert.Equal(t, 4, bytes.Count(out, []byte(`"cache_control"`)))

	var got struct {
		Messages []anthropicMessage `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(out, &got))
	require.Len(t, got.Messages, 4)
	cc := `[{"type":"text","text":"m","cache_control":{"type":"ephemeral"}}]`
	for i, want := range []string{`"m"`, `"m"`, cc, cc} {
		assert.JSONEq(t, want, string(got.Messages[i].Content), "message %d", i)
	}
}

type anthropicRawBody struct {
	CacheControl json.RawMessage `json:"cache_control"`
	System       json.RawMessage `json:"system"`
	Tools        json.RawMessage `json:"tools"`
	Messages     []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	} `json:"messages"`
}

func reencodeAnthropic(t *testing.T, body string) anthropicRawBody {
	t.Helper()
	a := &AnthropicAdapter{}
	cr, err := a.DecodeRequest([]byte(body))
	require.NoError(t, err)
	out, err := a.EncodeRequest(cr)
	require.NoError(t, err)
	var got anthropicRawBody
	require.NoError(t, json.Unmarshal(out, &got))
	return got
}

func TestAnthropicRequest_CacheMarkerKeepsItsBlockBoundary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		system       string
		messages     []string
		wantSystem   string
		wantMessages []string
	}{
		{
			name:     "marker before volatile system and user text",
			system:   `[{"type":"text","text":"Static instructions.","cache_control":{"type":"ephemeral"}},{"type":"text","text":"Current time: 2026-09-25T08:00:00Z"}]`,
			messages: []string{`[{"type":"text","text":"Big document ...","cache_control":{"type":"ephemeral"}},{"type":"text","text":"Question?"}]`},
		},
		{
			name:     "marked text before tool calls stays on the text",
			system:   `"s"`,
			messages: []string{`"q"`, `[{"type":"text","text":"calling","cache_control":{"type":"ephemeral","ttl":"1h"}},{"type":"tool_use","id":"t1","name":"f","input":{}}]`, `[{"type":"tool_result","tool_use_id":"t1","content":"ok"}]`},
		},
		{
			name:         "several system markers keep the last position with the longest TTL",
			system:       `[{"type":"text","text":"A","cache_control":{"type":"ephemeral","ttl":"1h"}},{"type":"text","text":"B","cache_control":{"type":"ephemeral"}},{"type":"text","text":"C"}]`,
			messages:     []string{`"hi"`},
			wantSystem:   `[{"type":"text","text":"A\nB","cache_control":{"type":"ephemeral","ttl":"1h"}},{"type":"text","text":"C"}]`,
			wantMessages: []string{`"hi"`},
		},
		{
			name:         "thinking markers are dropped with the block",
			system:       `"s"`,
			messages:     []string{`"q"`, `[{"type":"thinking","thinking":"hm","signature":"sig","cache_control":{"type":"ephemeral"}},{"type":"text","text":"a"}]`},
			wantSystem:   `"s"`,
			wantMessages: []string{`"q"`, `"a"`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			roles := []string{"user", "assistant"}
			msgs := make([]string, len(tt.messages))
			for i, c := range tt.messages {
				msgs[i] = `{"role":"` + roles[i%2] + `","content":` + c + `}`
			}
			body := `{"model":"claude-haiku-4-5","max_tokens":5,"system":` + tt.system + `,"messages":[` + strings.Join(msgs, ",") + `]}`
			got := reencodeAnthropic(t, body)

			wantSystem, wantMessages := tt.wantSystem, tt.wantMessages
			if wantSystem == "" {
				wantSystem, wantMessages = tt.system, tt.messages
			}
			assert.JSONEq(t, wantSystem, string(got.System))
			require.Len(t, got.Messages, len(wantMessages))
			for i, want := range wantMessages {
				assert.JSONEq(t, want, string(got.Messages[i].Content), "message %d", i)
			}
		})
	}
}

func TestAnthropicRequest_ExplicitMarkerNeverConflictsWithAutomaticCaching(t *testing.T) {
	t.Parallel()

	stable := `[{"type":"text","text":"stable","cache_control":{"type":"ephemeral","ttl":"1h"}},{"type":"text","text":"volatile tail"}]`
	got := reencodeAnthropic(t, `{"model":"claude-haiku-4-5","max_tokens":5,"cache_control":{"type":"ephemeral"},"messages":[{"role":"user","content":`+stable+`}]}`)
	assert.JSONEq(t, `{"type":"ephemeral"}`, string(got.CacheControl))
	require.Len(t, got.Messages, 1)
	assert.JSONEq(t, stable, string(got.Messages[0].Content), "the 1h marker stays off the last block")

	tests := []struct {
		name    string
		auto    *CanonicalCacheBreakpoint
		message CanonicalMessage
		want    string
	}{
		{
			name:    "a boundary a plugin moved falls back to the end",
			message: CanonicalMessage{Role: "user", Content: "stable, redacted\nvolatile", Cache: &CanonicalCacheBreakpoint{TTL: CacheTTL1h, Offset: 6}},
			want:    `[{"type":"text","text":"stable, redacted\nvolatile","cache_control":{"type":"ephemeral","ttl":"1h"}}]`,
		},
		{
			name:    "the fallback is dropped when automatic caching uses another TTL",
			auto:    bp(""),
			message: CanonicalMessage{Role: "user", Content: "stable, redacted\nvolatile", Cache: &CanonicalCacheBreakpoint{TTL: CacheTTL1h, Offset: 6}},
			want:    `[{"type":"text","text":"stable, redacted\nvolatile"}]`,
		},
		{
			name:    "a marker with the automatic TTL stays on the last block",
			auto:    bp(CacheTTL5m),
			message: CanonicalMessage{Role: "user", Content: "tail", Cache: bp("")},
			want:    `[{"type":"text","text":"tail","cache_control":{"type":"ephemeral"}}]`,
		},
		{
			name:    "a trailing tool result with another TTL loses its marker",
			auto:    bp(""),
			message: CanonicalMessage{Role: "tool", ToolCallID: "t1", Content: "ok", Cache: bp(CacheTTL1h)},
			want:    `[{"type":"tool_result","tool_use_id":"t1","content":"ok"}]`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := &CanonicalRequest{Model: "claude-haiku-4-5", Messages: []CanonicalMessage{tt.message}}
			if tt.auto != nil {
				req.CacheOptions = &CanonicalCacheOptions{Auto: tt.auto}
			}
			out, err := (&AnthropicAdapter{}).EncodeRequest(req)
			require.NoError(t, err)
			var got anthropicRawBody
			require.NoError(t, json.Unmarshal(out, &got))
			require.Len(t, got.Messages, 1)
			assert.JSONEq(t, tt.want, string(got.Messages[0].Content))
		})
	}
}

func TestAnthropicSplitAtCacheOffset_RefusesUnsafeSplits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		text   string
		offset int
		ok     bool
	}{
		{name: "intact boundary", text: "a\nb", offset: 1, ok: true},
		{name: "end of text", text: "a\nb", offset: 3, ok: true},
		{name: "no offset", text: "a\nb", offset: 0},
		{name: "past the end", text: "a\nb", offset: 4},
		{name: "not the joiner", text: "ab\nc", offset: 1},
		{name: "blank tail", text: "a\n ", offset: 1},
		{name: "blank head", text: " \nb", offset: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, _, ok := anthropicSplitAtCacheOffset(tt.text, &CanonicalCacheBreakpoint{Offset: tt.offset})
			assert.Equal(t, tt.ok, ok)
		})
	}
}

func TestAnthropicRequest_ClaudeCodeShapedBodyKeepsMarkersInPlace(t *testing.T) {
	t.Parallel()

	got := reencodeAnthropic(t, `{
		"model": "claude-haiku-4-5", "max_tokens": 5,
		"system": [
			{"type": "text", "text": "x-anthropic-billing-header: cc_version=2.1.0;"},
			{"type": "text", "text": "You are Claude Code.", "cache_control": {"type": "ephemeral", "ttl": "1h"}},
			{"type": "text", "text": "\nYou are an interactive CLI tool.\n", "cache_control": {"type": "ephemeral", "ttl": "1h"}}
		],
		"tools": [
			{"name": "Bash", "input_schema": {"type": "object"}},
			{"name": "Read", "input_schema": {"type": "object"}, "cache_control": {"type": "ephemeral", "ttl": "1h"}}
		],
		"messages": [
			{"role": "user", "content": [{"type": "text", "text": "<system-reminder>ctx</system-reminder>"}, {"type": "text", "text": "list files"}]},
			{"role": "assistant", "content": [
				{"type": "thinking", "thinking": "User wants ls.", "signature": "sig", "cache_control": {"type": "ephemeral"}},
				{"type": "text", "text": "I'll list them."},
				{"type": "tool_use", "id": "toolu_01A", "name": "Bash", "input": {"command": "ls"}}
			]},
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "toolu_01A", "content": "a.go"},
				{"type": "text", "text": "thanks", "cache_control": {"type": "ephemeral"}}
			]}
		]
	}`)

	assert.JSONEq(t, `[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.0;\nYou are Claude Code.\n\nYou are an interactive CLI tool.\n","cache_control":{"type":"ephemeral","ttl":"1h"}}]`, string(got.System))
	assert.Equal(t, 1, bytes.Count(got.Tools, []byte(`"cache_control"`)))
	require.Len(t, got.Messages, 4)
	assert.NotContains(t, string(got.Messages[1].Content), "cache_control")
	assert.JSONEq(t, `[{"type":"tool_result","tool_use_id":"toolu_01A","content":"a.go"}]`, string(got.Messages[2].Content))
	assert.JSONEq(t, `[{"type":"text","text":"thanks","cache_control":{"type":"ephemeral"}}]`, string(got.Messages[3].Content))
}

func TestAnthropicDecodeRequest_BlankSystemStringIsEmpty(t *testing.T) {
	t.Parallel()

	body := []byte(`{"model":"claude-haiku-4-5","max_tokens":5,"system":" \n ","messages":[{"role":"user","content":"hi"}]}`)
	cr, err := (&AnthropicAdapter{}).DecodeRequest(body)
	require.NoError(t, err)
	assert.Empty(t, cr.System)

	cr, err = (&AnthropicAdapter{}).DecodeRequest([]byte(`{"model":"m","max_tokens":5,"system":"  keep me \n","messages":[]}`))
	require.NoError(t, err)
	assert.Equal(t, "  keep me \n", cr.System)

	out, err := NewRegistry().AdaptRequest(body, FormatAnthropic, FormatBedrock)
	require.NoError(t, err)
	assert.NotContains(t, string(out), `"system"`)
}

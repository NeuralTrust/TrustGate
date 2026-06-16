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
	assert.Equal(t, 0, cr.Usage.CacheCreationInputTokens)
	assert.Equal(t, 0, cr.Usage.CacheReadInputTokens)
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
	assert.Equal(t, cr.Usage.CacheCreationInputTokens, cr2.Usage.CacheCreationInputTokens)
	assert.Equal(t, cr.Usage.CacheReadInputTokens, cr2.Usage.CacheReadInputTokens)

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
			InputTokens:              1,
			OutputTokens:             1,
			TotalTokens:              2,
			CacheCreationInputTokens: 4,
			CacheReadInputTokens:     9,
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
	assert.Equal(t, 4, decoded.Usage.CacheCreationInputTokens)
	assert.Equal(t, 9, decoded.Usage.CacheReadInputTokens)
}

func TestAnthropicSSE_CacheFieldRoundTrip_MessageStart(t *testing.T) {
	adapter := &AnthropicAdapter{}
	chunk := &CanonicalStreamChunk{
		ID:    "msg_round_trip",
		Model: "claude-3-sonnet",
		Role:  "assistant",
		Usage: &CanonicalUsage{
			InputTokens:              1,
			OutputTokens:             1,
			TotalTokens:              2,
			CacheCreationInputTokens: 4,
			CacheReadInputTokens:     9,
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
	assert.Equal(t, 4, decoded.Usage.CacheCreationInputTokens)
	assert.Equal(t, 9, decoded.Usage.CacheReadInputTokens)
}

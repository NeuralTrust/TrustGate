package adapter

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// isValidMistralID
// ---------------------------------------------------------------------------

func TestIsValidMistralID(t *testing.T) {
	tests := []struct {
		name   string
		id     string
		expect bool
	}{
		{"exactly 9 lowercase", "abcdefghi", true},
		{"exactly 9 uppercase", "ABCDEFGHI", true},
		{"exactly 9 digits", "123456789", true},
		{"mixed alphanumeric 9 chars", "aB3dE6gH9", true},
		{"too short", "abc", false},
		{"too long", "abcdefghij", false},
		{"empty", "", false},
		{"contains underscore", "abc_efghi", false},
		{"contains dash", "abc-efghi", false},
		{"contains space", "abc efghi", false},
		{"8 chars", "abcdefgh", false},
		{"10 chars", "abcdefghij", false},
		{"unicode letter", "abcdefghñ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expect, isValidMistralID(tt.id))
		})
	}
}

// ---------------------------------------------------------------------------
// mistralID
// ---------------------------------------------------------------------------

func TestMistralID_Deterministic(t *testing.T) {
	cache := map[string]string{}
	id1 := mistralID("call_abc123", cache)
	id2 := mistralID("call_abc123", cache)
	assert.Equal(t, id1, id2, "same input should produce same output")
}

func TestMistralID_ExactlyNineAlphanumeric(t *testing.T) {
	inputs := []string{
		"call_abc123",
		"toolu_016u41qZE8fBygCBmSxapu7x",
		"query_clients",
		"a",
		"very-long-tool-call-id-that-exceeds-nine-characters-by-a-lot",
	}
	for _, input := range inputs {
		cache := map[string]string{}
		id := mistralID(input, cache)
		assert.Len(t, id, 9, "id for %q should be 9 chars, got %q", input, id)
		assert.True(t, isValidMistralID(id), "id %q for input %q should be valid", id, input)
	}
}

func TestMistralID_DifferentInputsDifferentOutputs(t *testing.T) {
	cache := map[string]string{}
	id1 := mistralID("call_abc", cache)
	id2 := mistralID("call_xyz", cache)
	assert.NotEqual(t, id1, id2, "different inputs should produce different IDs")
}

func TestMistralID_CacheIsUsed(t *testing.T) {
	cache := map[string]string{}
	id1 := mistralID("original_id", cache)
	assert.Contains(t, cache, "original_id")
	assert.Equal(t, id1, cache["original_id"])
}

func TestMistralID_ConsistentAcrossToolCallAndToolResult(t *testing.T) {
	cache := map[string]string{}
	// Simulate: assistant message has tool_call with ID, tool message references same ID
	tcID := mistralID("call_long_id_from_openai", cache)
	resultID := mistralID("call_long_id_from_openai", cache)
	assert.Equal(t, tcID, resultID, "tool_call ID and tool_result ID must match")
}

// ---------------------------------------------------------------------------
// MistralAdapter.EncodeRequest — tool parameters injection
// ---------------------------------------------------------------------------

func TestMistralAdapter_EncodeRequest_InjectsParameters(t *testing.T) {
	adapter := &MistralAdapter{}

	canonical := &CanonicalRequest{
		Model: "mistral-large-latest",
		Messages: []CanonicalMessage{
			{Role: "user", Content: "hello"},
		},
		Tools: []CanonicalTool{
			{Name: "my_tool", Description: "does stuff", Schema: nil},
		},
	}

	out, err := adapter.EncodeRequest(canonical)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	tools := result["tools"].([]interface{})
	require.Len(t, tools, 1)
	fn := tools[0].(map[string]interface{})["function"].(map[string]interface{})
	params := fn["parameters"].(map[string]interface{})
	assert.Equal(t, "object", params["type"])
	assert.NotNil(t, params["properties"])
}

func TestMistralAdapter_EncodeRequest_PreservesExistingParameters(t *testing.T) {
	adapter := &MistralAdapter{}

	canonical := &CanonicalRequest{
		Model: "mistral-large-latest",
		Messages: []CanonicalMessage{
			{Role: "user", Content: "hello"},
		},
		Tools: []CanonicalTool{
			{
				Name: "search",
				Schema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"query": map[string]interface{}{"type": "string"},
					},
					"required": []interface{}{"query"},
				},
			},
		},
	}

	out, err := adapter.EncodeRequest(canonical)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	tools := result["tools"].([]interface{})
	fn := tools[0].(map[string]interface{})["function"].(map[string]interface{})
	params := fn["parameters"].(map[string]interface{})
	props := params["properties"].(map[string]interface{})
	assert.Contains(t, props, "query")
}

// ---------------------------------------------------------------------------
// MistralAdapter.EncodeRequest — tool_call ID normalization
// ---------------------------------------------------------------------------

func TestMistralAdapter_EncodeRequest_NormalizesToolCallIDs(t *testing.T) {
	adapter := &MistralAdapter{}

	canonical := &CanonicalRequest{
		Model: "mistral-large-latest",
		Messages: []CanonicalMessage{
			{Role: "user", Content: "find clients"},
			{
				Role: "assistant",
				ToolCalls: []CanonicalToolCall{
					{ID: "call_long_openai_id", Name: "db_query", Arguments: `{"q":"clients"}`},
				},
			},
			{
				Role:       "tool",
				ToolCallID: "call_long_openai_id",
				Content:    `[{"name":"Juan"}]`,
			},
		},
	}

	out, err := adapter.EncodeRequest(canonical)
	require.NoError(t, err)

	var result openaiRequest
	require.NoError(t, json.Unmarshal(out, &result))

	// Assistant tool_call ID should be normalized
	require.Len(t, result.Messages, 3)
	assistantMsg := result.Messages[1]
	require.Len(t, assistantMsg.ToolCalls, 1)
	assert.True(t, isValidMistralID(assistantMsg.ToolCalls[0].ID),
		"tool_call ID should be valid Mistral ID, got %q", assistantMsg.ToolCalls[0].ID)

	// Tool result message should reference the same normalized ID
	toolMsg := result.Messages[2]
	assert.Equal(t, assistantMsg.ToolCalls[0].ID, toolMsg.ToolCallID,
		"tool_call_id in tool message must match the normalized ID in assistant message")
}

func TestMistralAdapter_EncodeRequest_SkipsAlreadyValidIDs(t *testing.T) {
	adapter := &MistralAdapter{}

	canonical := &CanonicalRequest{
		Model: "mistral-large-latest",
		Messages: []CanonicalMessage{
			{Role: "user", Content: "hello"},
			{
				Role: "assistant",
				ToolCalls: []CanonicalToolCall{
					{ID: "abcde1234", Name: "tool1", Arguments: "{}"},
				},
			},
			{
				Role:       "tool",
				ToolCallID: "abcde1234",
				Content:    "result",
			},
		},
	}

	out, err := adapter.EncodeRequest(canonical)
	require.NoError(t, err)

	var result openaiRequest
	require.NoError(t, json.Unmarshal(out, &result))

	assert.Equal(t, "abcde1234", result.Messages[1].ToolCalls[0].ID,
		"already valid ID should not be changed")
	assert.Equal(t, "abcde1234", result.Messages[2].ToolCallID)
}

// ---------------------------------------------------------------------------
// MistralAdapter — roundtrip decode/encode
// ---------------------------------------------------------------------------

func TestMistralAdapter_Roundtrip(t *testing.T) {
	input := `{
		"model": "mistral-large-latest",
		"messages": [
			{"role": "system", "content": "You are helpful."},
			{"role": "user", "content": "Hello"}
		],
		"max_tokens": 100,
		"temperature": 0.7
	}`

	adapter := &MistralAdapter{}

	canonical, err := adapter.DecodeRequest([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, "mistral-large-latest", canonical.Model)
	assert.Equal(t, "You are helpful.", canonical.System)
	assert.Len(t, canonical.Messages, 1)

	encoded, err := adapter.EncodeRequest(canonical)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(encoded, &result))
	msgs := result["messages"].([]interface{})
	assert.Len(t, msgs, 2) // system re-injected + user
}

// ---------------------------------------------------------------------------
// Cross-provider: OpenAI → Mistral
// ---------------------------------------------------------------------------

func TestAdaptRequest_OpenAIToMistral(t *testing.T) {
	input := `{
		"model": "gpt-4",
		"messages": [
			{"role": "system", "content": "You are helpful."},
			{"role": "user", "content": "Hello"},
			{
				"role": "assistant",
				"tool_calls": [
					{"id": "call_very_long_openai_id_12345", "type": "function", "function": {"name": "search", "arguments": "{\"q\":\"test\"}"}}
				]
			},
			{"role": "tool", "tool_call_id": "call_very_long_openai_id_12345", "content": "result"}
		],
		"max_tokens": 100,
		"tools": [
			{
				"type": "function",
				"function": {"name": "search", "description": "Search"}
			}
		]
	}`

	out, err := testRegistry().AdaptRequest([]byte(input), FormatOpenAI, FormatMistral)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	// Tools should have parameters injected
	tools := result["tools"].([]interface{})
	require.Len(t, tools, 1)
	fn := tools[0].(map[string]interface{})["function"].(map[string]interface{})
	assert.NotNil(t, fn["parameters"], "Mistral requires parameters on every tool")

	// Tool call IDs should be normalized to 9 chars
	msgs := result["messages"].([]interface{})
	assistantMsg := msgs[2].(map[string]interface{})
	tcs := assistantMsg["tool_calls"].([]interface{})
	tcID := tcs[0].(map[string]interface{})["id"].(string)
	assert.Len(t, tcID, 9)
	assert.True(t, isValidMistralID(tcID))

	// Tool result references the same normalized ID
	toolMsg := msgs[3].(map[string]interface{})
	assert.Equal(t, tcID, toolMsg["tool_call_id"])
}

// ---------------------------------------------------------------------------
// Cross-provider: Mistral → OpenAI (same wire format, passthrough)
// ---------------------------------------------------------------------------

func TestAdaptRequest_MistralToOpenAI(t *testing.T) {
	input := `{"model":"mistral-large","messages":[{"role":"user","content":"hi"}]}`
	out, err := testRegistry().AdaptRequest([]byte(input), FormatMistral, FormatOpenAI)
	require.NoError(t, err)

	// Mistral and OpenAI are NOT wire-compatible (different adapters), so
	// this goes through decode→encode. The result should still be valid.
	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))
	msgs := result["messages"].([]interface{})
	assert.Len(t, msgs, 1)
}

// ---------------------------------------------------------------------------
// Cross-provider: Anthropic → Mistral
// ---------------------------------------------------------------------------

func TestAdaptRequest_AnthropicToMistral(t *testing.T) {
	input := `{
		"model": "claude-3-sonnet",
		"system": "Be helpful.",
		"messages": [{"role": "user", "content": "Hello"}],
		"max_tokens": 100,
		"tools": [
			{
				"name": "lookup",
				"description": "Lookup data",
				"input_schema": {"type": "object", "properties": {"id": {"type": "string"}}}
			}
		]
	}`

	out, err := testRegistry().AdaptRequest([]byte(input), FormatAnthropic, FormatMistral)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	// System should be re-injected as first message
	msgs := result["messages"].([]interface{})
	assert.Equal(t, "system", msgs[0].(map[string]interface{})["role"])

	// Tools should have parameters
	tools := result["tools"].([]interface{})
	fn := tools[0].(map[string]interface{})["function"].(map[string]interface{})
	assert.NotNil(t, fn["parameters"])
}

// ---------------------------------------------------------------------------
// Cross-provider: Gemini → Mistral
// ---------------------------------------------------------------------------

func TestAdaptRequest_GeminiToMistral(t *testing.T) {
	input := `{
		"contents": [{"role": "user", "parts": [{"text": "Hello"}]}],
		"systemInstruction": {"parts": [{"text": "Be concise."}]},
		"generationConfig": {"maxOutputTokens": 50}
	}`

	out, err := testRegistry().AdaptRequest([]byte(input), FormatGemini, FormatMistral)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	// Should be in OpenAI-like format now
	msgs := result["messages"].([]interface{})
	assert.GreaterOrEqual(t, len(msgs), 1)
}

// ---------------------------------------------------------------------------
// MistralAdapter response/stream delegation
// ---------------------------------------------------------------------------

func TestMistralAdapter_DecodeResponse(t *testing.T) {
	body := `{
		"id": "chatcmpl-mistral-123",
		"object": "chat.completion",
		"model": "mistral-large-latest",
		"choices": [{
			"index": 0,
			"message": {"role": "assistant", "content": "Hello!"},
			"finish_reason": "stop"
		}],
		"usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}
	}`

	adapter := &MistralAdapter{}
	cr, err := adapter.DecodeResponse([]byte(body))
	require.NoError(t, err)
	assert.Equal(t, "chatcmpl-mistral-123", cr.ID)
	assert.Equal(t, "Hello!", cr.Content)
	assert.Equal(t, "stop", cr.FinishReason)
	assert.Equal(t, 8, cr.Usage.TotalTokens)
}

func TestMistralAdapter_EncodeResponse(t *testing.T) {
	cr := &CanonicalResponse{
		ID:           "resp-1",
		Model:        "mistral-large-latest",
		Content:      "Hi",
		Role:         "assistant",
		FinishReason: "stop",
		Usage:        &CanonicalUsage{PromptTokens: 3, CompletionTokens: 1, TotalTokens: 4},
	}

	adapter := &MistralAdapter{}
	out, err := adapter.EncodeResponse(cr)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))
	assert.Equal(t, "chat.completion", result["object"])
}

func TestMistralAdapter_DecodeStreamChunk(t *testing.T) {
	chunk := `{"id":"chatcmpl-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}`

	adapter := &MistralAdapter{}
	sc, err := adapter.DecodeStreamChunk([]byte(chunk))
	require.NoError(t, err)
	assert.Equal(t, "Hello", sc.Delta)
}

func TestMistralAdapter_EncodeStreamChunk(t *testing.T) {
	chunk := &CanonicalStreamChunk{
		ID:    "chunk-1",
		Model: "mistral-large-latest",
		Delta: "world",
	}

	adapter := &MistralAdapter{}
	lines, err := adapter.EncodeStreamChunk(chunk)
	require.NoError(t, err)
	require.NotEmpty(t, lines)
}

// ---------------------------------------------------------------------------
// Registry: Mistral adapter is registered
// ---------------------------------------------------------------------------

func TestRegistry_MistralAdapterRegistered(t *testing.T) {
	a, err := testRegistry().GetAdapter(FormatMistral)
	require.NoError(t, err)
	assert.IsType(t, &MistralAdapter{}, a)
}

func TestRegistry_MistralNotSameWireFormatAsOpenAI(t *testing.T) {
	assert.False(t, IsSameWireFormat(FormatMistral, FormatOpenAI),
		"Mistral and OpenAI should NOT be wire-compatible (Mistral has its own adapter)")
}

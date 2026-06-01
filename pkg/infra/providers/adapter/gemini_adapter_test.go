package adapter

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Canonical roundtrip: Gemini → Canonical → Gemini
// ---------------------------------------------------------------------------

func TestCanonical_Gemini_Roundtrip(t *testing.T) {
	input := `{
		"contents": [
			{"role": "user", "parts": [{"text": "Hello"}]},
			{"role": "model", "parts": [{"text": "Hi!"}]}
		],
		"systemInstruction": {"parts": [{"text": "Be concise."}]},
		"generationConfig": {
			"maxOutputTokens": 50,
			"temperature": 0.5
		}
	}`

	adapter := &GeminiAdapter{}

	canonical, err := adapter.DecodeRequest([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, "Be concise.", canonical.System)
	assert.Len(t, canonical.Messages, 2)
	assert.Equal(t, "user", canonical.Messages[0].Role)
	assert.Equal(t, "assistant", canonical.Messages[1].Role) // model → assistant
	assert.Equal(t, 50, canonical.MaxTokens)

	encoded, err := adapter.EncodeRequest(canonical)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(encoded, &result))
	contents := result["contents"].([]interface{})
	assert.Len(t, contents, 2)
	second := contents[1].(map[string]interface{})
	assert.Equal(t, "model", second["role"]) // assistant → model
}

// ---------------------------------------------------------------------------
// Gemini functionCall response: real-world payload
// ---------------------------------------------------------------------------

func TestGemini_DecodeResponse_FunctionCall_RealPayload(t *testing.T) {
	body := `{
		"candidates": [{
			"content": {
				"parts": [{
					"functionCall": {
						"name": "database_agent",
						"args": {
							"query": "cliente Juan"
						}
					},
					"thoughtSignature": "CqACAb4+9vud..."
				}],
				"role": "model"
			},
			"finishReason": "STOP",
			"index": 0,
			"finishMessage": "Model generated function call(s)."
		}],
		"usageMetadata": {
			"promptTokenCount": 640,
			"candidatesTokenCount": 16,
			"totalTokenCount": 712,
			"promptTokensDetails": [{
				"modality": "TEXT",
				"tokenCount": 640
			}],
			"thoughtsTokenCount": 56
		},
		"modelVersion": "gemini-2.5-flash",
		"responseId": "5QKOaf_DL97ensEPo5OwkQg"
	}`

	adapter := &GeminiAdapter{}

	// Decode to canonical
	cr, err := adapter.DecodeResponse([]byte(body))
	require.NoError(t, err)

	// ID, Model, Role
	assert.Equal(t, "5QKOaf_DL97ensEPo5OwkQg", cr.ID)
	assert.Equal(t, "gemini-2.5-flash", cr.Model)
	assert.Equal(t, "assistant", cr.Role)

	// Content should be empty (only functionCall, no text)
	assert.Equal(t, "", cr.Content)

	// Tool calls
	require.Len(t, cr.ToolCalls, 1)
	assert.Equal(t, "database_agent", cr.ToolCalls[0].Name)
	assert.Contains(t, cr.ToolCalls[0].Arguments, "cliente Juan")

	// FinishReason: functionCall → tool_calls
	assert.Equal(t, "tool_calls", cr.FinishReason)

	// Usage
	require.NotNil(t, cr.Usage)
	assert.Equal(t, 640, cr.Usage.InputTokens)
	assert.Equal(t, 16, cr.Usage.OutputTokens)
	assert.Equal(t, 712, cr.Usage.TotalTokens)

	// Cross-format: Gemini → Canonical → OpenAI
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
	tcObj := toolCalls[0].(map[string]interface{})
	assert.Equal(t, "function", tcObj["type"])
	fnObj := tcObj["function"].(map[string]interface{})
	assert.Equal(t, "database_agent", fnObj["name"])
	assert.Contains(t, fnObj["arguments"], "cliente Juan")

	// Roundtrip: Canonical → Gemini → Canonical
	geminiBody, err := adapter.EncodeResponse(cr)
	require.NoError(t, err)

	cr2, err := adapter.DecodeResponse(geminiBody)
	require.NoError(t, err)
	assert.Equal(t, cr.ID, cr2.ID)
	assert.Equal(t, cr.Model, cr2.Model)
	assert.Equal(t, "tool_calls", cr2.FinishReason)
	require.Len(t, cr2.ToolCalls, 1)
	assert.Equal(t, "database_agent", cr2.ToolCalls[0].Name)
}

// ---------------------------------------------------------------------------
// Gemini → OpenAI: tool schema type conversion (STRING → string)
// ---------------------------------------------------------------------------

func TestGemini_ToolSchemaTypes_ConvertedToOpenAI(t *testing.T) {
	// Gemini-format request with UPPER_CASE types
	input := `{
		"contents": [{"role": "user", "parts": [{"text": "busca Juan"}]}],
		"tools": [{
			"functionDeclarations": [{
				"name": "database_agent",
				"description": "Query the database",
				"parameters": {
					"type": "OBJECT",
					"properties": {
						"query": {"type": "STRING"},
						"limit": {"type": "INTEGER"}
					},
					"required": ["query"]
				}
			}]
		}]
	}`

	// Decode Gemini → Canonical
	gemini := &GeminiAdapter{}
	canonical, err := gemini.DecodeRequest([]byte(input))
	require.NoError(t, err)
	require.Len(t, canonical.Tools, 1)

	// Schema should have lowercase types now
	schema := canonical.Tools[0].Schema
	assert.Equal(t, "object", schema["type"])
	props := schema["properties"].(map[string]interface{})
	assert.Equal(t, "string", props["query"].(map[string]interface{})["type"])
	assert.Equal(t, "integer", props["limit"].(map[string]interface{})["type"])

	// Encode Canonical → OpenAI
	openai := &OpenAIAdapter{}
	openaiBody, err := openai.EncodeRequest(canonical)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(openaiBody, &result))

	tools := result["tools"].([]interface{})
	require.Len(t, tools, 1)
	fn := tools[0].(map[string]interface{})["function"].(map[string]interface{})
	params := fn["parameters"].(map[string]interface{})

	// OpenAI gets lowercase types — no more "STRING is not valid" errors
	assert.Equal(t, "object", params["type"])
	openaiProps := params["properties"].(map[string]interface{})
	assert.Equal(t, "string", openaiProps["query"].(map[string]interface{})["type"])
	assert.Equal(t, "integer", openaiProps["limit"].(map[string]interface{})["type"])
}

func TestOpenAI_ToolSchemaTypes_ConvertedToGemini(t *testing.T) {
	// OpenAI-format request with lowercase types
	input := `{
		"model": "gemini-2.5-flash",
		"messages": [{"role": "user", "content": "busca Juan"}],
		"tools": [{
			"type": "function",
			"function": {
				"name": "db_agent",
				"parameters": {
					"type": "object",
					"properties": {
						"q": {"type": "string"}
					}
				}
			}
		}]
	}`

	// Decode OpenAI → Canonical
	oa := &OpenAIAdapter{}
	canonical, err := oa.DecodeRequest([]byte(input))
	require.NoError(t, err)

	// Encode Canonical → Gemini
	gemini := &GeminiAdapter{}
	geminiBody, err := gemini.EncodeRequest(canonical)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(geminiBody, &result))

	tools := result["tools"].([]interface{})
	require.Len(t, tools, 1)
	decls := tools[0].(map[string]interface{})["functionDeclarations"].([]interface{})
	params := decls[0].(map[string]interface{})["parameters"].(map[string]interface{})

	// Gemini gets UPPER_CASE types
	assert.Equal(t, "OBJECT", params["type"])
	geminiProps := params["properties"].(map[string]interface{})
	assert.Equal(t, "STRING", geminiProps["q"].(map[string]interface{})["type"])
}

func TestUsageExtraction_Gemini(t *testing.T) {
	runUsageCases(t, &GeminiAdapter{}, []usageCase{
		{
			name:      "response with usage",
			body:      []byte(`{"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":40,"candidatesTokenCount":10,"totalTokenCount":50}}`),
			path:      "response",
			wantUsage: &CanonicalUsage{InputTokens: 40, OutputTokens: 10, TotalTokens: 50},
		},
		{
			name:      "response no usage",
			body:      []byte(`{"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]},"finishReason":"STOP"}]}`),
			path:      "response",
			wantUsage: nil,
		},
		{
			name:      "stream final chunk with usage",
			body:      []byte(`{"candidates":[{"content":{"role":"model","parts":[{"text":""}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":40,"candidatesTokenCount":10,"totalTokenCount":50}}`),
			path:      "stream",
			wantUsage: &CanonicalUsage{InputTokens: 40, OutputTokens: 10, TotalTokens: 50},
		},
		{
			name:      "stream no usage",
			body:      []byte(`{"candidates":[{"content":{"role":"model","parts":[{"text":"Hi"}]}}]}`),
			path:      "stream",
			wantUsage: nil,
		},
	})
}

func TestUsageExtraction_Gemini_TotalSynthesized(t *testing.T) {
	body := []byte(`{"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":8,"candidatesTokenCount":4}}`)
	cr, err := (&GeminiAdapter{}).DecodeResponse(body)
	require.NoError(t, err)
	assert.Equal(t, &CanonicalUsage{InputTokens: 8, OutputTokens: 4, TotalTokens: 12}, cr.Usage)
}

func TestUsageSubCounts_Gemini_CachedAndThoughts(t *testing.T) {
	body := []byte(`{"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":40,"candidatesTokenCount":10,"totalTokenCount":50,"cachedContentTokenCount":3,"thoughtsTokenCount":5}}`)
	cr, err := (&GeminiAdapter{}).DecodeResponse(body)
	require.NoError(t, err)
	require.NotNil(t, cr.Usage)
	assert.Equal(t, 3, cr.Usage.CachedInputTokens)
	assert.Equal(t, 5, cr.Usage.ReasoningOutputTokens)
	assert.Equal(t, 40, cr.Usage.InputTokens, "sub-counts are inclusive, not subtracted")
	assert.Equal(t, 10, cr.Usage.OutputTokens, "sub-counts are inclusive, not subtracted")
}

func TestUsageExtraction_Gemini_Stream_ToolUseInput(t *testing.T) {
	body := []byte(`{"candidates":[{"content":{"role":"model","parts":[{"text":""}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":40,"candidatesTokenCount":10,"totalTokenCount":50,"toolUsePromptTokenCount":6}}`)
	sc, err := (&GeminiAdapter{}).DecodeStreamChunk(body)
	require.NoError(t, err)
	require.NotNil(t, sc)
	require.NotNil(t, sc.Usage)
	assert.Equal(t, 6, sc.Usage.ToolUseInputTokens)
}

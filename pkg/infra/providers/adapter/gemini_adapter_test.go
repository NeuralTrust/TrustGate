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
	assert.Equal(t, 72, cr.Usage.OutputTokens, "candidates 16 + thoughts 56, which is what Gemini bills")
	assert.Equal(t, 56, cr.Usage.ReasoningOutputTokens)
	assert.Equal(t, 712, cr.Usage.TotalTokens)
	assert.Equal(t, cr.Usage.InputTokens+cr.Usage.OutputTokens, cr.Usage.TotalTokens)

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
	body := []byte(`{"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":40,"candidatesTokenCount":10,"totalTokenCount":55,"cachedContentTokenCount":3,"thoughtsTokenCount":5}}`)
	cr, err := (&GeminiAdapter{}).DecodeResponse(body)
	require.NoError(t, err)
	require.NotNil(t, cr.Usage)
	assert.Equal(t, 3, cr.Usage.CachedInputTokens)
	assert.Equal(t, 5, cr.Usage.ReasoningOutputTokens)
	assert.Equal(t, 40, cr.Usage.InputTokens, "cachedContentTokenCount is already inside promptTokenCount")
	assert.Equal(t, 15, cr.Usage.OutputTokens, "thoughtsTokenCount is disjoint from candidates and billed as output")
	assert.Equal(t, 55, cr.Usage.TotalTokens)
}

func TestUsageExtraction_Gemini_Stream_ToolUseInput(t *testing.T) {
	body := []byte(`{"candidates":[{"content":{"role":"model","parts":[{"text":""}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":40,"candidatesTokenCount":10,"totalTokenCount":56,"toolUsePromptTokenCount":6}}`)
	sc, err := (&GeminiAdapter{}).DecodeStreamChunk(body)
	require.NoError(t, err)
	require.NotNil(t, sc)
	require.NotNil(t, sc.Usage)
	assert.Equal(t, 6, sc.Usage.ToolUseInputTokens)
	assert.Equal(t, 46, sc.Usage.InputTokens, "toolUsePromptTokenCount is disjoint from prompt and billed as input")
	assert.Equal(t, 10, sc.Usage.OutputTokens)
	assert.Equal(t, 56, sc.Usage.TotalTokens)
}

func TestGemini_DecodeRequest_SkipsThoughtParts(t *testing.T) {
	input := `{
		"contents":[{
			"role":"user",
			"parts":[
				{"thought":true,"text":"secret thought"},
				{"text":"Weather?"}
			]
		}]
	}`
	cr, err := (&GeminiAdapter{}).DecodeRequest([]byte(input))
	require.NoError(t, err)
	require.Len(t, cr.Messages, 1)
	assert.Equal(t, "Weather?", cr.Messages[0].Content)
	assert.NotContains(t, cr.Messages[0].Content, "secret")
}

func TestGemini_DecodeStreamChunk_SkipsThoughtParts(t *testing.T) {
	chunk := []byte(`{"candidates":[{"content":{"role":"model","parts":[{"thought":true,"text":"secret"},{"text":"hello"}]}}]}`)
	sc, err := (&GeminiAdapter{}).DecodeStreamChunk(chunk)
	require.NoError(t, err)
	require.NotNil(t, sc)
	assert.Equal(t, "hello", sc.Delta)
	assert.NotContains(t, sc.Delta, "secret")
	assert.Equal(t, "secret", sc.ReasoningDelta)
}

func TestGemini_DecodeStreamChunk_ThoughtSignature(t *testing.T) {
	tests := []struct {
		name          string
		chunk         string
		wantDelta     string
		wantReasoning string
		wantCalls     []StreamToolCallDelta
	}{
		{
			name:      "gemini 3 signed functionCall",
			chunk:     `{"candidates":[{"content":{"parts":[{"functionCall":{"name":"get_weather","args":{"city":"Paris"},"id":"call_235554"},"thoughtSignature":"EoUECoIEAWkUfRO7"}],"role":"model"},"index":0}],"modelVersion":"gemini-3-flash-preview","responseId":"c9izarDqFZvR28oP9_Wo-QQ"}`,
			wantCalls: []StreamToolCallDelta{{Index: 0, ID: "call_235554", Name: "get_weather", ArgumentsDelta: `{"city":"Paris"}`}},
		},
		{
			name:      "gemini 2.5 signed functionCall without id",
			chunk:     `{"candidates":[{"content":{"parts":[{"functionCall":{"name":"get_weather","args":{"city":"Paris"}},"thoughtSignature":"CiQBaRR9Eyw3lLUk"}],"role":"model"},"finishReason":"STOP","index":0}],"modelVersion":"gemini-2.5-flash"}`,
			wantCalls: []StreamToolCallDelta{{Index: 0, ID: "get_weather", Name: "get_weather", ArgumentsDelta: `{"city":"Paris"}`}},
		},
		{
			name:      "signed text",
			chunk:     `{"candidates":[{"content":{"parts":[{"text":"Hi there, friend.","thoughtSignature":"EqQHCqEHAWkUfRNY"}],"role":"model"},"index":0}],"modelVersion":"gemini-3-flash-preview"}`,
			wantDelta: "Hi there, friend.",
		},
		{
			name:          "thought part",
			chunk:         `{"candidates":[{"content":{"parts":[{"text":"**Determining Paris' Weather**","thought":true}],"role":"model"},"index":0}],"modelVersion":"gemini-2.5-flash"}`,
			wantReasoning: "**Determining Paris' Weather**",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc, err := (&GeminiAdapter{}).DecodeStreamChunk([]byte(tt.chunk))
			require.NoError(t, err)
			require.NotNil(t, sc)
			assert.Equal(t, tt.wantDelta, sc.Delta)
			assert.Equal(t, tt.wantReasoning, sc.ReasoningDelta)
			assert.Equal(t, tt.wantCalls, sc.ToolCallDeltas)
		})
	}
}

func TestGemini_DecodeResponse_ThoughtSignature(t *testing.T) {
	tests := []struct {
		name          string
		body          string
		wantContent   string
		wantReasoning *CanonicalReasoning
		wantCalls     []CanonicalToolCall
	}{
		{
			name:        "gemini 3 signed answer is content only",
			body:        `{"candidates":[{"content":{"parts":[{"text":"Hi there, friend.","thoughtSignature":"EqQHCqEHAWkUfRNY"}],"role":"model"},"finishReason":"STOP","index":0}],"modelVersion":"gemini-3-flash-preview"}`,
			wantContent: "Hi there, friend.",
		},
		{
			name:      "gemini 3 signed functionCall keeps its id",
			body:      `{"candidates":[{"content":{"parts":[{"functionCall":{"name":"get_weather","args":{"city":"Paris"},"id":"call_260240"},"thoughtSignature":"EpUCCpICAWkUfRPy"}],"role":"model"},"finishReason":"STOP","index":0}],"modelVersion":"gemini-3-flash-preview"}`,
			wantCalls: []CanonicalToolCall{{ID: "call_260240", Name: "get_weather", Arguments: `{"city":"Paris"}`}},
		},
		{
			name:          "thought part is reasoning",
			body:          `{"candidates":[{"content":{"parts":[{"text":"thinking","thought":true},{"text":"answer","thoughtSignature":"CiQBaRR9"}],"role":"model"},"finishReason":"STOP","index":0}]}`,
			wantContent:   "answer",
			wantReasoning: &CanonicalReasoning{ThinkingText: "thinking"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr, err := (&GeminiAdapter{}).DecodeResponse([]byte(tt.body))
			require.NoError(t, err)
			assert.Equal(t, tt.wantContent, cr.Content)
			assert.Equal(t, tt.wantReasoning, cr.Reasoning)
			assert.Equal(t, tt.wantCalls, cr.ToolCalls)
		})
	}
}

func TestGemini_DecodeRequest_KeepsSignedParts(t *testing.T) {
	input := `{
		"contents":[
			{"role":"user","parts":[{"text":"Weather in Paris?"}]},
			{"role":"model","parts":[
				{"thought":true,"text":"secret"},
				{"text":"Checking.","thoughtSignature":"EqQHCqEHAWkUfRNY"},
				{"functionCall":{"name":"get_weather","args":{"city":"Paris"},"id":"call_235554"},"thoughtSignature":"EoUECoIEAWkUfRO7"}
			]},
			{"role":"user","parts":[{"functionResponse":{"name":"get_weather","id":"call_235554","response":{"result":"sunny"}}}]}
		]
	}`
	cr, err := (&GeminiAdapter{}).DecodeRequest([]byte(input))
	require.NoError(t, err)
	require.Len(t, cr.Messages, 3)
	assistant := cr.Messages[1]
	assert.Equal(t, "assistant", assistant.Role)
	assert.Equal(t, "Checking.", assistant.Content)
	assert.Equal(t, []CanonicalToolCall{{ID: "call_235554", Name: "get_weather", Arguments: `{"city":"Paris"}`}}, assistant.ToolCalls)
	assert.Equal(t, CanonicalMessage{Role: "tool", ToolCallID: "call_235554", Content: `{"result":"sunny"}`}, cr.Messages[2])
}

func TestGemini_EncodeRequest_ThoughtSignatureSentinel(t *testing.T) {
	messages := []CanonicalMessage{
		{Role: "user", Content: "Weather in Paris and Rome?"},
		{Role: "assistant", Content: "Checking.", ToolCalls: []CanonicalToolCall{
			{ID: "call_1", Name: "get_weather", Arguments: `{"city":"Paris"}`},
			{ID: "call_2", Name: "get_weather", Arguments: `{"city":"Rome"}`},
		}},
		{Role: "tool", ToolCallID: "call_1", Content: `{"ok":true}`},
		{Role: "tool", ToolCallID: "call_2", Content: `{"ok":true}`},
		{Role: "assistant", ToolCalls: []CanonicalToolCall{{ID: "get_time", Name: "get_time", Arguments: `{}`}}},
		{Role: "tool", ToolCallID: "get_time", Content: `{"ok":true}`},
		{Role: "assistant", Content: "Sunny in both."},
	}

	body, err := (&GeminiAdapter{}).EncodeRequest(&CanonicalRequest{Model: "gemini", Messages: messages})
	require.NoError(t, err)

	var req geminiRequest
	require.NoError(t, json.Unmarshal(body, &req))
	require.Len(t, req.Contents, 6)
	signatures := make([][]string, len(req.Contents))
	for i, c := range req.Contents {
		for _, p := range c.Parts {
			signatures[i] = append(signatures[i], p.ThoughtSignature)
		}
	}
	assert.Equal(t, [][]string{
		{""},
		{"", geminiSkipThoughtSignature, ""},
		{"", ""},
		{geminiSkipThoughtSignature},
		{""},
		{""},
	}, signatures)

	firstTurn := req.Contents[1].Parts
	assert.Equal(t, "call_1", firstTurn[1].FunctionCall.ID)
	assert.Equal(t, "call_2", firstTurn[2].FunctionCall.ID)
	results := req.Contents[2].Parts
	assert.Equal(t, geminiFuncResponse{ID: "call_1", Name: "get_weather", Response: map[string]interface{}{"ok": true}}, *results[0].FunctionResponse)
	assert.Equal(t, geminiFuncResponse{ID: "call_2", Name: "get_weather", Response: map[string]interface{}{"ok": true}}, *results[1].FunctionResponse)
	assert.Empty(t, req.Contents[3].Parts[0].FunctionCall.ID, "an id that is the function name is not sent")
	assert.Empty(t, req.Contents[4].Parts[0].FunctionResponse.ID)
}

func TestGemini_DecodeRequest_PairsResponsesWithoutIDs(t *testing.T) {
	tests := []struct {
		name      string
		model     string
		responses string
		want      []string
	}{
		{
			name:      "call with id, response without",
			model:     `{"functionCall":{"name":"get_weather","args":{"city":"Paris"},"id":"call_1"}}`,
			responses: `{"functionResponse":{"name":"get_weather","response":{"ok":true}}}`,
			want:      []string{"call_1"},
		},
		{
			name: "same-name calls answered in order",
			model: `{"functionCall":{"name":"get_weather","args":{"city":"Paris"},"id":"call_1"}},
				{"functionCall":{"name":"get_weather","args":{"city":"Rome"},"id":"call_2"}}`,
			responses: `{"functionResponse":{"name":"get_weather","response":{"ok":1}}},
				{"functionResponse":{"name":"get_weather","response":{"ok":2}}}`,
			want: []string{"call_1", "call_2"},
		},
		{
			name: "different names",
			model: `{"functionCall":{"name":"get_weather","args":{},"id":"call_1"}},
				{"functionCall":{"name":"get_time","args":{},"id":"call_2"}}`,
			responses: `{"functionResponse":{"name":"get_time","response":{"ok":1}}},
				{"functionResponse":{"name":"get_weather","response":{"ok":2}}}`,
			want: []string{"call_2", "call_1"},
		},
		{
			name: "response with id takes its own call",
			model: `{"functionCall":{"name":"get_weather","args":{},"id":"call_1"}},
				{"functionCall":{"name":"get_weather","args":{},"id":"call_2"}}`,
			responses: `{"functionResponse":{"name":"get_weather","id":"call_1","response":{"ok":1}}},
				{"functionResponse":{"name":"get_weather","response":{"ok":2}}}`,
			want: []string{"call_1", "call_2"},
		},
		{
			name:      "no matching call keeps the name",
			model:     `{"functionCall":{"name":"get_weather","args":{},"id":"call_1"}}`,
			responses: `{"functionResponse":{"name":"get_time","response":{"ok":1}}}`,
			want:      []string{"get_time"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"contents":[
				{"role":"user","parts":[{"text":"hi"}]},
				{"role":"model","parts":[` + tt.model + `]},
				{"role":"user","parts":[` + tt.responses + `]}
			]}`
			cr, err := (&GeminiAdapter{}).DecodeRequest([]byte(body))
			require.NoError(t, err)
			var got []string
			for _, m := range cr.Messages {
				if m.Role == "tool" {
					got = append(got, m.ToolCallID)
				}
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGemini_DecodeRequest_PairsOnlyWithThePrecedingModelTurn(t *testing.T) {
	body := `{"contents":[
		{"role":"model","parts":[{"functionCall":{"name":"get_weather","args":{},"id":"call_1"}},{"functionCall":{"name":"get_weather","args":{},"id":"call_2"}}]},
		{"role":"user","parts":[{"functionResponse":{"name":"get_weather","response":{"ok":1}}}]},
		{"role":"model","parts":[{"functionCall":{"name":"get_weather","args":{},"id":"call_3"}}]},
		{"role":"user","parts":[{"functionResponse":{"name":"get_weather","response":{"ok":2}}}]}
	]}`
	cr, err := (&GeminiAdapter{}).DecodeRequest([]byte(body))
	require.NoError(t, err)
	var got []string
	for _, m := range cr.Messages {
		if m.Role == "tool" {
			got = append(got, m.ToolCallID)
		}
	}
	assert.Equal(t, []string{"call_1", "call_3"}, got)
}

func TestGemini_EncodeRequest_SentinelPerModelTurn(t *testing.T) {
	messages := []CanonicalMessage{
		{Role: "user", Content: "Weather and time?"},
		{Role: "assistant", Content: "Checking the weather.", ToolCalls: []CanonicalToolCall{{ID: "call_1", Name: "get_weather", Arguments: `{}`}}},
		{Role: "assistant", ToolCalls: []CanonicalToolCall{
			{ID: "call_2", Name: "get_time", Arguments: `{}`},
			{ID: "call_3", Name: "get_date", Arguments: `{}`},
		}},
	}
	body, err := (&GeminiAdapter{}).EncodeRequest(&CanonicalRequest{Messages: messages})
	require.NoError(t, err)

	var req geminiRequest
	require.NoError(t, json.Unmarshal(body, &req))
	require.Len(t, req.Contents, 3)
	textTurn := req.Contents[1].Parts
	require.Len(t, textTurn, 2)
	assert.Equal(t, "Checking the weather.", textTurn[0].Text)
	assert.Empty(t, textTurn[0].ThoughtSignature)
	assert.Equal(t, geminiSkipThoughtSignature, textTurn[1].ThoughtSignature)
	callTurn := req.Contents[2].Parts
	require.Len(t, callTurn, 2)
	assert.Equal(t, geminiSkipThoughtSignature, callTurn[0].ThoughtSignature)
	assert.Empty(t, callTurn[1].ThoughtSignature)
}

func TestGemini_EncodeRequest_VertexKeepsPlainToolTurns(t *testing.T) {
	req := &CanonicalRequest{Messages: []CanonicalMessage{
		{Role: "user", Content: "Weather?"},
		{Role: "assistant", ToolCalls: []CanonicalToolCall{{ID: "call_1", Name: "get_weather", Arguments: `{"city":"Paris"}`}}},
		{Role: "tool", ToolCallID: "call_1", Content: `{"ok":true}`},
	}}
	reg := NewRegistry()
	tests := []struct {
		name          string
		target        Format
		wantCallID    string
		wantResultID  string
		wantSignature string
	}{
		{name: "gemini api", target: FormatGemini, wantCallID: "call_1", wantResultID: "call_1", wantSignature: geminiSkipThoughtSignature},
		{name: "vertex", target: FormatVertex},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ad, err := reg.GetAdapter(tt.target)
			require.NoError(t, err)
			body, err := ad.EncodeRequest(req)
			require.NoError(t, err)

			var out geminiRequest
			require.NoError(t, json.Unmarshal(body, &out))
			require.Len(t, out.Contents, 3)
			call := out.Contents[1].Parts[0]
			assert.Equal(t, tt.wantSignature, call.ThoughtSignature)
			assert.Equal(t, geminiFunctionCall{ID: tt.wantCallID, Name: "get_weather", Args: map[string]interface{}{"city": "Paris"}}, *call.FunctionCall)
			assert.Equal(t, geminiFuncResponse{ID: tt.wantResultID, Name: "get_weather", Response: map[string]interface{}{"ok": true}}, *out.Contents[2].Parts[0].FunctionResponse)
		})
	}
}

func TestGemini_DecodeResponse_ThoughtOnlyFallsBackToContent(t *testing.T) {
	tests := []struct {
		name        string
		parts       string
		wantContent string
		wantCalls   int
	}{
		{
			name:        "only thoughts",
			parts:       `{"text":"thinking","thought":true}`,
			wantContent: "thinking",
		},
		{
			name:      "thoughts and a call",
			parts:     `{"text":"thinking","thought":true},{"functionCall":{"name":"get_weather","args":{}}}`,
			wantCalls: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"candidates":[{"content":{"parts":[` + tt.parts + `],"role":"model"},"finishReason":"STOP"}]}`
			for _, ad := range []*GeminiAdapter{{}, NewVertexAdapter()} {
				cr, err := ad.DecodeResponse([]byte(body))
				require.NoError(t, err)
				assert.Equal(t, tt.wantContent, cr.Content)
				assert.Len(t, cr.ToolCalls, tt.wantCalls)
				assert.Equal(t, &CanonicalReasoning{ThinkingText: "thinking"}, cr.Reasoning)
			}
		})
	}
}

func TestGeminiCallIndexer_Renumber(t *testing.T) {
	var g GeminiCallIndexer
	first := []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "a"}, {Index: 1, ID: "call_2", Name: "b"}}
	second := []StreamToolCallDelta{{Index: 0, ID: "call_3", Name: "a"}}
	continuation := []StreamToolCallDelta{{Index: 0, ArgumentsDelta: "{}"}}
	g.Renumber(first)
	g.Renumber(second)
	g.Renumber(continuation)
	assert.Equal(t, 0, first[0].Index)
	assert.Equal(t, 1, first[1].Index)
	assert.Equal(t, 2, second[0].Index)
	assert.Equal(t, 2, continuation[0].Index)

	var nilIndexer *GeminiCallIndexer
	untouched := []StreamToolCallDelta{{Index: 4, ID: "x"}}
	nilIndexer.Renumber(untouched)
	assert.Equal(t, 4, untouched[0].Index)
}

// Gemini reports thoughtsTokenCount and toolUsePromptTokenCount DISJOINT from
// candidatesTokenCount and promptTokenCount, and bills them at the output and
// input rate respectively. Cost prices only InputTokens and OutputTokens, so the
// adapter has to fold them in. This invariant is what makes a fabricated usage
// fixture impossible to write: any payload that violates it is not real Gemini.
func TestGeminiUsage_FoldsAdditiveSubCountsAndReconciles(t *testing.T) {
	cases := []struct {
		name      string
		usage     string
		wantIn    int
		wantOut   int
		wantTotal int
	}{
		{
			name:      "thoughts are billed as output",
			usage:     `{"promptTokenCount":38,"candidatesTokenCount":223,"totalTokenCount":1088,"thoughtsTokenCount":827}`,
			wantIn:    38,
			wantOut:   1050,
			wantTotal: 1088,
		},
		{
			name:      "tool-use prompt tokens are billed as input",
			usage:     `{"promptTokenCount":40,"candidatesTokenCount":10,"totalTokenCount":56,"toolUsePromptTokenCount":6}`,
			wantIn:    46,
			wantOut:   10,
			wantTotal: 56,
		},
		{
			name:      "cached content is already inside the prompt count",
			usage:     `{"promptTokenCount":40,"candidatesTokenCount":10,"totalTokenCount":50,"cachedContentTokenCount":30}`,
			wantIn:    40,
			wantOut:   10,
			wantTotal: 50,
		},
		{
			name:      "every additive count at once",
			usage:     `{"promptTokenCount":26,"candidatesTokenCount":3333,"totalTokenCount":5663,"thoughtsTokenCount":2297,"toolUsePromptTokenCount":7,"cachedContentTokenCount":11}`,
			wantIn:    33,
			wantOut:   5630,
			wantTotal: 5663,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(`{"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]},` +
				`"finishReason":"STOP"}],"usageMetadata":` + tc.usage + `}`)
			cr, err := (&GeminiAdapter{}).DecodeResponse(body)
			require.NoError(t, err)
			require.NotNil(t, cr.Usage)

			assert.Equal(t, tc.wantIn, cr.Usage.InputTokens)
			assert.Equal(t, tc.wantOut, cr.Usage.OutputTokens)
			assert.Equal(t, tc.wantTotal, cr.Usage.TotalTokens)
			assert.Equal(t, cr.Usage.InputTokens+cr.Usage.OutputTokens, cr.Usage.TotalTokens,
				"a folded usage view must reconcile: anything else is unpriced tokens")
			assert.LessOrEqual(t, cr.Usage.ReasoningOutputTokens, cr.Usage.OutputTokens)
			assert.LessOrEqual(t, cr.Usage.CachedInputTokens, cr.Usage.InputTokens)
			assert.LessOrEqual(t, cr.Usage.ToolUseInputTokens, cr.Usage.InputTokens)
		})
	}
}

// Re-encoding to Gemini must rebuild the disjoint wire counts, or a client
// metering off the gateway's own response sees a payload whose parts do not sum
// to its total.
func TestGeminiUsage_EncodeRebuildsDisjointWireCounts(t *testing.T) {
	body := []byte(`{"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]},"finishReason":"STOP"}],` +
		`"usageMetadata":{"promptTokenCount":38,"candidatesTokenCount":223,"totalTokenCount":1095,` +
		`"thoughtsTokenCount":827,"toolUsePromptTokenCount":7}}`)
	a := &GeminiAdapter{}
	cr, err := a.DecodeResponse(body)
	require.NoError(t, err)

	out, err := a.EncodeResponse(cr)
	require.NoError(t, err)

	var got struct {
		UsageMetadata struct {
			PromptTokenCount        int `json:"promptTokenCount"`
			CandidatesTokenCount    int `json:"candidatesTokenCount"`
			TotalTokenCount         int `json:"totalTokenCount"`
			ThoughtsTokenCount      int `json:"thoughtsTokenCount"`
			ToolUsePromptTokenCount int `json:"toolUsePromptTokenCount"`
		} `json:"usageMetadata"`
	}
	require.NoError(t, json.Unmarshal(out, &got))
	u := got.UsageMetadata

	assert.Equal(t, 38, u.PromptTokenCount)
	assert.Equal(t, 223, u.CandidatesTokenCount)
	assert.Equal(t, 827, u.ThoughtsTokenCount)
	assert.Equal(t, 7, u.ToolUsePromptTokenCount)
	assert.Equal(t, 1095, u.TotalTokenCount)
	assert.Equal(t,
		u.PromptTokenCount+u.CandidatesTokenCount+u.ThoughtsTokenCount+u.ToolUsePromptTokenCount,
		u.TotalTokenCount, "the re-encoded payload must satisfy Gemini's own arithmetic")
}

func TestGemini_EncodeRequest_GroupsToolResultsOfOneTurn(t *testing.T) {
	tests := []struct {
		name      string
		calls     []CanonicalToolCall
		wantNames []string
	}{
		{
			name:      "two functions",
			calls:     []CanonicalToolCall{{ID: "call_1", Name: "get_weather", Arguments: `{"city":"Paris"}`}, {ID: "call_2", Name: "get_time", Arguments: `{"tz":"CET"}`}},
			wantNames: []string{"get_weather", "get_time"},
		},
		{
			name:      "same function twice",
			calls:     []CanonicalToolCall{{ID: "get_weather", Name: "get_weather", Arguments: `{"city":"Paris"}`}, {ID: "toolu_ABC_1", Name: "get_weather", Arguments: `{"city":"Rome"}`}},
			wantNames: []string{"get_weather", "get_weather"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			messages := []CanonicalMessage{
				{Role: "user", Content: "question"},
				{Role: "assistant", ToolCalls: tt.calls},
			}
			for _, c := range tt.calls {
				messages = append(messages, CanonicalMessage{Role: "tool", ToolCallID: c.ID, Content: `{"ok":true}`})
			}
			messages = append(messages, CanonicalMessage{Role: "user", Content: "thanks"})

			body, err := (&GeminiAdapter{}).EncodeRequest(&CanonicalRequest{Model: "gemini", Messages: messages})
			require.NoError(t, err)

			var req geminiRequest
			require.NoError(t, json.Unmarshal(body, &req))
			require.Len(t, req.Contents, 4)
			assert.Equal(t, "model", req.Contents[1].Role)
			assert.Len(t, req.Contents[1].Parts, len(tt.calls))
			results := req.Contents[2]
			assert.Equal(t, "user", results.Role)
			var names []string
			for _, p := range results.Parts {
				require.NotNil(t, p.FunctionResponse)
				names = append(names, p.FunctionResponse.Name)
			}
			assert.Equal(t, tt.wantNames, names)
			assert.Equal(t, "thanks", req.Contents[3].Parts[0].Text)
		})
	}
}

func TestGemini_EncodeRequest_SkippedMessageEndsToolResultGroup(t *testing.T) {
	messages := []CanonicalMessage{
		{Role: "user", Content: "question"},
		{Role: "assistant", ToolCalls: []CanonicalToolCall{
			{ID: "call_1", Name: "get_weather", Arguments: `{"city":"Paris"}`},
			{ID: "call_2", Name: "get_time", Arguments: `{"tz":"CET"}`},
		}},
		{Role: "tool", ToolCallID: "call_1", Content: `{"ok":true}`},
		{Role: "assistant"},
		{Role: "tool", ToolCallID: "call_2", Content: `{"ok":true}`},
	}

	body, err := (&GeminiAdapter{}).EncodeRequest(&CanonicalRequest{Model: "gemini", Messages: messages})
	require.NoError(t, err)

	var req geminiRequest
	require.NoError(t, json.Unmarshal(body, &req))
	require.Len(t, req.Contents, 4)
	for i, want := range []string{"get_weather", "get_time"} {
		results := req.Contents[2+i]
		assert.Equal(t, "user", results.Role)
		require.Len(t, results.Parts, 1)
		require.NotNil(t, results.Parts[0].FunctionResponse)
		assert.Equal(t, want, results.Parts[0].FunctionResponse.Name)
	}
}

func TestGemini_EncodeRequest_ToolResultNameWithoutItsCall(t *testing.T) {
	generated := "toolu_ABCDEFGHIJKLMNOPQRSTUVWXYZ_3"
	tests := []struct {
		name   string
		callID string
		tools  []string
		want   string
	}{
		{name: "generated id with one declared function", callID: generated, tools: []string{"get_weather"}, want: "get_weather"},
		{name: "generated id with two declared functions", callID: generated, tools: []string{"get_weather", "get_time"}, want: generated},
		{name: "generated id without declared functions", callID: generated, want: generated},
		{name: "upstream id with one declared function", callID: "call_1", tools: []string{"get_weather"}, want: "call_1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &CanonicalRequest{
				Model:    "gemini",
				Messages: []CanonicalMessage{{Role: "tool", ToolCallID: tt.callID, Content: "sunny"}},
			}
			for _, name := range tt.tools {
				req.Tools = append(req.Tools, CanonicalTool{Name: name})
			}

			body, err := (&GeminiAdapter{}).EncodeRequest(req)
			require.NoError(t, err)

			var out geminiRequest
			require.NoError(t, json.Unmarshal(body, &out))
			require.Len(t, out.Contents, 1)
			require.Len(t, out.Contents[0].Parts, 1)
			require.NotNil(t, out.Contents[0].Parts[0].FunctionResponse)
			assert.Equal(t, tt.want, out.Contents[0].Parts[0].FunctionResponse.Name)
		})
	}
}

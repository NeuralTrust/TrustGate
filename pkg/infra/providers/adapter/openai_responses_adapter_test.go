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

// ===========================================================================
// OpenAI Responses API tests
// ===========================================================================

func TestCanonical_OpenAI_ResponsesAPI_DecodeRequest_StringInput(t *testing.T) {
	input := `{"model":"gpt-4o","input":"Hello!"}`

	adapter := &OpenAIAdapter{}
	canonical, err := adapter.DecodeRequest([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, "gpt-4o", canonical.Model)
	require.Len(t, canonical.Messages, 1)
	assert.Equal(t, "user", canonical.Messages[0].Role)
	assert.Equal(t, "Hello!", canonical.Messages[0].Content)
	assert.Empty(t, canonical.System)
}

func TestCanonical_OpenAI_ResponsesAPI_DecodeRequest_ArrayInput(t *testing.T) {
	input := `{
		"model": "gpt-4o",
		"instructions": "You are a helpful assistant.",
		"input": [
			{"role": "user", "content": "What is Go?"},
			{"role": "assistant", "content": "Go is a programming language."},
			{"role": "user", "content": "Tell me more."}
		],
		"max_output_tokens": 200,
		"temperature": 0.5
	}`

	adapter := &OpenAIAdapter{}
	canonical, err := adapter.DecodeRequest([]byte(input))
	require.NoError(t, err)

	assert.Equal(t, "gpt-4o", canonical.Model)
	assert.Equal(t, "You are a helpful assistant.", canonical.System)
	assert.Equal(t, 200, canonical.MaxTokens)
	assert.InDelta(t, 0.5, *canonical.Temperature, 0.001)

	require.Len(t, canonical.Messages, 3)
	assert.Equal(t, "user", canonical.Messages[0].Role)
	assert.Equal(t, "What is Go?", canonical.Messages[0].Content)
	assert.Equal(t, "assistant", canonical.Messages[1].Role)
	assert.Equal(t, "Tell me more.", canonical.Messages[2].Content)
}

func TestCanonical_OpenAI_ResponsesAPI_DecodeRequest_AssistantTurns(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		want       []CanonicalMessage
		wantSystem string
	}{
		{
			name: "text and parallel calls fold into one assistant message",
			input: `[
				{"role": "user", "content": "Weather and time?"},
				{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Checking."}]},
				{"type": "function_call", "call_id": "call_1", "name": "get_weather", "arguments": "{}"},
				{"type": "function_call", "call_id": "call_2", "name": "get_time", "arguments": "{}"},
				{"type": "function_call_output", "call_id": "call_1", "output": "sunny"},
				{"type": "function_call_output", "call_id": "call_2", "output": "noon"}
			]`,
			want: []CanonicalMessage{
				{Role: "user", Content: "Weather and time?"},
				{Role: "assistant", Content: "Checking.", ToolCalls: []CanonicalToolCall{
					{ID: "call_1", Name: "get_weather", Arguments: "{}"},
					{ID: "call_2", Name: "get_time", Arguments: "{}"},
				}},
				{Role: "tool", Content: "sunny", ToolCallID: "call_1"},
				{Role: "tool", Content: "noon", ToolCallID: "call_2"},
			},
		},
		{
			name: "an empty assistant message between items is dropped",
			input: `[
				{"role": "user", "content": "Find the client."},
				{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Checking."}]},
				{"type": "function_call", "call_id": "call_1", "name": "query_clients", "arguments": "{}"},
				{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": ""}]},
				{"type": "function_call_output", "call_id": "call_1", "output": "Ana"}
			]`,
			want: []CanonicalMessage{
				{Role: "user", Content: "Find the client."},
				{Role: "assistant", Content: "Checking.", ToolCalls: []CanonicalToolCall{{ID: "call_1", Name: "query_clients", Arguments: "{}"}}},
				{Role: "tool", Content: "Ana", ToolCallID: "call_1"},
			},
		},
		{
			name: "text after a call joins the same turn",
			input: `[
				{"type": "function_call", "call_id": "call_1", "name": "f", "arguments": "{}"},
				{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "One."}]},
				{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Two."}]},
				{"type": "function_call_output", "call_id": "call_1", "output": "ok"}
			]`,
			want: []CanonicalMessage{
				{Role: "assistant", Content: "One.\nTwo.", ToolCalls: []CanonicalToolCall{{ID: "call_1", Name: "f", Arguments: "{}"}}},
				{Role: "tool", Content: "ok", ToolCallID: "call_1"},
			},
		},
		{
			name: "a refusal-only assistant message is kept",
			input: `[
				{"role": "user", "content": "Do the thing."},
				{"type": "message", "role": "assistant", "content": [{"type": "refusal", "refusal": "I can't help with that."}]},
				{"role": "user", "content": "Why?"}
			]`,
			want: []CanonicalMessage{
				{Role: "user", Content: "Do the thing."},
				{Role: "assistant", Content: "I can't help with that."},
				{Role: "user", Content: "Why?"},
			},
		},
		{
			name: "an empty assistant message between users is dropped",
			input: `[
				{"role": "user", "content": "Hi."},
				{"type": "message", "role": "assistant", "content": []},
				{"role": "user", "content": "Hello?"}
			]`,
			want: []CanonicalMessage{
				{Role: "user", Content: "Hi."},
				{Role: "user", Content: "Hello?"},
			},
		},
		{
			name: "a developer message between assistant items stays in the turn",
			input: `[
				{"role": "user", "content": "Hi."},
				{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "A."}]},
				{"role": "developer", "content": "Be brief."},
				{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": ""}]},
				{"type": "function_call", "call_id": "c1", "name": "f", "arguments": "{}"},
				{"type": "function_call_output", "call_id": "c1", "output": "ok"}
			]`,
			want: []CanonicalMessage{
				{Role: "user", Content: "Hi."},
				{Role: "assistant", Content: "A.", ToolCalls: []CanonicalToolCall{{ID: "c1", Name: "f", Arguments: "{}"}}},
				{Role: "tool", Content: "ok", ToolCallID: "c1"},
			},
			wantSystem: "Be brief.",
		},
		{
			name: "skipped items between assistant items stay in the turn",
			input: `[
				{"type": "function_call", "call_id": "A", "name": "f", "arguments": "{}"},
				{"type": "item_reference", "id": "msg_1"},
				{"type": "function_call", "call_id": "B", "name": "g", "arguments": "{}"},
				{"type": "custom_tool_call", "call_id": "C", "name": "apply_patch", "input": "*** Begin Patch"},
				{"type": "web_search_call", "id": "ws_1", "status": "completed", "action": {"type": "search", "query": "q"}},
				{"type": "tool_search_call", "call_id": "ts1", "execution": "client", "arguments": {"query": "calendar"}},
				{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Done."}]},
				{"type": "function_call_output", "call_id": "A", "output": "a"},
				{"type": "function_call_output", "call_id": "B", "output": "b"}
			]`,
			want: []CanonicalMessage{
				{Role: "assistant", Content: "Done.", ToolCalls: []CanonicalToolCall{
					{ID: "A", Name: "f", Arguments: "{}"},
					{ID: "B", Name: "g", Arguments: "{}"},
				}},
				{Role: "tool", Content: "a", ToolCallID: "A"},
				{Role: "tool", Content: "b", ToolCallID: "B"},
			},
		},
		{
			name: "a tool output ends the turn",
			input: `[
				{"type": "function_call", "call_id": "A", "name": "f", "arguments": "{}"},
				{"type": "function_call_output", "call_id": "A", "output": "a"},
				{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Next."}]},
				{"type": "function_call", "call_id": "B", "name": "g", "arguments": "{}"}
			]`,
			want: []CanonicalMessage{
				{Role: "assistant", ToolCalls: []CanonicalToolCall{{ID: "A", Name: "f", Arguments: "{}"}}},
				{Role: "tool", Content: "a", ToolCallID: "A"},
				{Role: "assistant", Content: "Next.", ToolCalls: []CanonicalToolCall{{ID: "B", Name: "g", Arguments: "{}"}}},
			},
		},
		{
			name: "an empty assistant message does not open a turn",
			input: `[
				{"type": "function_call", "call_id": "A", "name": "f", "arguments": "{}"},
				{"type": "function_call_output", "call_id": "A", "output": "a"},
				{"type": "message", "role": "assistant", "content": ""},
				{"role": "user", "content": "Go on."}
			]`,
			want: []CanonicalMessage{
				{Role: "assistant", ToolCalls: []CanonicalToolCall{{ID: "A", Name: "f", Arguments: "{}"}}},
				{Role: "tool", Content: "a", ToolCallID: "A"},
				{Role: "user", Content: "Go on."},
			},
		},
		{
			name: "reasoning items stay within the turn",
			input: `[
				{"type": "reasoning", "id": "rs_1", "summary": [{"type": "summary_text", "text": "think"}]},
				{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Checking."}]},
				{"type": "reasoning", "id": "rs_2", "summary": []},
				{"type": "function_call", "call_id": "call_1", "name": "f", "arguments": "{}"}
			]`,
			want: []CanonicalMessage{
				{Role: "assistant", Content: "Checking.", ToolCalls: []CanonicalToolCall{{ID: "call_1", Name: "f", Arguments: "{}"}}},
			},
		},
		{
			name: "a call with no arguments gets an empty object",
			input: `[
				{"type": "function_call", "call_id": "call_1", "name": "f", "arguments": ""},
				{"type": "function_call", "call_id": "call_2", "name": "g"}
			]`,
			want: []CanonicalMessage{
				{Role: "assistant", ToolCalls: []CanonicalToolCall{
					{ID: "call_1", Name: "f", Arguments: "{}"},
					{ID: "call_2", Name: "g", Arguments: "{}"},
				}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canonical, err := (&OpenAIAdapter{}).DecodeRequest([]byte(`{"model": "deepseek-chat", "input": ` + tt.input + `}`))
			require.NoError(t, err)
			assert.Equal(t, tt.want, canonical.Messages)
			assert.Equal(t, tt.wantSystem, canonical.System)
		})
	}
}

func TestCanonical_OpenAI_ResponsesAPI_DecodeRequest_FunctionCallOutput(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{name: "string", output: `"sunny"`, want: "sunny"},
		{name: "text parts are joined", output: `[{"type": "input_text", "text": "line 1"}, {"type": "output_text", "text": "line 2"}]`, want: "line 1\nline 2"},
		{name: "non-text parts are left out", output: `[{"type": "input_text", "text": "img"}, {"type": "input_image", "image_url": "data:image/png;base64,AA=="}]`, want: "img"},
		{name: "only non-text parts", output: `[{"type": "input_image", "image_url": "data:image/png;base64,AA=="}]`, want: responsesNonTextToolOutput},
		{name: "empty list", output: `[]`, want: responsesNonTextToolOutput},
		{name: "null", output: `null`, want: responsesNonTextToolOutput},
		{name: "empty string", output: `""`, want: ""},
		{name: "object", output: `{"stdout": "a"}`, want: `{"stdout": "a"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := `{"model": "m", "input": [
				{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "look"}]},
				{"type": "function_call", "call_id": "c1", "name": "view_image", "arguments": "{}"},
				{"type": "function_call_output", "call_id": "c1", "output": ` + tt.output + `}
			]}`
			canonical, err := (&OpenAIAdapter{}).DecodeRequest([]byte(input))
			require.NoError(t, err)
			assert.Equal(t, []CanonicalMessage{
				{Role: "user", Content: "look"},
				{Role: "assistant", ToolCalls: []CanonicalToolCall{{ID: "c1", Name: "view_image", Arguments: "{}"}}},
				{Role: "tool", Content: tt.want, ToolCallID: "c1"},
			}, canonical.Messages)
		})
	}
}

func TestCanonical_OpenAI_ResponsesAPI_DecodeRequest_MalformedInputFails(t *testing.T) {
	for _, input := range []string{
		`{"input": 42}`,
		`{"input": {"role": "user", "content": "hi"}}`,
		`{"input": true}`,
	} {
		_, err := (&OpenAIAdapter{}).DecodeRequest([]byte(input))
		assert.Error(t, err, input)
	}

	_, err := NewRegistry().DecodeRequestFor([]byte(`{"model": "m", "input": 42}`), FormatOpenAIResponses)
	assert.True(t, IsRequestDecodeError(err), "a malformed input is the caller's error: %v", err)
}

func TestCanonical_OpenAI_ResponsesAPI_DecodeRequest_LeavesOutItemsItCannotDecode(t *testing.T) {
	body := `{"model": "m", "tools": [{"type": "function", "name": "book", "parameters": {"type": "object"}}], "input": [
		{"role": "user", "content": "Find my calendar tool."},
		{"type": "tool_search_call", "call_id": "ts1", "execution": "client", "arguments": {"query": "calendar"}, "status": "completed"},
		{"type": "tool_search_output", "call_id": "ts1", "execution": "client", "status": "completed", "tools": []},
		{"type": "function_call", "call_id": "bad", "name": "f", "arguments": {"a": 1}},
		{"type": "input_text", "text": 42},
		"stray",
		{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Found it."}]},
		{"type": "function_call", "call_id": "c1", "name": "book", "arguments": "{\"day\":\"mon\"}"},
		{"type": "function_call_output", "call_id": "c1", "output": "booked"},
		{"role": "user", "content": "Thanks."}
	]}`

	canonical, err := NewRegistry().DecodeRequestFor([]byte(body), FormatOpenAIResponses)
	require.NoError(t, err)
	assert.Equal(t, []CanonicalMessage{
		{Role: "user", Content: "Find my calendar tool."},
		{Role: "assistant", Content: "Found it.", ToolCalls: []CanonicalToolCall{{ID: "c1", Name: "book", Arguments: `{"day":"mon"}`}}},
		{Role: "tool", Content: "booked", ToolCallID: "c1"},
		{Role: "user", Content: "Thanks."},
	}, canonical.Messages)
	require.Len(t, canonical.Tools, 1)
	assert.Equal(t, "book", canonical.Tools[0].Name)

	for _, target := range []Format{FormatOpenAI, FormatAnthropic, FormatBedrock, FormatGemini, FormatCohere, FormatDeepSeek} {
		_, err := NewRegistry().AdaptRequest([]byte(body), FormatOpenAIResponses, target)
		assert.NoError(t, err, target)
	}
}

func TestCanonical_OpenAI_ResponsesAPI_DecodeRequest_InputTextItems(t *testing.T) {
	input := `{
		"model": "gpt-4o",
		"input": [
			{"type": "input_text", "text": "Hello from input_text"}
		]
	}`

	adapter := &OpenAIAdapter{}
	canonical, err := adapter.DecodeRequest([]byte(input))
	require.NoError(t, err)

	require.Len(t, canonical.Messages, 1)
	assert.Equal(t, "user", canonical.Messages[0].Role)
	assert.Equal(t, "Hello from input_text", canonical.Messages[0].Content)
}

func TestCanonical_OpenAI_ResponsesAPI_DecodeRequest_DeveloperRole(t *testing.T) {
	input := `{
		"model": "gpt-4o",
		"input": [
			{"role": "developer", "content": "System-level instruction"},
			{"role": "user", "content": "Hello"}
		]
	}`

	adapter := &OpenAIAdapter{}
	canonical, err := adapter.DecodeRequest([]byte(input))
	require.NoError(t, err)

	assert.Equal(t, "System-level instruction", canonical.System)
	require.Len(t, canonical.Messages, 1)
	assert.Equal(t, "user", canonical.Messages[0].Role)
}

func TestCanonical_OpenAI_ResponsesAPI_DecodeRequest_WithTools(t *testing.T) {
	input := `{
		"model": "gpt-4o",
		"input": "What is the weather?",
		"tools": [
			{
				"type": "function",
				"name": "get_weather",
				"description": "Get weather info",
				"parameters": {
					"type": "object",
					"properties": {"city": {"type": "string"}},
					"required": ["city"]
				}
			}
		]
	}`

	adapter := &OpenAIAdapter{}
	canonical, err := adapter.DecodeRequest([]byte(input))
	require.NoError(t, err)

	require.Len(t, canonical.Tools, 1)
	assert.Equal(t, "get_weather", canonical.Tools[0].Name)
	assert.Equal(t, "Get weather info", canonical.Tools[0].Description)
	assert.NotNil(t, canonical.Tools[0].Schema)
}

func TestCanonical_OpenAI_ResponsesAPI_DecodeRequest_WithTools_ShorthandNoType(t *testing.T) {
	input := `{
		"instructions": "You are helpful.",
		"tools": [
			{"description": "entry without name is skipped"},
			{"name": "translate", "description": "Translate text"}
		]
	}`

	adapter := &OpenAIResponsesAdapter{}
	canonical, err := adapter.DecodeRequest([]byte(input))
	require.NoError(t, err)

	require.Len(t, canonical.Tools, 1)
	assert.Equal(t, "translate", canonical.Tools[0].Name)
	assert.Equal(t, "Translate text", canonical.Tools[0].Description)
}

func TestCanonical_OpenAI_ResponsesAPI_DecodeRequest_WithTextFormat(t *testing.T) {
	input := `{
		"model": "gpt-4o",
		"input": "Jane, 54 years old",
		"text": {"format": {"type": "json_object"}}
	}`

	adapter := &OpenAIAdapter{}
	canonical, err := adapter.DecodeRequest([]byte(input))
	require.NoError(t, err)

	require.NotNil(t, canonical.ResponseFormat)
	assert.Equal(t, "json_object", canonical.ResponseFormat.Type)
}

func TestCanonical_OpenAI_ResponsesAPI_DecodeRequest_WithStream(t *testing.T) {
	input := `{"model":"gpt-4o","input":"Hi","stream":true}`

	adapter := &OpenAIAdapter{}
	canonical, err := adapter.DecodeRequest([]byte(input))
	require.NoError(t, err)
	assert.True(t, canonical.Stream)
}

func TestCanonical_OpenAI_ResponsesAPI_DecodeResponse_Message(t *testing.T) {
	body := `{
		"id": "resp_abc123",
		"object": "response",
		"model": "gpt-4o",
		"status": "completed",
		"output": [
			{
				"type": "message",
				"id": "msg_001",
				"role": "assistant",
				"content": [
					{"type": "output_text", "text": "Hello! How can I help?"}
				],
				"status": "completed"
			}
		],
		"usage": {
			"input_tokens": 10,
			"output_tokens": 8,
			"total_tokens": 18
		}
	}`

	adapter := &OpenAIAdapter{}
	cr, err := adapter.DecodeResponse([]byte(body))
	require.NoError(t, err)

	assert.Equal(t, "resp_abc123", cr.ID)
	assert.Equal(t, "gpt-4o", cr.Model)
	assert.Equal(t, "assistant", cr.Role)
	assert.Equal(t, "Hello! How can I help?", cr.Content)
	assert.Equal(t, "stop", cr.FinishReason)

	require.NotNil(t, cr.Usage)
	assert.Equal(t, 10, cr.Usage.InputTokens)
	assert.Equal(t, 8, cr.Usage.OutputTokens)
	assert.Equal(t, 18, cr.Usage.TotalTokens)
}

func TestCanonical_OpenAI_ResponsesAPI_DecodeResponse_FunctionCall(t *testing.T) {
	body := `{
		"id": "resp_func123",
		"object": "response",
		"model": "gpt-4o",
		"status": "completed",
		"output": [
			{
				"type": "function_call",
				"id": "fc_001",
				"call_id": "call_abc",
				"name": "get_weather",
				"arguments": "{\"city\":\"Paris\"}"
			}
		]
	}`

	adapter := &OpenAIAdapter{}
	cr, err := adapter.DecodeResponse([]byte(body))
	require.NoError(t, err)

	assert.Equal(t, "tool_calls", cr.FinishReason)
	require.Len(t, cr.ToolCalls, 1)
	assert.Equal(t, "call_abc", cr.ToolCalls[0].ID)
	assert.Equal(t, "get_weather", cr.ToolCalls[0].Name)
	assert.Equal(t, `{"city":"Paris"}`, cr.ToolCalls[0].Arguments)
}

func TestCanonical_OpenAI_ResponsesAPI_DecodeResponse_MessageAndFunctionCall(t *testing.T) {
	body := `{
		"id": "resp_mixed",
		"object": "response",
		"model": "gpt-4o",
		"status": "completed",
		"output": [
			{
				"type": "message",
				"role": "assistant",
				"content": [{"type": "output_text", "text": "Let me check."}]
			},
			{
				"type": "function_call",
				"call_id": "call_xyz",
				"name": "lookup",
				"arguments": "{}"
			}
		]
	}`

	adapter := &OpenAIAdapter{}
	cr, err := adapter.DecodeResponse([]byte(body))
	require.NoError(t, err)

	assert.Equal(t, "Let me check.", cr.Content)
	assert.Equal(t, "tool_calls", cr.FinishReason)
	require.Len(t, cr.ToolCalls, 1)
	assert.Equal(t, "lookup", cr.ToolCalls[0].Name)
}

func TestCanonical_OpenAI_ResponsesAPI_DecodeResponse_Incomplete(t *testing.T) {
	body := `{
		"id": "resp_inc",
		"object": "response",
		"model": "gpt-4o",
		"status": "incomplete",
		"output": [
			{
				"type": "message",
				"role": "assistant",
				"content": [{"type": "output_text", "text": "Partial answer..."}]
			}
		]
	}`

	adapter := &OpenAIAdapter{}
	cr, err := adapter.DecodeResponse([]byte(body))
	require.NoError(t, err)

	assert.Equal(t, "length", cr.FinishReason)
	assert.Equal(t, "Partial answer...", cr.Content)
}

func TestCanonical_OpenAI_ResponsesAPI_DecodeStreamChunk_TextDelta(t *testing.T) {
	chunk := `{"type":"response.output_text.delta","item_id":"msg_001","output_index":0,"content_index":0,"delta":"Hello"}`

	adapter := &OpenAIAdapter{}
	sc, err := adapter.DecodeStreamChunk([]byte(chunk))
	require.NoError(t, err)
	require.NotNil(t, sc)
	assert.Equal(t, "Hello", sc.Delta)
}

func TestCanonical_OpenAI_ResponsesAPI_DecodeStreamChunk_FuncArgsDelta(t *testing.T) {
	chunk := `{"type":"response.function_call_arguments.delta","item_id":"fc_001","output_index":1,"delta":"{\"city\":"}`

	adapter := &OpenAIAdapter{}
	sc, err := adapter.DecodeStreamChunk([]byte(chunk))
	require.NoError(t, err)
	require.NotNil(t, sc)
	require.Len(t, sc.ToolCallDeltas, 1)
	assert.Equal(t, 1, sc.ToolCallDeltas[0].Index)
	assert.Equal(t, `{"city":`, sc.ToolCallDeltas[0].ArgumentsDelta)
}

func TestCanonical_OpenAI_ResponsesAPI_DecodeStreamChunk_OutputItemAdded(t *testing.T) {
	chunk := `{"type":"response.output_item.added","output_index":0,"item":{"type":"message","id":"msg_001","role":"assistant","content":[]}}`

	adapter := &OpenAIAdapter{}
	sc, err := adapter.DecodeStreamChunk([]byte(chunk))
	require.NoError(t, err)
	require.NotNil(t, sc)
	assert.Equal(t, "assistant", sc.Role)
}

func TestCanonical_OpenAI_ResponsesAPI_DecodeStreamChunk_FuncArgsDone(t *testing.T) {
	chunk := `{"type":"response.function_call_arguments.done","item_id":"fc_001","output_index":1,"name":"get_weather","arguments":"{\"city\":\"Paris\"}"}`

	adapter := &OpenAIAdapter{}
	sc, err := adapter.DecodeStreamChunk([]byte(chunk))
	require.NoError(t, err)
	require.NotNil(t, sc)
	assert.Equal(t, "tool_calls", sc.FinishReason)
}

func TestCanonical_OpenAI_ResponsesAPI_DecodeStreamChunk_Completed(t *testing.T) {
	chunk := `{
		"type": "response.completed",
		"response": {
			"id": "resp_done",
			"model": "gpt-4o",
			"status": "completed",
			"usage": {
				"input_tokens": 50,
				"output_tokens": 30,
				"total_tokens": 80
			}
		}
	}`

	adapter := &OpenAIAdapter{}
	sc, err := adapter.DecodeStreamChunk([]byte(chunk))
	require.NoError(t, err)
	require.NotNil(t, sc)

	assert.Equal(t, "stop", sc.FinishReason)
	assert.Equal(t, "resp_done", sc.ID)
	assert.Equal(t, "gpt-4o", sc.Model)

	require.NotNil(t, sc.Usage)
	assert.Equal(t, 50, sc.Usage.InputTokens)
	assert.Equal(t, 30, sc.Usage.OutputTokens)
	assert.Equal(t, 80, sc.Usage.TotalTokens)
}

func TestCanonical_OpenAI_ResponsesAPI_DecodeStreamChunk_Skipped(t *testing.T) {
	events := []string{
		`{"type":"response.created","response":{}}`,
		`{"type":"response.in_progress"}`,
		`{"type":"response.content_part.added","item_id":"msg_001"}`,
		`{"type":"response.content_part.done","item_id":"msg_001"}`,
		`{"type":"response.output_text.done","item_id":"msg_001","text":"full text"}`,
		`{"type":"response.output_item.done","item":{"type":"message"}}`,
	}

	adapter := &OpenAIAdapter{}
	for _, ev := range events {
		sc, err := adapter.DecodeStreamChunk([]byte(ev))
		assert.NoError(t, err, "event: %s", ev)
		assert.Nil(t, sc, "expected nil for event: %s", ev)
	}
}

// ---------------------------------------------------------------------------
// Generic extractors: Responses API support
// ---------------------------------------------------------------------------

func TestExtractUserInputGeneric_ResponsesAPI_StringInput(t *testing.T) {
	body := `{"model":"gpt-4o","input":"Hello from responses"}`
	got := ExtractUserInputGeneric([]byte(body))
	assert.Equal(t, "Hello from responses", got)
}

func TestExtractUserInputGeneric_ResponsesAPI_ArrayInput(t *testing.T) {
	body := `{"model":"gpt-4o","input":[{"role":"user","content":"first"},{"role":"assistant","content":"reply"},{"role":"user","content":"second"}]}`
	got := ExtractUserInputGeneric([]byte(body))
	assert.Equal(t, "second", got)
}

func TestExtractUserInputGeneric_ResponsesAPI_InputTextItems(t *testing.T) {
	body := `{"model":"gpt-4o","input":[{"type":"input_text","text":"typed input"}]}`
	got := ExtractUserInputGeneric([]byte(body))
	assert.Equal(t, "typed input", got)
}

func TestExtractAssistantOutputGeneric_ResponsesAPI(t *testing.T) {
	body := `{
		"id": "resp_1",
		"object": "response",
		"output": [
			{
				"type": "message",
				"content": [
					{"type": "output_text", "text": "Assistant says hello"}
				]
			}
		]
	}`
	got := ExtractAssistantOutputGeneric([]byte(body))
	assert.Equal(t, "Assistant says hello", got)
}

func TestExtractAssistantOutputGeneric_ResponsesAPI_FunctionCallOnly(t *testing.T) {
	body := `{
		"id": "resp_2",
		"object": "response",
		"output": [
			{
				"type": "function_call",
				"name": "get_weather",
				"arguments": "{}"
			}
		]
	}`
	got := ExtractAssistantOutputGeneric([]byte(body))
	assert.Equal(t, "", got)
}

// ---------------------------------------------------------------------------
// Responses API: Encode tests
// ---------------------------------------------------------------------------

func TestEncodeResponsesRequest_Basic(t *testing.T) {
	adapter := &OpenAIResponsesAdapter{}
	cr := &CanonicalRequest{
		Model:  "gpt-4o",
		System: "You are helpful.",
		Messages: []CanonicalMessage{
			{Role: "user", Content: "What is Go?"},
			{Role: "assistant", Content: "A language."},
			{Role: "user", Content: "Tell me more."},
		},
		MaxTokens: 200,
	}
	temp := 0.7
	cr.Temperature = &temp

	out, err := adapter.EncodeRequest(cr)
	require.NoError(t, err)

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &raw))

	var model string
	require.NoError(t, json.Unmarshal(raw["model"], &model))
	assert.Equal(t, "gpt-4o", model)

	var instructions string
	require.NoError(t, json.Unmarshal(raw["instructions"], &instructions))
	assert.Equal(t, "You are helpful.", instructions)

	var maxOut int
	require.NoError(t, json.Unmarshal(raw["max_output_tokens"], &maxOut))
	assert.Equal(t, 200, maxOut)

	var items []map[string]interface{}
	require.NoError(t, json.Unmarshal(raw["input"], &items))
	require.Len(t, items, 3)
	assert.Equal(t, "user", items[0]["role"])
	assert.Equal(t, "Tell me more.", items[2]["content"])
}

func TestEncodeResponsesRequest_WithTools(t *testing.T) {
	adapter := &OpenAIResponsesAdapter{}
	cr := &CanonicalRequest{
		Model:    "gpt-4o",
		Messages: []CanonicalMessage{{Role: "user", Content: "Weather?"}},
		Tools: []CanonicalTool{{
			Name:        "get_weather",
			Description: "Get the weather",
			Schema:      map[string]interface{}{"type": "object"},
		}},
	}

	out, err := adapter.EncodeRequest(cr)
	require.NoError(t, err)

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &raw))

	var tools []map[string]interface{}
	require.NoError(t, json.Unmarshal(raw["tools"], &tools))
	require.Len(t, tools, 1)
	assert.Equal(t, "function", tools[0]["type"])
	assert.Equal(t, "get_weather", tools[0]["name"])
}

func TestEncodeResponsesResponse_Message(t *testing.T) {
	adapter := &OpenAIResponsesAdapter{}
	cr := &CanonicalResponse{
		ID:           "resp_123",
		Model:        "gpt-4o",
		Content:      "Hello there!",
		Role:         "assistant",
		FinishReason: "stop",
		Usage: &CanonicalUsage{
			InputTokens:  10,
			OutputTokens: 5,
			TotalTokens:  15,
		},
	}

	out, err := adapter.EncodeResponse(cr)
	require.NoError(t, err)

	var resp openaiResponsesResponse
	require.NoError(t, json.Unmarshal(out, &resp))

	assert.Equal(t, "resp_123", resp.ID)
	assert.Equal(t, "response", resp.Object)
	assert.Equal(t, "gpt-4o", resp.Model)
	assert.Equal(t, "completed", resp.Status)

	require.Len(t, resp.Output, 1)
	assert.Equal(t, "message", resp.Output[0].Type)
	assert.Equal(t, "assistant", resp.Output[0].Role)
	require.Len(t, resp.Output[0].Content, 1)
	assert.Equal(t, "output_text", resp.Output[0].Content[0].Type)
	assert.Equal(t, "Hello there!", resp.Output[0].Content[0].Text)

	require.NotNil(t, resp.Usage)
	assert.Equal(t, 10, resp.Usage.InputTokens)
	assert.Equal(t, 5, resp.Usage.OutputTokens)
	assert.Equal(t, 15, resp.Usage.TotalTokens)
}

func TestEncodeResponsesResponse_ToolCalls(t *testing.T) {
	adapter := &OpenAIResponsesAdapter{}
	cr := &CanonicalResponse{
		ID:           "resp_456",
		Model:        "gpt-4o",
		FinishReason: "tool_calls",
		ToolCalls: []CanonicalToolCall{
			{ID: "call_1", Name: "get_weather", Arguments: `{"city":"NYC"}`},
		},
	}

	out, err := adapter.EncodeResponse(cr)
	require.NoError(t, err)

	var resp openaiResponsesResponse
	require.NoError(t, json.Unmarshal(out, &resp))

	assert.Equal(t, "completed", resp.Status)
	require.Len(t, resp.Output, 1)
	assert.Equal(t, "function_call", resp.Output[0].Type)
	assert.Equal(t, "call_1", resp.Output[0].CallID)
	assert.Equal(t, "get_weather", resp.Output[0].Name)
	assert.Equal(t, `{"city":"NYC"}`, resp.Output[0].Arguments)
}

func TestEncodeResponsesResponse_Incomplete(t *testing.T) {
	adapter := &OpenAIResponsesAdapter{}
	cr := &CanonicalResponse{
		ID:           "resp_789",
		Model:        "gpt-4o",
		Content:      "partial...",
		FinishReason: "length",
	}

	out, err := adapter.EncodeResponse(cr)
	require.NoError(t, err)

	var resp openaiResponsesResponse
	require.NoError(t, json.Unmarshal(out, &resp))
	assert.Equal(t, "incomplete", resp.Status)
}

func TestEncodeResponsesStreamChunk_TextDelta(t *testing.T) {
	adapter := &OpenAIResponsesAdapter{}
	chunk := &CanonicalStreamChunk{Delta: "Hello"}

	lines, err := adapter.EncodeStreamChunk(chunk)
	require.NoError(t, err)
	require.NotEmpty(t, lines)

	joined := bytes.Join(lines, []byte("\n"))
	assert.Contains(t, string(joined), "response.output_text.delta")
	assert.Contains(t, string(joined), `"delta":"Hello"`)
}

func TestEncodeResponsesStreamChunk_Role(t *testing.T) {
	adapter := &OpenAIResponsesAdapter{}
	chunk := &CanonicalStreamChunk{Role: "assistant"}

	lines, err := adapter.EncodeStreamChunk(chunk)
	require.NoError(t, err)
	require.NotEmpty(t, lines)

	joined := bytes.Join(lines, []byte("\n"))
	assert.Contains(t, string(joined), "response.output_item.added")
	assert.Contains(t, string(joined), `"role":"assistant"`)
}

func TestEncodeResponsesStreamChunk_Completed(t *testing.T) {
	adapter := &OpenAIResponsesAdapter{}
	chunk := &CanonicalStreamChunk{
		FinishReason: "stop",
		ID:           "resp_done",
		Model:        "gpt-4o",
		Usage: &CanonicalUsage{
			InputTokens:  50,
			OutputTokens: 30,
			TotalTokens:  80,
		},
	}

	lines, err := adapter.EncodeStreamChunk(chunk)
	require.NoError(t, err)
	require.NotEmpty(t, lines)

	joined := bytes.Join(lines, []byte("\n"))
	assert.Contains(t, string(joined), "response.completed")
	assert.Contains(t, string(joined), `"status":"completed"`)
	assert.Contains(t, string(joined), `"input_tokens":50`)
}

func TestEncodeResponsesStreamChunk_ToolCallDelta(t *testing.T) {
	adapter := &OpenAIResponsesAdapter{}
	chunk := &CanonicalStreamChunk{
		ToolCallDeltas: []StreamToolCallDelta{{
			Index:          0,
			ID:             "call_1",
			Name:           "get_weather",
			ArgumentsDelta: `{"ci`,
		}},
	}

	lines, err := adapter.EncodeStreamChunk(chunk)
	require.NoError(t, err)

	joined := bytes.Join(lines, []byte("\n"))
	assert.Contains(t, string(joined), "response.output_item.added")
	assert.Contains(t, string(joined), "response.function_call_arguments.delta")
	assert.Contains(t, string(joined), `{\"ci`)
}

func TestEncodeResponsesStreamChunk_ToolCallFinish(t *testing.T) {
	adapter := &OpenAIResponsesAdapter{}
	chunk := &CanonicalStreamChunk{
		FinishReason: "tool_calls",
	}

	lines, err := adapter.EncodeStreamChunk(chunk)
	require.NoError(t, err)

	joined := bytes.Join(lines, []byte("\n"))
	assert.Contains(t, string(joined), "response.function_call_arguments.done")
	assert.Contains(t, string(joined), "response.completed")
}

// ---------------------------------------------------------------------------
// Responses API: Decode → Encode roundtrip
// ---------------------------------------------------------------------------

func TestResponsesAPI_RequestRoundtrip(t *testing.T) {
	input := `{
		"model": "gpt-4o",
		"instructions": "Be concise.",
		"input": [
			{"role": "user", "content": "What is Go?"}
		],
		"max_output_tokens": 150,
		"temperature": 0.5
	}`

	adapter := &OpenAIResponsesAdapter{}
	canonical, err := adapter.DecodeRequest([]byte(input))
	require.NoError(t, err)

	encoded, err := adapter.EncodeRequest(canonical)
	require.NoError(t, err)

	canonical2, err := adapter.DecodeRequest(encoded)
	require.NoError(t, err)

	assert.Equal(t, canonical.Model, canonical2.Model)
	assert.Equal(t, canonical.System, canonical2.System)
	assert.Equal(t, canonical.MaxTokens, canonical2.MaxTokens)
	require.Len(t, canonical2.Messages, len(canonical.Messages))
	assert.Equal(t, canonical.Messages[0].Content, canonical2.Messages[0].Content)
}

func TestResponsesAPI_ResponseRoundtrip(t *testing.T) {
	respBody := `{
		"id": "resp_rt",
		"object": "response",
		"model": "gpt-4o",
		"status": "completed",
		"output": [
			{
				"type": "message",
				"role": "assistant",
				"content": [{"type": "output_text", "text": "Go is great."}]
			}
		],
		"usage": {"input_tokens": 20, "output_tokens": 10, "total_tokens": 30}
	}`

	adapter := &OpenAIResponsesAdapter{}
	canonical, err := adapter.DecodeResponse([]byte(respBody))
	require.NoError(t, err)

	encoded, err := adapter.EncodeResponse(canonical)
	require.NoError(t, err)

	canonical2, err := adapter.DecodeResponse(encoded)
	require.NoError(t, err)

	assert.Equal(t, canonical.ID, canonical2.ID)
	assert.Equal(t, canonical.Content, canonical2.Content)
	assert.Equal(t, canonical.FinishReason, canonical2.FinishReason)
	assert.Equal(t, canonical.Usage.InputTokens, canonical2.Usage.InputTokens)
}

func TestUsageExtraction_OpenAIResponses(t *testing.T) {
	runUsageCases(t, &OpenAIResponsesAdapter{}, []usageCase{
		{
			name:      "response with usage",
			body:      []byte(`{"id":"resp_1","object":"response","model":"gpt-4o","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hi"}]}],"usage":{"input_tokens":5,"output_tokens":7,"total_tokens":12}}`),
			path:      "response",
			wantUsage: &CanonicalUsage{InputTokens: 5, OutputTokens: 7, TotalTokens: 12},
		},
		{
			name:      "response no usage",
			body:      []byte(`{"id":"resp_1","object":"response","model":"gpt-4o","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hi"}]}]}`),
			path:      "response",
			wantUsage: nil,
		},
		{
			name:      "stream final chunk with usage",
			body:      []byte(`{"type":"response.completed","response":{"id":"resp_done","model":"gpt-4o","status":"completed","usage":{"input_tokens":5,"output_tokens":7,"total_tokens":12}}}`),
			path:      "stream",
			wantUsage: &CanonicalUsage{InputTokens: 5, OutputTokens: 7, TotalTokens: 12},
		},
		{
			name:      "stream no usage",
			body:      []byte(`{"type":"response.output_text.delta","delta":"Hi"}`),
			path:      "stream",
			wantUsage: nil,
		},
	})
}

func TestUsageSubCounts_OpenAIResponses_Reasoning(t *testing.T) {
	body := []byte(`{"id":"resp_1","object":"response","model":"gpt-4o","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hi"}]}],"usage":{"input_tokens":5,"output_tokens":20,"total_tokens":25,"output_tokens_details":{"reasoning_tokens":12}}}`)
	cr, err := (&OpenAIResponsesAdapter{}).DecodeResponse(body)
	require.NoError(t, err)
	require.NotNil(t, cr.Usage)
	assert.Equal(t, 12, cr.Usage.ReasoningOutputTokens)
	assert.Equal(t, 20, cr.Usage.OutputTokens, "ReasoningOutputTokens is a sub-count; OutputTokens must not be reduced")
}

func TestUsageSubCounts_OpenAIResponses_CachedInput(t *testing.T) {
	body := []byte(`{"id":"resp_1","object":"response","model":"gpt-4o","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hi"}]}],"usage":{"input_tokens":5,"output_tokens":7,"total_tokens":12,"input_tokens_details":{"cached_tokens":4}}}`)
	cr, err := (&OpenAIResponsesAdapter{}).DecodeResponse(body)
	require.NoError(t, err)
	require.NotNil(t, cr.Usage)
	assert.Equal(t, 4, cr.Usage.CachedInputTokens)
	assert.Equal(t, 5, cr.Usage.InputTokens, "CachedInputTokens is a sub-count; InputTokens must not be reduced")
}

func TestUsageCache_OpenAIResponses_CacheWrite(t *testing.T) {
	const usage = `{"input_tokens":3000,"output_tokens":9,"total_tokens":3009,"input_tokens_details":{"cached_tokens":1200,"cache_write_tokens":700}}`
	want := &CanonicalUsage{InputTokens: 3000, OutputTokens: 9, TotalTokens: 3009, CachedInputTokens: 1200, CacheWriteInputTokens: 700}
	runUsageCases(t, &OpenAIResponsesAdapter{}, []usageCase{
		{
			name:      "buffered",
			body:      []byte(`{"id":"resp_1","object":"response","model":"gpt-5.6","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hi"}]}],"usage":` + usage + `}`),
			path:      "response",
			wantUsage: want,
		},
		{
			name:      "stream completed",
			body:      []byte(`{"type":"response.completed","response":{"id":"resp_1","model":"gpt-5.6","status":"completed","usage":` + usage + `}}`),
			path:      "stream",
			wantUsage: want,
		},
	})
}

func TestUsageCache_OpenAIResponses_ZeroDetails(t *testing.T) {
	const usage = `{"input_tokens":3000,"output_tokens":9,"total_tokens":3009,"input_tokens_details":{"cached_tokens":0,"cache_write_tokens":0}}`
	want := &CanonicalUsage{InputTokens: 3000, OutputTokens: 9, TotalTokens: 3009}
	runUsageCases(t, &OpenAIResponsesAdapter{}, []usageCase{
		{
			name:      "buffered",
			body:      []byte(`{"id":"resp_1","object":"response","model":"gpt-5.6","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hi"}]}],"usage":` + usage + `}`),
			path:      "response",
			wantUsage: want,
		},
		{
			name:      "stream completed",
			body:      []byte(`{"type":"response.completed","response":{"id":"resp_1","model":"gpt-5.6","status":"completed","usage":` + usage + `}}`),
			path:      "stream",
			wantUsage: want,
		},
	})
}

// Responses API custom tools are flat (no nested "custom" object). They used to
// be dropped on decode, silently removing the tool from the request (ENG-1281).
func TestCanonical_OpenAIResponses_CustomToolRoundtrip(t *testing.T) {
	a := &OpenAIResponsesAdapter{}
	body := []byte(`{
		"model":"gpt-5.1",
		"input":"hi",
		"tools":[
			{"type":"function","name":"read_file","parameters":{"type":"object"}},
			{"type":"custom","name":"bash","description":"Run a shell command","format":{"type":"text"}}
		]
	}`)

	cr, err := a.DecodeRequest(body)
	require.NoError(t, err)
	require.Len(t, cr.Tools, 2, "custom tools must not be dropped")
	assert.Equal(t, ToolKindFunction, cr.Tools[0].Kind)
	assert.Equal(t, ToolKindCustom, cr.Tools[1].Kind)
	assert.Equal(t, "bash", cr.Tools[1].Name)

	encoded, err := a.EncodeRequest(cr)
	require.NoError(t, err)

	var out struct {
		Tools []map[string]any `json:"tools"`
	}
	require.NoError(t, json.Unmarshal(encoded, &out))
	require.Len(t, out.Tools, 2)
	assert.Equal(t, "function", out.Tools[0]["type"])
	assert.Equal(t, "custom", out.Tools[1]["type"])
	assert.Equal(t, "bash", out.Tools[1]["name"])
	format, ok := out.Tools[1]["format"].(map[string]any)
	require.True(t, ok, "format must survive: %v", out.Tools[1])
	assert.Equal(t, "text", format["type"])
}

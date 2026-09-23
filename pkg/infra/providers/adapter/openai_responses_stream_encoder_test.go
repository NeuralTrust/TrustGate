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
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func responsesEncoderEvents(t *testing.T, lines [][]byte) []string {
	t.Helper()
	var events []string
	for _, line := range lines {
		payload, ok := strings.CutPrefix(string(line), "data: ")
		if !ok {
			continue
		}
		var event struct {
			Type        string `json:"type"`
			Delta       string `json:"delta"`
			OutputIndex int    `json:"output_index"`
			Item        struct {
				Type   string `json:"type"`
				CallID string `json:"call_id"`
			} `json:"item"`
		}
		require.NoError(t, json.Unmarshal([]byte(payload), &event))
		switch event.Type {
		case "response.output_item.added":
			events = append(events, strings.TrimSpace(fmt.Sprintf("added %d %s %s", event.OutputIndex, event.Item.Type, event.Item.CallID)))
		case "response.output_text.delta":
			events = append(events, fmt.Sprintf("text %d %s", event.OutputIndex, event.Delta))
		case "response.function_call_arguments.delta":
			events = append(events, fmt.Sprintf("arguments %d %s", event.OutputIndex, event.Delta))
		}
	}
	return events
}

func TestResponsesStreamEncoder_OutputIndexes(t *testing.T) {
	tests := []struct {
		name   string
		chunks []*CanonicalStreamChunk
		want   []string
	}{
		{
			name: "role on every chunk opens one message",
			chunks: []*CanonicalStreamChunk{
				{Role: "assistant", Delta: "Hel"},
				{Role: "assistant", Delta: "lo"},
			},
			want: []string{"added 0 message", "text 0 Hel", "text 0 lo"},
		},
		{
			name: "text and a call in the same chunk",
			chunks: []*CanonicalStreamChunk{
				{Role: "assistant", Delta: "Checking.", ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "get_weather", ArgumentsDelta: "{}"}}},
			},
			want: []string{"added 0 message", "text 0 Checking.", "added 1 function_call call_1", "arguments 1 {}"},
		},
		{
			name: "calls streamed as continuation deltas",
			chunks: []*CanonicalStreamChunk{
				{Role: "assistant"},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "a", ArgumentsDelta: `{"x"`}}},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ArgumentsDelta: `:1}`}}},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 1, ID: "call_2", Name: "b"}}},
			},
			want: []string{
				"added 0 function_call call_1",
				`arguments 0 {"x"`,
				"arguments 0 :1}",
				"added 1 function_call call_2",
			},
		},
		{
			name: "calls with different ids at one index",
			chunks: []*CanonicalStreamChunk{
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "a", ArgumentsDelta: "{}"}}},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_2", Name: "a", ArgumentsDelta: `{"x":1}`}}},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ArgumentsDelta: " "}}},
			},
			want: []string{
				"added 0 function_call call_1",
				"arguments 0 {}",
				"added 1 function_call call_2",
				`arguments 1 {"x":1}`,
				"arguments 1  ",
			},
		},
		{
			name: "arguments held until the call has a name",
			chunks: []*CanonicalStreamChunk{
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ArgumentsDelta: `{"x"`}}},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, Name: "a", ArgumentsDelta: ":1"}}},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ArgumentsDelta: "}"}}},
			},
			want: []string{"added 0 function_call call_*_0", `arguments 0 {"x":1`, "arguments 0 }"},
		},
		{
			name: "a repeated call id is replaced",
			chunks: []*CanonicalStreamChunk{
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "a"}}},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 1, ID: "call_1", Name: "b"}}},
			},
			want: []string{"added 0 function_call call_1", "added 1 function_call call_*_1"},
		},
		{
			name: "role and empty text open no message",
			chunks: []*CanonicalStreamChunk{
				{Role: "assistant"},
				{Role: "assistant", Delta: ""},
			},
		},
		{
			name: "an id-only call waits for its name",
			chunks: []*CanonicalStreamChunk{
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", ArgumentsDelta: "{"}}},
				{Delta: "hi"},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, Name: "a", ArgumentsDelta: "}"}}},
			},
			want: []string{"added 0 message", "text 0 hi", "added 1 function_call call_1", "arguments 1 {}"},
		},
		{
			name: "text after a call opens a new message",
			chunks: []*CanonicalStreamChunk{
				{Delta: "Checking."},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "a", ArgumentsDelta: "{}"}}},
				{Delta: "Done."},
			},
			want: []string{"added 0 message", "text 0 Checking.", "added 1 function_call call_1", "arguments 1 {}", "added 2 message", "text 2 Done."},
		},
		{
			name: "a call before any text",
			chunks: []*CanonicalStreamChunk{
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "a"}}},
				{Delta: "done"},
			},
			want: []string{"added 0 function_call call_1", "added 1 message", "text 1 done"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := NewResponsesStreamEncoder()
			var lines [][]byte
			for _, chunk := range tt.chunks {
				lines = append(lines, enc.Content(chunk)...)
			}
			got := responsesEncoderEvents(t, lines)
			for i := range got {
				got[i] = strings.ReplaceAll(got[i], "call_"+enc.nonce+"_", "call_*_")
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func responsesEncoderTypes(t *testing.T, lines [][]byte) []string {
	t.Helper()
	var types []string
	for _, line := range lines {
		payload, ok := strings.CutPrefix(string(line), "data: ")
		if !ok {
			continue
		}
		var event struct {
			Type string `json:"type"`
		}
		require.NoError(t, json.Unmarshal([]byte(payload), &event))
		types = append(types, event.Type)
	}
	return types
}

func TestResponsesStreamEncoder_Finish(t *testing.T) {
	t.Run("items finish in output_index order", func(t *testing.T) {
		enc := NewResponsesStreamEncoder()
		lines := enc.Content(&CanonicalStreamChunk{ID: "resp_1", Model: "m", ToolCallDeltas: []StreamToolCallDelta{
			{Index: 0, ID: "call_1", Name: "a", ArgumentsDelta: "{}"},
			{Index: 1, ArgumentsDelta: "{}"},
		}})
		lines = append(lines, enc.Content(&CanonicalStreamChunk{Delta: "hi"})...)
		lines = append(lines, enc.Finish(&CanonicalStreamChunk{FinishReason: "tool_calls", Usage: &CanonicalUsage{InputTokens: 1, OutputTokens: 2, TotalTokens: 3}})...)
		assert.Equal(t, []string{
			"response.created", "response.in_progress",
			"response.output_item.added", "response.function_call_arguments.delta",
			"response.output_item.added", "response.content_part.added", "response.output_text.delta",
			"response.function_call_arguments.done", "response.output_item.done",
			"response.output_text.done", "response.content_part.done", "response.output_item.done",
			"response.completed",
		}, responsesEncoderTypes(t, lines))

		payload, ok := strings.CutPrefix(string(lines[len(lines)-2]), "data: ")
		require.True(t, ok)
		var completed struct {
			SequenceNumber int `json:"sequence_number"`
			Response       struct {
				ID     string `json:"id"`
				Model  string `json:"model"`
				Status string `json:"status"`
				Output []struct {
					Type string `json:"type"`
				} `json:"output"`
				Usage *openaiResponsesUsage `json:"usage"`
			} `json:"response"`
		}
		require.NoError(t, json.Unmarshal([]byte(payload), &completed))
		assert.Equal(t, 12, completed.SequenceNumber)
		assert.Equal(t, "resp_1", completed.Response.ID)
		assert.Equal(t, "m", completed.Response.Model)
		assert.Equal(t, "completed", completed.Response.Status)
		require.Len(t, completed.Response.Output, 2)
		assert.Equal(t, "function_call", completed.Response.Output[0].Type)
		assert.Equal(t, "message", completed.Response.Output[1].Type)
		assert.Equal(t, &openaiResponsesUsage{
			InputTokens:         1,
			OutputTokens:        2,
			TotalTokens:         3,
			InputTokensDetails:  &openaiResponsesInputTokensDetails{},
			OutputTokensDetails: &openaiResponsesOutputTokensDetails{},
		}, completed.Response.Usage)
	})
	t.Run("text before a call closes the message first", func(t *testing.T) {
		enc := NewResponsesStreamEncoder()
		lines := enc.Content(&CanonicalStreamChunk{ID: "resp_1", Delta: "Checking."})
		lines = append(lines, enc.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "f", ArgumentsDelta: "{}"}}})...)
		lines = append(lines, enc.Finish(&CanonicalStreamChunk{FinishReason: "tool_calls"})...)
		assert.Equal(t, []string{
			"response.created", "response.in_progress",
			"response.output_item.added", "response.content_part.added", "response.output_text.delta",
			"response.output_text.done", "response.content_part.done", "response.output_item.done",
			"response.output_item.added", "response.function_call_arguments.delta",
			"response.function_call_arguments.done", "response.output_item.done",
			"response.completed",
		}, responsesEncoderTypes(t, lines))

		var payloads []string
		for _, line := range lines {
			if payload, ok := strings.CutPrefix(string(line), "data: "); ok {
				payloads = append(payloads, payload)
			}
		}
		for i, payload := range payloads {
			assert.JSONEq(t, fmt.Sprint(i), jsonField(t, payload, "sequence_number"))
		}
		messageDone := payloads[7]
		assert.JSONEq(t, `0`, jsonField(t, messageDone, "output_index"))
		assert.JSONEq(t, `"completed"`, jsonField(t, messageDone, "item", "status"))
		assert.JSONEq(t, `[{"type":"output_text","text":"Checking.","annotations":[]}]`, jsonField(t, messageDone, "item", "content"))

		var output []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		}
		require.NoError(t, json.Unmarshal([]byte(jsonField(t, payloads[len(payloads)-1], "response", "output")), &output))
		require.Len(t, output, 2)
		assert.Equal(t, "message", output[0].Type)
		assert.Equal(t, "function_call", output[1].Type)
		for _, item := range output {
			assert.Equal(t, "completed", item.Status)
		}
	})
	t.Run("once", func(t *testing.T) {
		enc := NewResponsesStreamEncoder()
		lines := enc.Finish(&CanonicalStreamChunk{FinishReason: "stop"})
		assert.Equal(t, []string{"response.created", "response.in_progress", "response.completed"}, responsesEncoderTypes(t, lines))
		assert.Empty(t, enc.Finish(&CanonicalStreamChunk{FinishReason: "stop"}))
		assert.Empty(t, enc.Content(&CanonicalStreamChunk{Delta: "late"}))
	})
	t.Run("length stop", func(t *testing.T) {
		enc := NewResponsesStreamEncoder()
		lines := enc.Content(&CanonicalStreamChunk{Delta: "Once"})
		lines = append(lines, enc.Finish(&CanonicalStreamChunk{FinishReason: "length"})...)
		payload, ok := strings.CutPrefix(string(lines[len(lines)-2]), "data: ")
		require.True(t, ok)
		assert.JSONEq(t, `{"reason":"max_output_tokens"}`, jsonField(t, payload, "response", "incomplete_details"))
		assert.JSONEq(t, `"incomplete"`, jsonField(t, payload, "response", "status"))
		assert.Contains(t, responsesEncoderTypes(t, lines), "response.incomplete")
	})
}

func jsonField(t *testing.T, payload string, path ...string) string {
	t.Helper()
	var v any
	require.NoError(t, json.Unmarshal([]byte(payload), &v))
	for _, key := range path {
		m, ok := v.(map[string]any)
		require.True(t, ok, key)
		v = m[key]
	}
	out, err := json.Marshal(v)
	require.NoError(t, err)
	return string(out)
}

func TestResponsesStreamEncoder_MessageIDsAreDistinct(t *testing.T) {
	enc := NewResponsesStreamEncoder()
	lines := enc.Content(&CanonicalStreamChunk{Delta: "a"})
	lines = append(lines, enc.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "f"}}})...)
	lines = append(lines, enc.Content(&CanonicalStreamChunk{Delta: "b"})...)
	ids := map[string]bool{}
	for _, line := range lines {
		payload, ok := strings.CutPrefix(string(line), "data: ")
		if !ok || !strings.Contains(payload, `"response.output_item.added"`) {
			continue
		}
		id := jsonField(t, payload, "item", "id")
		assert.False(t, ids[id], "item id %s repeats", id)
		ids[id] = true
	}
	assert.Len(t, ids, 3)
}

func TestResponsesStreamEncoder_FinishStatus(t *testing.T) {
	tests := []struct {
		reason         string
		wantEvent      string
		wantStatus     string
		wantIncomplete string
		wantError      string
	}{
		{reason: "stop", wantEvent: "response.completed", wantStatus: "completed"},
		{reason: "tool_calls", wantEvent: "response.completed", wantStatus: "completed"},
		{reason: "length", wantEvent: "response.incomplete", wantStatus: "incomplete", wantIncomplete: "max_output_tokens"},
		{reason: "content_filter", wantEvent: "response.incomplete", wantStatus: "incomplete", wantIncomplete: "content_filter"},
		{reason: "refusal", wantEvent: "response.incomplete", wantStatus: "incomplete", wantIncomplete: "content_filter"},
		{reason: "SAFETY", wantEvent: "response.incomplete", wantStatus: "incomplete", wantIncomplete: "content_filter"},
		{reason: "RECITATION", wantEvent: "response.incomplete", wantStatus: "incomplete", wantIncomplete: "content_filter"},
		{reason: "error", wantEvent: "response.failed", wantStatus: "failed", wantError: "upstream reported an error while generating the message"},
		{reason: "MALFORMED_FUNCTION_CALL", wantEvent: "response.failed", wantStatus: "failed", wantError: "upstream generated a malformed tool call"},
	}
	for _, tt := range tests {
		t.Run(tt.reason, func(t *testing.T) {
			enc := NewResponsesStreamEncoder()
			lines := enc.Content(&CanonicalStreamChunk{Delta: "hi"})
			lines = append(lines, enc.Finish(&CanonicalStreamChunk{FinishReason: tt.reason, Usage: &CanonicalUsage{InputTokens: 1, OutputTokens: 1, TotalTokens: 2}})...)
			types := responsesEncoderTypes(t, lines)
			require.Equal(t, tt.wantEvent, types[len(types)-1])
			payload, ok := strings.CutPrefix(string(lines[len(lines)-2]), "data: ")
			require.True(t, ok)
			assert.JSONEq(t, `"`+tt.wantStatus+`"`, jsonField(t, payload, "response", "status"))
			assert.JSONEq(t, `2`, jsonField(t, payload, "response", "usage", "total_tokens"))
			if tt.wantIncomplete == "" {
				assert.Equal(t, "null", jsonField(t, payload, "response", "incomplete_details"))
			} else {
				assert.JSONEq(t, `{"reason":"`+tt.wantIncomplete+`"}`, jsonField(t, payload, "response", "incomplete_details"))
			}
			if tt.wantError == "" {
				assert.Equal(t, "null", jsonField(t, payload, "response", "error"))
				assert.NotContains(t, types, "error")
				assert.False(t, enc.Aborted())
				return
			}
			assert.JSONEq(t, `{"code":"server_error","message":"`+tt.wantError+`"}`, jsonField(t, payload, "response", "error"))
			assert.Equal(t, "error", types[len(types)-2])
			assert.True(t, enc.Aborted())
		})
	}
}

func TestResponsesStreamEncoder_Abort(t *testing.T) {
	t.Run("nothing before the response started", func(t *testing.T) {
		enc := NewResponsesStreamEncoder()
		assert.Empty(t, enc.Abort("upstream stream failed", nil))
		assert.False(t, enc.Started())
		assert.False(t, enc.Aborted())
	})
	t.Run("error then response.failed with every open item incomplete", func(t *testing.T) {
		enc := NewResponsesStreamEncoder()
		lines := enc.Content(&CanonicalStreamChunk{ID: "resp_1", Delta: "hi"})
		lines = append(lines, enc.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "f", ArgumentsDelta: `{"a"`}}})...)
		lines = append(lines, enc.Abort("upstream stream failed", &CanonicalUsage{InputTokens: 3, OutputTokens: 1, TotalTokens: 4})...)
		assert.True(t, enc.Aborted())

		types := responsesEncoderTypes(t, lines)
		assert.Equal(t, []string{
			"response.created", "response.in_progress",
			"response.output_item.added", "response.content_part.added", "response.output_text.delta",
			"response.output_text.done", "response.content_part.done", "response.output_item.done",
			"response.output_item.added", "response.function_call_arguments.delta",
			"response.function_call_arguments.done", "response.output_item.done",
			"error", "response.failed",
		}, types)

		var payloads []string
		for _, line := range lines {
			if payload, ok := strings.CutPrefix(string(line), "data: "); ok {
				payloads = append(payloads, payload)
			}
		}
		for i, payload := range payloads {
			assert.JSONEq(t, fmt.Sprint(i), jsonField(t, payload, "sequence_number"))
		}
		errEvent := payloads[len(payloads)-2]
		assert.JSONEq(t, `"server_error"`, jsonField(t, errEvent, "code"))
		assert.JSONEq(t, `"upstream stream failed"`, jsonField(t, errEvent, "message"))
		failed := payloads[len(payloads)-1]
		assert.JSONEq(t, `"resp_1"`, jsonField(t, failed, "response", "id"))
		assert.JSONEq(t, `"failed"`, jsonField(t, failed, "response", "status"))
		assert.JSONEq(t, `{"code":"server_error","message":"upstream stream failed"}`, jsonField(t, failed, "response", "error"))
		assert.JSONEq(t, `4`, jsonField(t, failed, "response", "usage", "total_tokens"))
		var output []struct {
			Status string `json:"status"`
		}
		require.NoError(t, json.Unmarshal([]byte(jsonField(t, failed, "response", "output")), &output))
		require.Len(t, output, 2)
		assert.Equal(t, "completed", output[0].Status)
		assert.Equal(t, "incomplete", output[1].Status)

		assert.Empty(t, enc.Abort("again", nil))
		assert.Empty(t, enc.Finish(&CanonicalStreamChunk{FinishReason: "stop"}))
	})
}

func TestResponsesStreamEncoder_DroppedNamelessCalls(t *testing.T) {
	enc := NewResponsesStreamEncoder()
	enc.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", ArgumentsDelta: "{}"}}})
	enc.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 1, ID: "call_2", Name: "f", ArgumentsDelta: "{}"}}})
	lines := enc.Finish(&CanonicalStreamChunk{FinishReason: "tool_calls"})

	assert.Equal(t, 1, enc.Dropped())
	payload, ok := strings.CutPrefix(string(lines[len(lines)-2]), "data: ")
	require.True(t, ok)
	var output []struct {
		CallID string `json:"call_id"`
	}
	require.NoError(t, json.Unmarshal([]byte(jsonField(t, payload, "response", "output")), &output))
	require.Len(t, output, 1)
	assert.Equal(t, "call_2", output[0].CallID)
}

func TestOpenAIResponsesUsageFromCanonical_AlwaysHasDetails(t *testing.T) {
	enc := NewResponsesStreamEncoder()
	lines := enc.Finish(&CanonicalStreamChunk{FinishReason: "stop", Usage: &CanonicalUsage{InputTokens: 1, OutputTokens: 1, TotalTokens: 2}})
	payload, ok := strings.CutPrefix(string(lines[len(lines)-2]), "data: ")
	require.True(t, ok)
	assert.JSONEq(t, `{"input_tokens":1,"output_tokens":1,"total_tokens":2,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}`,
		jsonField(t, payload, "response", "usage"))

	body, err := encodeResponsesResponse(&CanonicalResponse{ID: "r", Content: "hi", FinishReason: "stop", Usage: &CanonicalUsage{InputTokens: 1, OutputTokens: 1, TotalTokens: 2}})
	require.NoError(t, err)
	assert.JSONEq(t, `{"input_tokens":1,"output_tokens":1,"total_tokens":2,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}`,
		jsonField(t, string(body), "usage"))
}

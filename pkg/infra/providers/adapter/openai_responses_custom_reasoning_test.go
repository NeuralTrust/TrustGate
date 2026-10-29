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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func responsesEventsOf(t *testing.T, lines [][]byte, eventType string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, payload := range responsesEncoderPayloads(lines) {
		var event map[string]any
		require.NoError(t, json.Unmarshal([]byte(payload), &event))
		if event["type"] == eventType {
			out = append(out, event)
		}
	}
	return out
}

func responsesTerminalOutput(t *testing.T, lines [][]byte) []map[string]any {
	t.Helper()
	payloads := responsesEncoderPayloads(lines)
	require.NotEmpty(t, payloads)
	var event struct {
		Response struct {
			Output []map[string]any `json:"output"`
		} `json:"response"`
	}
	require.NoError(t, json.Unmarshal([]byte(payloads[len(payloads)-1]), &event))
	return event.Response.Output
}

func TestResponsesStreamEncoder_CustomToolCall(t *testing.T) {
	t.Parallel()

	enc := NewResponsesStreamEncoder()
	var lines [][]byte
	lines = append(lines, enc.Content(&CanonicalStreamChunk{Delta: "Applying.", ToolCallDeltas: []StreamToolCallDelta{{
		Index: 0, ID: "call_patch", Kind: ToolKindCustom, Name: "apply_patch", ArgumentsDelta: "*** Begin",
	}}})...)
	lines = append(lines, enc.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{
		Index: 0, ArgumentsDelta: " Patch\n+hello",
	}}})...)
	assert.True(t, enc.HeldCallsComplete(), "freeform custom input is complete even when it is not JSON")
	for _, eventType := range responsesEncoderTypes(t, lines) {
		assert.NotContains(t, eventType, "function_call")
		assert.NotContains(t, eventType, "custom_tool_call")
	}

	lines = append(lines, enc.Finish(&CanonicalStreamChunk{FinishReason: "tool_calls"})...)
	requireSequentialItems(t, lines)
	types := responsesEncoderTypes(t, lines)
	assert.Contains(t, types, "response.custom_tool_call_input.delta")
	assert.Contains(t, types, "response.custom_tool_call_input.done")
	assert.NotContains(t, types, "response.function_call_arguments.delta")
	assert.NotContains(t, types, "response.function_call_arguments.done")

	deltas := responsesEventsOf(t, lines, "response.custom_tool_call_input.delta")
	require.Len(t, deltas, 1)
	assert.Equal(t, "*** Begin Patch\n+hello", deltas[0]["delta"])
	done := responsesEventsOf(t, lines, "response.custom_tool_call_input.done")
	require.Len(t, done, 1)
	assert.Equal(t, "*** Begin Patch\n+hello", done[0]["input"])
	assert.NotContains(t, done[0], "arguments")

	added := responsesEventsOf(t, lines, "response.output_item.added")
	require.Len(t, added, 2)
	call := added[1]["item"].(map[string]any)
	assert.Equal(t, "custom_tool_call", call["type"])
	assert.Equal(t, "call_patch", call["call_id"])
	assert.Equal(t, "apply_patch", call["name"])
	assert.Equal(t, "", call["input"])
	assert.True(t, strings.HasPrefix(call["id"].(string), "ctc_"))
	assert.NotContains(t, call, "arguments")

	output := responsesTerminalOutput(t, lines)
	require.Len(t, output, 2)
	assert.Equal(t, "message", output[0]["type"])
	assert.Equal(t, "custom_tool_call", output[1]["type"])
	assert.Equal(t, "*** Begin Patch\n+hello", output[1]["input"])
	assert.Equal(t, "completed", output[1]["status"])
	assert.NotContains(t, output[1], "arguments")
}

func TestResponsesStreamEncoder_CustomToolCallEmptyInput(t *testing.T) {
	t.Parallel()

	enc := NewResponsesStreamEncoder()
	lines := enc.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{
		Index: 0, ID: "call_patch", Kind: ToolKindCustom, Name: "apply_patch",
	}}})
	lines = append(lines, enc.Finish(&CanonicalStreamChunk{FinishReason: "tool_calls"})...)
	requireSequentialItems(t, lines)

	done := responsesEventsOf(t, lines, "response.custom_tool_call_input.done")
	require.Len(t, done, 1)
	assert.Equal(t, "", done[0]["input"])
	assert.NotContains(t, responsesEncoderTypes(t, lines), "response.function_call_arguments.delta")
	output := responsesTerminalOutput(t, lines)
	require.Len(t, output, 1)
	assert.Equal(t, "", output[0]["input"])
	assert.NotEqual(t, "{}", output[0]["input"])
}

func TestResponsesStreamEncoder_CustomKindArrivesAfterArguments(t *testing.T) {
	t.Parallel()

	enc := NewResponsesStreamEncoder()
	lines := enc.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{
		Index: 0, ID: "call_patch", Name: "apply_patch", ArgumentsDelta: "*** ",
	}}})
	assert.False(t, enc.HeldCallsComplete(), "a named function call with non-JSON arguments is incomplete")
	lines = append(lines, enc.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{
		Index: 0, Kind: ToolKindCustom, ArgumentsDelta: "Begin Patch",
	}}})...)
	assert.True(t, enc.HeldCallsComplete())
	lines = append(lines, enc.Finish(&CanonicalStreamChunk{FinishReason: "tool_calls"})...)
	requireSequentialItems(t, lines)

	assert.NotContains(t, responsesEncoderTypes(t, lines), "response.function_call_arguments.done")
	done := responsesEventsOf(t, lines, "response.custom_tool_call_input.done")
	require.Len(t, done, 1)
	assert.Equal(t, "*** Begin Patch", done[0]["input"])
}

func TestResponsesStreamEncoder_MixedFunctionAndCustomCalls(t *testing.T) {
	t.Parallel()

	enc := NewResponsesStreamEncoder()
	lines := enc.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{
		{Index: 0, ID: "call_fn", Name: "get_weather", ArgumentsDelta: `{"city":"Paris"}`},
		{Index: 1, ID: "call_cu", Kind: ToolKindCustom, Name: "apply_patch", ArgumentsDelta: "*** Begin Patch"},
	}})
	assert.True(t, enc.HeldCallsComplete())
	lines = append(lines, enc.Finish(&CanonicalStreamChunk{FinishReason: "tool_calls"})...)
	requireSequentialItems(t, lines)

	types := responsesEncoderTypes(t, lines)
	fn := typesIndex(types, "response.function_call_arguments.done")
	custom := typesIndex(types, "response.custom_tool_call_input.done")
	require.NotEqual(t, -1, fn)
	require.NotEqual(t, -1, custom)
	assert.Less(t, fn, custom, "calls are emitted in arrival order")

	output := responsesTerminalOutput(t, lines)
	require.Len(t, output, 2)
	assert.Equal(t, "function_call", output[0]["type"])
	assert.Equal(t, `{"city":"Paris"}`, output[0]["arguments"])
	assert.Equal(t, "custom_tool_call", output[1]["type"])
	assert.Equal(t, "*** Begin Patch", output[1]["input"])
	assert.True(t, strings.HasPrefix(output[1]["id"].(string), "ctc_"))
	assert.True(t, strings.HasPrefix(output[0]["id"].(string), "fc_"))
}

func TestResponsesStreamEncoder_HeldCallsCompleteIgnoresCustomText(t *testing.T) {
	t.Parallel()

	enc := NewResponsesStreamEncoder()
	enc.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{
		{Index: 0, ID: "call_cu", Kind: ToolKindCustom, Name: "apply_patch", ArgumentsDelta: "*** not json"},
		{Index: 1, ID: "call_fn", Name: "get_weather", ArgumentsDelta: `{"city"`},
	}})
	assert.False(t, enc.HeldCallsComplete(), "a cut function call is still incomplete")

	onlyCustom := NewResponsesStreamEncoder()
	onlyCustom.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{
		Index: 0, ID: "call_cu", Kind: ToolKindCustom, Name: "apply_patch", ArgumentsDelta: "*** not json",
	}}})
	assert.True(t, onlyCustom.HeldCallsComplete())
}

func TestResponsesStreamEncoder_ReasoningSummary(t *testing.T) {
	t.Parallel()

	enc := NewResponsesStreamEncoder()
	var lines [][]byte
	lines = append(lines, enc.Content(&CanonicalStreamChunk{ReasoningDelta: "Think "})...)
	lines = append(lines, enc.Content(&CanonicalStreamChunk{ReasoningDelta: "hard."})...)
	lines = append(lines, enc.Content(&CanonicalStreamChunk{Delta: "Answer."})...)
	lines = append(lines, enc.Finish(&CanonicalStreamChunk{FinishReason: "stop"})...)
	requireSequentialItems(t, lines)

	types := responsesEncoderTypes(t, lines)
	assert.Equal(t, []string{
		"response.created", "response.in_progress",
		"response.output_item.added", "response.reasoning_summary_part.added",
		"response.reasoning_summary_text.delta", "response.reasoning_summary_text.delta",
		"response.reasoning_summary_text.done", "response.reasoning_summary_part.done", "response.output_item.done",
		"response.output_item.added", "response.content_part.added", "response.output_text.delta",
		"response.output_text.done", "response.content_part.done", "response.output_item.done",
		"response.completed",
	}, types)

	added := responsesEventsOf(t, lines, "response.output_item.added")
	require.Len(t, added, 2)
	reasoning := added[0]["item"].(map[string]any)
	assert.Equal(t, "reasoning", reasoning["type"])
	assert.Equal(t, "in_progress", reasoning["status"])
	assert.Empty(t, reasoning["summary"])
	id := reasoning["id"].(string)
	assert.True(t, strings.HasPrefix(id, "rs_"))

	deltas := responsesEventsOf(t, lines, "response.reasoning_summary_text.delta")
	require.Len(t, deltas, 2)
	assert.Equal(t, "Think ", deltas[0]["delta"])
	assert.Equal(t, "hard.", deltas[1]["delta"])
	for _, delta := range deltas {
		assert.Equal(t, id, delta["item_id"])
		assert.Equal(t, float64(0), delta["summary_index"])
		assert.Equal(t, float64(0), delta["output_index"])
	}
	textDone := responsesEventsOf(t, lines, "response.reasoning_summary_text.done")
	require.Len(t, textDone, 1)
	assert.Equal(t, "Think hard.", textDone[0]["text"])
	assert.Equal(t, id, textDone[0]["item_id"])

	partAdded := responsesEventsOf(t, lines, "response.reasoning_summary_part.added")
	require.Len(t, partAdded, 1)
	assert.Equal(t, map[string]any{"type": "summary_text", "text": ""}, partAdded[0]["part"])
	partDone := responsesEventsOf(t, lines, "response.reasoning_summary_part.done")
	require.Len(t, partDone, 1)
	assert.Equal(t, map[string]any{"type": "summary_text", "text": "Think hard."}, partDone[0]["part"])

	output := responsesTerminalOutput(t, lines)
	require.Len(t, output, 2)
	assert.Equal(t, "reasoning", output[0]["type"])
	assert.Equal(t, "completed", output[0]["status"])
	assert.Equal(t, []any{map[string]any{"type": "summary_text", "text": "Think hard."}}, output[0]["summary"])
	assert.Equal(t, "message", output[1]["type"])
	assert.Equal(t, float64(1), responsesEventsOf(t, lines, "response.output_text.delta")[0]["output_index"])
}

func TestResponsesStreamEncoder_ReasoningOnly(t *testing.T) {
	t.Parallel()

	enc := NewResponsesStreamEncoder()
	lines := enc.Content(&CanonicalStreamChunk{ReasoningDelta: "only thinking"})
	lines = append(lines, enc.Finish(&CanonicalStreamChunk{FinishReason: "stop"})...)
	requireSequentialItems(t, lines)
	types := responsesEncoderTypes(t, lines)
	assert.NotContains(t, types, "response.output_text.delta")
	assert.NotContains(t, types, "response.content_part.added")
	output := responsesTerminalOutput(t, lines)
	require.Len(t, output, 1)
	assert.Equal(t, "reasoning", output[0]["type"])
	assert.Equal(t, []any{map[string]any{"type": "summary_text", "text": "only thinking"}}, output[0]["summary"])
}

func TestResponsesStreamEncoder_ReasoningAfterTextIsEmittedAfterTheMessage(t *testing.T) {
	t.Parallel()

	enc := NewResponsesStreamEncoder()
	lines := enc.Content(&CanonicalStreamChunk{
		Delta:          "Answer.",
		ReasoningDelta: "before",
	})
	lines = append(lines, enc.Content(&CanonicalStreamChunk{
		ReasoningDelta: " after",
		ToolCallDeltas: []StreamToolCallDelta{{
			Index: 0, ID: "call_1", Kind: ToolKindCustom, Name: "apply_patch", ArgumentsDelta: "patch",
		}},
	})...)
	lines = append(lines, enc.Finish(&CanonicalStreamChunk{FinishReason: "tool_calls"})...)
	requireSequentialItems(t, lines)

	output := responsesTerminalOutput(t, lines)
	require.Len(t, output, 4)
	assert.Equal(t, "reasoning", output[0]["type"])
	assert.Equal(t, []any{map[string]any{"type": "summary_text", "text": "before"}}, output[0]["summary"])
	assert.Equal(t, "message", output[1]["type"])
	assert.Equal(t, "reasoning", output[2]["type"])
	assert.Equal(t, []any{map[string]any{"type": "summary_text", "text": " after"}}, output[2]["summary"])
	assert.Equal(t, "custom_tool_call", output[3]["type"])
	assert.NotEqual(t, output[0]["id"], output[2]["id"])

	types := responsesEncoderTypes(t, lines)
	messageDone := typesIndex(types, "response.output_text.done")
	secondReasoning := -1
	seenReasoningDone := 0
	for i, eventType := range types {
		if eventType == "response.output_item.done" && jsonItemType(t, responsesEncoderPayloads(lines)[i]) == "reasoning" {
			seenReasoningDone++
			if seenReasoningDone == 2 {
				secondReasoning = i
			}
		}
	}
	custom := typesIndex(types, "response.custom_tool_call_input.done")
	require.NotEqual(t, -1, messageDone)
	require.NotEqual(t, -1, secondReasoning)
	require.NotEqual(t, -1, custom)
	assert.Less(t, messageDone, secondReasoning)
	assert.Less(t, secondReasoning, custom)
}

func TestResponsesStreamEncoder_LengthStopKeepsCompletedReasoning(t *testing.T) {
	t.Parallel()

	enc := NewResponsesStreamEncoder()
	lines := enc.Content(&CanonicalStreamChunk{ReasoningDelta: "hmm"})
	lines = append(lines, enc.Content(&CanonicalStreamChunk{
		Delta: "Hi",
		ToolCallDeltas: []StreamToolCallDelta{{
			Index: 0, ID: "call_1", Name: "f", ArgumentsDelta: `{"x"`,
		}},
	})...)
	lines = append(lines, enc.Finish(&CanonicalStreamChunk{FinishReason: "length"})...)
	requireSequentialItems(t, lines)
	assert.Equal(t, 1, enc.Withheld())
	assert.NotContains(t, responsesEncoderTypes(t, lines), "response.function_call_arguments.delta")

	output := responsesTerminalOutput(t, lines)
	require.Len(t, output, 2)
	assert.Equal(t, "reasoning", output[0]["type"])
	assert.Equal(t, "completed", output[0]["status"])
	assert.Equal(t, "message", output[1]["type"])
	assert.Equal(t, "incomplete", output[1]["status"])
}

func TestResponsesStreamEncoder_AbortClosesOpenReasoning(t *testing.T) {
	t.Parallel()

	enc := NewResponsesStreamEncoder()
	lines := enc.Content(&CanonicalStreamChunk{ID: "resp_1", ReasoningDelta: "partial"})
	lines = append(lines, enc.Abort("upstream stream failed", nil)...)
	requireSequentialItems(t, lines)
	assert.True(t, enc.Aborted())
	output := responsesTerminalOutput(t, lines)
	require.Len(t, output, 1)
	assert.Equal(t, "reasoning", output[0]["type"])
	assert.Equal(t, "incomplete", output[0]["status"])
	assert.Equal(t, []any{map[string]any{"type": "summary_text", "text": "partial"}}, output[0]["summary"])
}

func TestDecodeResponsesRequest_CustomToolHistory(t *testing.T) {
	t.Parallel()

	body := []byte(`{"model":"gpt-5.1","input":[
		{"role":"user","content":"Patch it."},
		{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Applying."}]},
		{"type":"function_call","call_id":"call_fn","name":"get_weather","arguments":"{}"},
		{"type":"custom_tool_call","call_id":"call_patch","name":"apply_patch","input":"*** Begin Patch\n+line"},
		{"role":"developer","content":"Be brief."},
		{"type":"custom_tool_call_output","call_id":"call_patch","output":"applied"},
		{"type":"function_call_output","call_id":"call_fn","output":[{"type":"input_text","text":"sunny"}]},
		{"role":"user","content":"Thanks."},
		{"type":"custom_tool_call","id":"ctc_next","name":"apply_patch","input":"second"},
		{"type":"custom_tool_call_output","call_id":"ctc_next","output":""}
	]}`)

	cr, err := (&OpenAIResponsesAdapter{}).DecodeRequest(body)
	require.NoError(t, err)
	assert.Zero(t, cr.DroppedInputItems)
	assert.Equal(t, "Be brief.", cr.System)
	assert.Equal(t, []CanonicalMessage{
		{Role: "user", Content: "Patch it."},
		{Role: "assistant", Content: "Applying.", ToolCalls: []CanonicalToolCall{
			{ID: "call_fn", Name: "get_weather", Arguments: "{}"},
			{ID: "call_patch", Kind: ToolKindCustom, Name: "apply_patch", Arguments: "*** Begin Patch\n+line"},
		}},
		{Role: "tool", Content: "applied", ToolCallID: "call_patch"},
		{Role: "tool", Content: "sunny", ToolCallID: "call_fn"},
		{Role: "user", Content: "Thanks."},
		{Role: "assistant", ToolCalls: []CanonicalToolCall{
			{ID: "ctc_next", Kind: ToolKindCustom, Name: "apply_patch", Arguments: "second"},
		}},
		{Role: "tool", Content: responsesNonTextToolOutput, ToolCallID: "ctc_next"},
	}, cr.Messages)
}

func TestDecodeResponsesRequest_CustomToolInputIsNotRewritten(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "omitted", input: ``, want: ""},
		{name: "empty string", input: `,"input":""`, want: ""},
		{name: "null", input: `,"input":null`, want: ""},
		{name: "freeform", input: `,"input":"{not json"`, want: "{not json"},
		{name: "object", input: `,"input":{"path":"a.go"}`, want: `{"path":"a.go"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body := `{"model":"m","input":[{"type":"custom_tool_call","call_id":"c","name":"apply_patch"` + tt.input + `}]}`
			cr, err := (&OpenAIResponsesAdapter{}).DecodeRequest([]byte(body))
			require.NoError(t, err)
			assert.Zero(t, cr.DroppedInputItems)
			require.Len(t, cr.Messages, 1)
			assert.Equal(t, []CanonicalToolCall{{
				ID: "c", Kind: ToolKindCustom, Name: "apply_patch", Arguments: tt.want,
			}}, cr.Messages[0].ToolCalls)
		})
	}
}

func TestDecodeResponsesRequest_CustomToolOutputEndsTheTurn(t *testing.T) {
	t.Parallel()

	body := []byte(`{"model":"m","input":[
		{"type":"custom_tool_call","call_id":"c1","name":"apply_patch","input":"one"},
		{"type":"function_call","call_id":"c2","name":"lookup","arguments":"{}"},
		{"type":"custom_tool_call_output","call_id":"c1","output":"done-custom"},
		{"type":"function_call_output","call_id":"c2","output":"done-fn"},
		{"role":"assistant","content":"All done."}
	]}`)
	cr, err := (&OpenAIResponsesAdapter{}).DecodeRequest(body)
	require.NoError(t, err)
	assert.Equal(t, []CanonicalMessage{
		{Role: "assistant", ToolCalls: []CanonicalToolCall{
			{ID: "c1", Kind: ToolKindCustom, Name: "apply_patch", Arguments: "one"},
			{ID: "c2", Name: "lookup", Arguments: "{}"},
		}},
		{Role: "tool", Content: "done-custom", ToolCallID: "c1"},
		{Role: "tool", Content: "done-fn", ToolCallID: "c2"},
		{Role: "assistant", Content: "All done."},
	}, cr.Messages)
}

func TestEncodeResponsesRequest_AssistantTextAndToolCalls(t *testing.T) {
	t.Parallel()

	a := &OpenAIResponsesAdapter{}
	req := &CanonicalRequest{
		Model: "gpt-4o",
		Messages: []CanonicalMessage{
			{Role: "user", Content: "Weather?"},
			{Role: "assistant", Content: "Checking.", ToolCalls: []CanonicalToolCall{
				{ID: "call_1", Name: "get_weather", Arguments: `{"city":"Paris"}`},
				{ID: "call_cu", Kind: ToolKindCustom, Name: "apply_patch", Arguments: "*** Begin Patch"},
			}},
			{Role: "tool", Content: "sunny", ToolCallID: "call_1"},
			{Role: "tool", Content: "patched", ToolCallID: "call_cu"},
		},
	}
	out, err := a.EncodeRequest(req)
	require.NoError(t, err)

	var raw struct {
		Input []map[string]any `json:"input"`
	}
	require.NoError(t, json.Unmarshal(out, &raw))
	require.Len(t, raw.Input, 6)
	assert.Equal(t, "user", raw.Input[0]["role"])
	assert.Equal(t, "Weather?", raw.Input[0]["content"])
	assert.Equal(t, "assistant", raw.Input[1]["role"])
	assert.Equal(t, "Checking.", raw.Input[1]["content"])
	assert.Equal(t, "function_call", raw.Input[2]["type"])
	assert.Equal(t, "call_1", raw.Input[2]["call_id"])
	assert.Equal(t, `{"city":"Paris"}`, raw.Input[2]["arguments"])
	assert.Equal(t, "fc_call_1", raw.Input[2]["id"])
	assert.Equal(t, "custom_tool_call", raw.Input[3]["type"])
	assert.Equal(t, "call_cu", raw.Input[3]["call_id"])
	assert.Equal(t, "*** Begin Patch", raw.Input[3]["input"])
	assert.Equal(t, "ctc_call_cu", raw.Input[3]["id"])
	assert.NotContains(t, raw.Input[3], "arguments")
	assert.Equal(t, "function_call_output", raw.Input[4]["type"])
	assert.Equal(t, "call_1", raw.Input[4]["call_id"])
	assert.Equal(t, "sunny", raw.Input[4]["output"])
	assert.Equal(t, "custom_tool_call_output", raw.Input[5]["type"])
	assert.Equal(t, "call_cu", raw.Input[5]["call_id"])
	assert.Equal(t, "patched", raw.Input[5]["output"])

	again, err := a.DecodeRequest(out)
	require.NoError(t, err)
	assert.Equal(t, req.Messages, again.Messages)
}

func TestEncodeResponsesRequest_ToolCallsWithoutTextOmitTheMessage(t *testing.T) {
	t.Parallel()

	out, err := (&OpenAIResponsesAdapter{}).EncodeRequest(&CanonicalRequest{
		Model: "gpt-4o",
		Messages: []CanonicalMessage{
			{Role: "assistant", ToolCalls: []CanonicalToolCall{
				{ID: "call_1", Name: "f", Arguments: "{}"},
			}},
		},
	})
	require.NoError(t, err)
	var raw struct {
		Input []map[string]any `json:"input"`
	}
	require.NoError(t, json.Unmarshal(out, &raw))
	require.Len(t, raw.Input, 1)
	assert.Equal(t, "function_call", raw.Input[0]["type"])
	assert.Equal(t, "{}", raw.Input[0]["arguments"])
}

func TestEncodeResponsesRequest_CustomHistoryRoundTrip(t *testing.T) {
	t.Parallel()

	a := &OpenAIResponsesAdapter{}
	body := []byte(`{"model":"gpt-5.1","input":[
		{"role":"user","content":"Patch it."},
		{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Applying."}]},
		{"type":"custom_tool_call","call_id":"call_patch","name":"apply_patch","input":"*** Begin Patch\n+line"},
		{"type":"custom_tool_call_output","call_id":"call_patch","output":"applied"},
		{"role":"user","content":"Thanks."}
	]}`)
	first, err := a.DecodeRequest(body)
	require.NoError(t, err)
	encoded, err := a.EncodeRequest(first)
	require.NoError(t, err)
	second, err := a.DecodeRequest(encoded)
	require.NoError(t, err)
	assert.Equal(t, first.Messages, second.Messages)
	assert.Equal(t, ToolKindCustom, second.Messages[1].ToolCalls[0].Kind)
	assert.Equal(t, "*** Begin Patch\n+line", second.Messages[1].ToolCalls[0].Arguments)
	assert.Equal(t, "Applying.", second.Messages[1].Content)
	assert.Equal(t, "applied", second.Messages[2].Content)
}

func typesIndex(types []string, want string) int {
	for i, eventType := range types {
		if eventType == want {
			return i
		}
	}
	return -1
}

func jsonItemType(t *testing.T, payload string) string {
	t.Helper()
	var event struct {
		Item struct {
			Type string `json:"type"`
		} `json:"item"`
	}
	require.NoError(t, json.Unmarshal([]byte(payload), &event))
	return event.Item.Type
}

func TestDecodeResponsesStreamChunk_CustomToolCall(t *testing.T) {
	tests := []struct {
		name string
		body string
		want StreamToolCallDelta
	}{
		{
			name: "output item added",
			body: `{"type":"response.output_item.added","output_index":2,"item":{"type":"custom_tool_call","id":"ctc_1","call_id":"call_1","name":"shell","input":""}}`,
			want: StreamToolCallDelta{Index: 2, ID: "call_1", Kind: ToolKindCustom, Name: "shell"},
		},
		{
			name: "output item added with input",
			body: `{"type":"response.output_item.added","output_index":2,"item":{"type":"custom_tool_call","call_id":"call_1","name":"shell","input":"rm -rf /"}}`,
			want: StreamToolCallDelta{Index: 2, ID: "call_1", Kind: ToolKindCustom, Name: "shell", ArgumentsDelta: "rm -rf /"},
		},
		{
			name: "input delta",
			body: `{"type":"response.custom_tool_call_input.delta","output_index":2,"item_id":"ctc_1","delta":"rm -rf"}`,
			want: StreamToolCallDelta{Index: 2, Kind: ToolKindCustom, ArgumentsDelta: "rm -rf"},
		},
		{
			name: "input done",
			body: `{"type":"response.custom_tool_call_input.done","output_index":2,"item_id":"ctc_1","input":"rm -rf /"}`,
			want: StreamToolCallDelta{Index: 2, Kind: ToolKindCustom, ArgumentsSnapshot: "rm -rf /", HasArgumentsSnapshot: true},
		},
		{
			name: "input done states an empty input",
			body: `{"type":"response.custom_tool_call_input.done","output_index":2,"input":""}`,
			want: StreamToolCallDelta{Index: 2, Kind: ToolKindCustom, HasArgumentsSnapshot: true},
		},
		{
			name: "input done without an input states nothing",
			body: `{"type":"response.custom_tool_call_input.done","output_index":2}`,
			want: StreamToolCallDelta{Index: 2, Kind: ToolKindCustom},
		},
		{
			name: "output item done",
			body: `{"type":"response.output_item.done","output_index":2,"item":{"type":"custom_tool_call","call_id":"call_1","name":"shell","input":"rm -rf /"}}`,
			want: StreamToolCallDelta{Index: 2, ID: "call_1", Kind: ToolKindCustom, Name: "shell", ArgumentsSnapshot: "rm -rf /", HasArgumentsSnapshot: true},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chunk, err := decodeResponsesStreamChunk([]byte(tc.body))
			require.NoError(t, err)
			require.NotNil(t, chunk)
			require.Len(t, chunk.ToolCallDeltas, 1)
			assert.Equal(t, tc.want, chunk.ToolCallDeltas[0])
			assert.Empty(t, chunk.FinishReason)
		})
	}
}

func TestDecodeResponsesStreamChunk_OtherOutputItemDoneDecodesToNothing(t *testing.T) {
	for _, item := range []string{
		`{"type":"message","role":"assistant","content":[]}`,
		`{"type":"function_call","call_id":"call_1","name":"f","arguments":"{}"}`,
		`{"type":"local_shell_call","call_id":"call_1","action":{"type":"exec"}}`,
	} {
		chunk, err := decodeResponsesStreamChunk([]byte(`{"type":"response.output_item.done","output_index":0,"item":` + item + `}`))
		require.NoError(t, err)
		assert.Nil(t, chunk, item)
	}
}

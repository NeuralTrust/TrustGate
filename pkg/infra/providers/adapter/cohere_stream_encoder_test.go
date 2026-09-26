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
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type cohereWireEvent struct {
	Type  string          `json:"type"`
	ID    string          `json:"id"`
	Index *int            `json:"index"`
	Delta json.RawMessage `json:"delta"`
	raw   string
}

var cohereGeneratedID = regexp.MustCompile(`^(call|msg)_[A-Z2-7]{26}(_\d+)?$`)

func cohereEvents(t *testing.T, lines [][]byte) []cohereWireEvent {
	t.Helper()
	var events []cohereWireEvent
	var name string
	for _, l := range lines {
		line := string(l)
		if n, ok := strings.CutPrefix(line, "event: "); ok {
			name = n
			continue
		}
		payload, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		if payload == "[DONE]" {
			require.Empty(t, name, "[DONE] has no event: line")
			events = append(events, cohereWireEvent{Type: payload, raw: payload})
			continue
		}
		var ev cohereWireEvent
		require.NoError(t, json.Unmarshal([]byte(payload), &ev))
		require.Equal(t, name, ev.Type, "event: line names the data type")
		ev.raw = payload
		name = ""
		events = append(events, ev)
	}
	return events
}

func requireCohereContract(t *testing.T, events []cohereWireEvent) {
	t.Helper()
	require.GreaterOrEqual(t, len(events), 3)
	require.Equal(t, "message-start", events[0].Type)
	require.Equal(t, "[DONE]", events[len(events)-1].Type, "[DONE] follows message-end")
	end := events[len(events)-2]
	require.Equal(t, "message-end", end.Type)
	var endDelta struct {
		Usage *struct {
			BilledUnits *struct{} `json:"billed_units"`
			Tokens      *struct{} `json:"tokens"`
		} `json:"usage"`
	}
	require.NoError(t, json.Unmarshal(end.Delta, &endDelta))
	require.NotNil(t, endDelta.Usage, "message-end carries usage")
	require.NotNil(t, endDelta.Usage.BilledUnits, "message-end carries usage.billed_units")
	require.NotNil(t, endDelta.Usage.Tokens, "message-end carries usage.tokens")
	openContent, openTool := -1, -1
	nextContent, nextTool := 0, 0
	for i, ev := range events[1 : len(events)-2] {
		require.NotNil(t, ev.Index, "event %d %s carries an index", i, ev.Type)
		index := *ev.Index
		switch ev.Type {
		case "content-start":
			require.Equal(t, -1, openContent)
			require.Equal(t, -1, openTool)
			require.Equal(t, nextContent, index)
			openContent, nextContent = index, nextContent+1
		case "content-delta":
			require.Equal(t, openContent, index)
		case "content-end":
			require.Equal(t, openContent, index)
			openContent = -1
		case "tool-call-start":
			require.Equal(t, -1, openContent)
			require.Equal(t, -1, openTool)
			require.Equal(t, nextTool, index)
			openTool, nextTool = index, nextTool+1
		case "tool-call-delta":
			require.Equal(t, openTool, index)
		case "tool-call-end":
			require.Equal(t, openTool, index)
			openTool = -1
		default:
			require.Failf(t, "unexpected event inside the message", "event %d: %s", i, ev.Type)
		}
	}
	require.Equal(t, -1, openContent, "content ends before message-end")
	require.Equal(t, -1, openTool, "tool call ends before message-end")
}

func cohereGolden(t *testing.T, events []cohereWireEvent) []string {
	t.Helper()
	var delta struct {
		FinishReason string `json:"finish_reason"`
		Message      struct {
			Content struct {
				Text string `json:"text"`
			} `json:"content"`
			ToolCalls struct {
				ID       string `json:"id"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
	}
	out := make([]string, 0, len(events))
	for _, ev := range events {
		delta.FinishReason, delta.Message.Content.Text = "", ""
		delta.Message.ToolCalls.ID, delta.Message.ToolCalls.Function.Name, delta.Message.ToolCalls.Function.Arguments = "", "", ""
		if len(ev.Delta) > 0 {
			require.NoError(t, json.Unmarshal(ev.Delta, &delta))
		}
		switch ev.Type {
		case "message-start":
			out = append(out, ev.Type)
		case "content-start", "content-end", "tool-call-end":
			out = append(out, fmt.Sprintf("%s %d", ev.Type, *ev.Index))
		case "content-delta":
			out = append(out, fmt.Sprintf("content-delta %d %s", *ev.Index, delta.Message.Content.Text))
		case "tool-call-start":
			id := cohereGeneratedID.ReplaceAllString(delta.Message.ToolCalls.ID, "${1}_*$2")
			out = append(out, fmt.Sprintf("tool-call-start %d %s %s", *ev.Index, id, delta.Message.ToolCalls.Function.Name))
		case "tool-call-delta":
			out = append(out, fmt.Sprintf("tool-call-delta %d %s", *ev.Index, delta.Message.ToolCalls.Function.Arguments))
		case "message-end":
			out = append(out, "message-end "+delta.FinishReason)
		}
	}
	return out
}

func encodeCohereStream(target Format, chunks ...*CanonicalStreamChunk) [][]byte {
	e := NewCohereStreamEncoder(target)
	var lines [][]byte
	for _, c := range chunks[:len(chunks)-1] {
		lines = append(lines, e.Content(c)...)
	}
	return append(lines, e.Finish(chunks[len(chunks)-1])...)
}

func TestCohereStreamEncoder_EventSequence(t *testing.T) {
	tests := []struct {
		name   string
		target Format
		chunks []*CanonicalStreamChunk
		want   []string
	}{
		{
			name:   "text only",
			target: FormatOpenAI,
			chunks: []*CanonicalStreamChunk{
				{ID: "c1", Role: "assistant"},
				{Delta: "Hel"},
				{Delta: "lo"},
				{FinishReason: "stop"},
			},
			want: []string{
				"message-start",
				"content-start 0", "content-delta 0 Hel", "content-delta 0 lo", "content-end 0",
				"message-end COMPLETE",
			},
		},
		{
			name:   "text then tool",
			target: FormatOpenAI,
			chunks: []*CanonicalStreamChunk{
				{Role: "assistant", Delta: "Let me check"},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "get_weather"}}},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ArgumentsDelta: `{"city":`}}},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ArgumentsDelta: `"Paris"}`}}},
				{FinishReason: "tool_calls"},
			},
			want: []string{
				"message-start",
				"content-start 0", "content-delta 0 Let me check", "content-end 0",
				"tool-call-start 0 call_1 get_weather", `tool-call-delta 0 {"city":`, `tool-call-delta 0 "Paris"}`, "tool-call-end 0",
				"message-end TOOL_CALL",
			},
		},
		{
			name:   "two parallel tools",
			target: FormatOpenAI,
			chunks: []*CanonicalStreamChunk{
				{Role: "assistant", ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "get_weather"}}},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ArgumentsDelta: `{"city":"Paris"}`}}},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 1, ID: "call_2", Name: "get_time", ArgumentsDelta: `{"tz":`}}},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 1, ArgumentsDelta: `"CET"}`}}},
				{FinishReason: "tool_calls"},
			},
			want: []string{
				"message-start",
				"tool-call-start 0 call_1 get_weather", `tool-call-delta 0 {"city":"Paris"}`, "tool-call-end 0",
				"tool-call-start 1 call_2 get_time", `tool-call-delta 1 {"tz":`, `tool-call-delta 1 "CET"}`, "tool-call-end 1",
				"message-end TOOL_CALL",
			},
		},
		{
			name:   "text inside incomplete tool arguments is held until the call ends",
			target: FormatOpenAI,
			chunks: []*CanonicalStreamChunk{
				{Role: "assistant", ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "get_weather", ArgumentsDelta: `{"city":`}}},
				{Delta: "note"},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ArgumentsDelta: `"Paris"}`}}},
				{FinishReason: "tool_calls"},
			},
			want: []string{
				"message-start",
				"tool-call-start 0 call_1 get_weather", `tool-call-delta 0 {"city":`, `tool-call-delta 0 "Paris"}`, "tool-call-end 0",
				"content-start 0", "content-delta 0 note", "content-end 0",
				"message-end TOOL_CALL",
			},
		},
		{
			name:   "arguments before the name and without an id",
			target: FormatOpenAI,
			chunks: []*CanonicalStreamChunk{
				{Role: "assistant", ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ArgumentsDelta: `{"city":`}}},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, Name: "get_weather", ArgumentsDelta: `"Paris"}`}}},
				{FinishReason: "tool_calls"},
			},
			want: []string{
				"message-start",
				"tool-call-start 0 call_*_0 get_weather", `tool-call-delta 0 {"city":"Paris"}`, "tool-call-end 0",
				"message-end TOOL_CALL",
			},
		},
		{
			name:   "gemini calls reusing index 0 and the function name as id",
			target: FormatGemini,
			chunks: []*CanonicalStreamChunk{
				{Role: "assistant", ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "get_weather", Name: "get_weather", ArgumentsDelta: `{"city":"Paris"}`}}},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "get_weather", Name: "get_weather", ArgumentsDelta: `{"city":"Rome"}`}}},
				{FinishReason: "stop"},
			},
			want: []string{
				"message-start",
				"tool-call-start 0 get_weather get_weather", `tool-call-delta 0 {"city":"Paris"}`, "tool-call-end 0",
				"tool-call-start 1 call_*_1 get_weather", `tool-call-delta 1 {"city":"Rome"}`, "tool-call-end 1",
				"message-end TOOL_CALL",
			},
		},
		{
			name:   "nameless tool call dropped",
			target: FormatOpenAI,
			chunks: []*CanonicalStreamChunk{
				{Role: "assistant", Delta: "hi", ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ArgumentsDelta: `{}`}}},
				{FinishReason: "tool_calls"},
			},
			want: []string{
				"message-start",
				"content-start 0", "content-delta 0 hi", "content-end 0",
				"message-end COMPLETE",
			},
		},
		{
			name:   "parallel tools announced with empty arguments stream one after another",
			target: FormatOpenAI,
			chunks: []*CanonicalStreamChunk{
				{Role: "assistant", ToolCallDeltas: []StreamToolCallDelta{
					{Index: 0, ID: "call_1", Name: "get_weather", ArgumentsDelta: ""},
					{Index: 1, ID: "call_2", Name: "get_time", ArgumentsDelta: ""},
				}},
				{ToolCallDeltas: []StreamToolCallDelta{
					{Index: 0, ArgumentsDelta: `{"city":"Paris"}`},
					{Index: 1, ArgumentsDelta: `{"tz":"CET"}`},
				}},
				{FinishReason: "tool_calls"},
			},
			want: []string{
				"message-start",
				"tool-call-start 0 call_1 get_weather", `tool-call-delta 0 {"city":"Paris"}`, "tool-call-end 0",
				"tool-call-start 1 call_2 get_time", `tool-call-delta 1 {"tz":"CET"}`, "tool-call-end 1",
				"message-end TOOL_CALL",
			},
		},
		{
			name:   "interleaved tool arguments wait for the open call",
			target: FormatOpenAI,
			chunks: []*CanonicalStreamChunk{
				{Role: "assistant", ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "a", ArgumentsDelta: `{"x":`}}},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 1, ID: "call_2", Name: "b", ArgumentsDelta: `{"y":`}}},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 1, ArgumentsDelta: `2}`}}},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ArgumentsDelta: `1}`}}},
				{FinishReason: "tool_calls"},
			},
			want: []string{
				"message-start",
				"tool-call-start 0 call_1 a", `tool-call-delta 0 {"x":`, `tool-call-delta 0 1}`, "tool-call-end 0",
				"tool-call-start 1 call_2 b", `tool-call-delta 1 {"y":2}`, "tool-call-end 1",
				"message-end TOOL_CALL",
			},
		},
		{
			name:   "held tools whose arguments never complete start in arrival order at the finish",
			target: FormatOpenAI,
			chunks: []*CanonicalStreamChunk{
				{Role: "assistant", ToolCallDeltas: []StreamToolCallDelta{
					{Index: 0, ID: "call_1", Name: "a"},
					{Index: 2, ID: "call_3", Name: "c"},
					{Index: 1, ID: "call_2", Name: "b"},
				}},
				{FinishReason: "tool_calls"},
			},
			want: []string{
				"message-start",
				"tool-call-start 0 call_1 a", "tool-call-delta 0 {}", "tool-call-end 0",
				"tool-call-start 1 call_3 c", "tool-call-delta 1 {}", "tool-call-end 1",
				"tool-call-start 2 call_2 b", "tool-call-delta 2 {}", "tool-call-end 2",
				"message-end TOOL_CALL",
			},
		},
		{
			name:   "arguments of an open call that follow a later header are kept",
			target: FormatOpenAI,
			chunks: []*CanonicalStreamChunk{
				{Role: "assistant", ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "a"}}},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 1, ID: "call_2", Name: "b"}}},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ArgumentsDelta: `{"x":1}`}}},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 1, ArgumentsDelta: `{"y":2}`}}},
				{FinishReason: "tool_calls"},
			},
			want: []string{
				"message-start",
				"tool-call-start 0 call_1 a", `tool-call-delta 0 {"x":1}`, "tool-call-end 0",
				"tool-call-start 1 call_2 b", `tool-call-delta 1 {"y":2}`, "tool-call-end 1",
				"message-end TOOL_CALL",
			},
		},
		{
			name:   "an argument-less call ends when a later call streams its arguments",
			target: FormatOpenAI,
			chunks: []*CanonicalStreamChunk{
				{Role: "assistant", ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "a"}}},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 1, ID: "call_2", Name: "b"}}},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 1, ArgumentsDelta: `{"y":2}`}}},
				{FinishReason: "tool_calls"},
			},
			want: []string{
				"message-start",
				"tool-call-start 0 call_1 a", "tool-call-delta 0 {}", "tool-call-end 0",
				"tool-call-start 1 call_2 b", `tool-call-delta 1 {"y":2}`, "tool-call-end 1",
				"message-end TOOL_CALL",
			},
		},
		{
			name:   "text after a tool start with empty arguments waits for them",
			target: FormatOpenAI,
			chunks: []*CanonicalStreamChunk{
				{Role: "assistant", ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "get_weather", ArgumentsDelta: ""}}},
				{Delta: "note"},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ArgumentsDelta: `{"city":"Paris"}`}}},
				{FinishReason: "tool_calls"},
			},
			want: []string{
				"message-start",
				"tool-call-start 0 call_1 get_weather", `tool-call-delta 0 {"city":"Paris"}`, "tool-call-end 0",
				"content-start 0", "content-delta 0 note", "content-end 0",
				"message-end TOOL_CALL",
			},
		},
		{
			name:   "held text after a later tool call follows it",
			target: FormatOpenAI,
			chunks: []*CanonicalStreamChunk{
				{Role: "assistant", ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "a", ArgumentsDelta: `{"x":`}}},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 1, ID: "call_2", Name: "b", ArgumentsDelta: `{"y":2}`}}},
				{Delta: "T"},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ArgumentsDelta: `1}`}}},
				{FinishReason: "tool_calls"},
			},
			want: []string{
				"message-start",
				"tool-call-start 0 call_1 a", `tool-call-delta 0 {"x":`, `tool-call-delta 0 1}`, "tool-call-end 0",
				"tool-call-start 1 call_2 b", `tool-call-delta 1 {"y":2}`, "tool-call-end 1",
				"content-start 0", "content-delta 0 T", "content-end 0",
				"message-end TOOL_CALL",
			},
		},
		{
			name:   "held text before a later tool call precedes it",
			target: FormatOpenAI,
			chunks: []*CanonicalStreamChunk{
				{Role: "assistant", ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "a", ArgumentsDelta: `{"x":`}}},
				{Delta: "T"},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 1, ID: "call_2", Name: "b", ArgumentsDelta: `{"y":2}`}}},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ArgumentsDelta: `1}`}}},
				{FinishReason: "tool_calls"},
			},
			want: []string{
				"message-start",
				"tool-call-start 0 call_1 a", `tool-call-delta 0 {"x":`, `tool-call-delta 0 1}`, "tool-call-end 0",
				"content-start 0", "content-delta 0 T", "content-end 0",
				"tool-call-start 1 call_2 b", `tool-call-delta 1 {"y":2}`, "tool-call-end 1",
				"message-end TOOL_CALL",
			},
		},
		{
			name:   "zero-argument tool calls in a row get empty objects",
			target: FormatAnthropic,
			chunks: []*CanonicalStreamChunk{
				{Role: "assistant"},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "toolu_1", Name: "a"}}},
				{ToolCallDeltas: []StreamToolCallDelta{{Index: 1, ID: "toolu_2", Name: "b"}}},
				{FinishReason: "tool_calls"},
			},
			want: []string{
				"message-start",
				"tool-call-start 0 toolu_1 a", "tool-call-delta 0 {}", "tool-call-end 0",
				"tool-call-start 1 toolu_2 b", "tool-call-delta 1 {}", "tool-call-end 1",
				"message-end TOOL_CALL",
			},
		},
		{
			name:   "finish without content still starts the message",
			target: FormatOpenAI,
			chunks: []*CanonicalStreamChunk{{FinishReason: "stop"}},
			want:   []string{"message-start", "message-end COMPLETE"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events := cohereEvents(t, encodeCohereStream(tt.target, tt.chunks...))
			requireCohereContract(t, events)
			assert.Equal(t, tt.want, cohereGolden(t, events))
		})
	}
}

func TestCohereStreamEncoder_FinishReasons(t *testing.T) {
	tests := []struct {
		finish   string
		withTool bool
		want     string
	}{
		{finish: "stop", want: "COMPLETE"},
		{finish: "length", want: "MAX_TOKENS"},
		{finish: "length", withTool: true, want: "MAX_TOKENS"},
		{finish: "tool_calls", withTool: true, want: "TOOL_CALL"},
		{finish: "stop", withTool: true, want: "TOOL_CALL"},
		{finish: "tool_calls", want: "COMPLETE"},
		{finish: "error", want: "ERROR"},
		{finish: "MALFORMED_FUNCTION_CALL", want: "ERROR"},
		{finish: "content_filter", want: "ERROR"},
		{finish: "refusal", want: "ERROR"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s tool=%v", tt.finish, tt.withTool), func(t *testing.T) {
			first := &CanonicalStreamChunk{Role: "assistant", Delta: "hi"}
			if tt.withTool {
				first.ToolCallDeltas = []StreamToolCallDelta{{ID: "call_1", Name: "f", ArgumentsDelta: "{}"}}
			}
			events := cohereEvents(t, encodeCohereStream(FormatOpenAI, first, &CanonicalStreamChunk{FinishReason: tt.finish}))
			requireCohereContract(t, events)
			golden := cohereGolden(t, events)
			assert.Equal(t, "message-end "+tt.want, golden[len(golden)-1])
		})
	}
}

func TestCohereStreamEncoder_WireShape(t *testing.T) {
	usage := &CanonicalUsage{InputTokens: 793, OutputTokens: 61, TotalTokens: 854, CachedInputTokens: 176}
	events := cohereEvents(t, encodeCohereStream(FormatOpenAI,
		&CanonicalStreamChunk{ID: "gen-1", Role: "assistant", Delta: "hi"},
		&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "database_agent"}}},
		&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ArgumentsDelta: `{"q":1}`}}},
		&CanonicalStreamChunk{FinishReason: "tool_calls", Usage: usage},
	))
	raw := make([]string, len(events))
	for i, ev := range events {
		raw[i] = ev.raw
	}
	want := []string{
		`{"id":"gen-1","type":"message-start","delta":{"message":{"role":"assistant"}}}`,
		`{"type":"content-start","index":0,"delta":{"message":{"content":{"type":"text","text":""}}}}`,
		`{"type":"content-delta","index":0,"delta":{"message":{"content":{"text":"hi"}}}}`,
		`{"type":"content-end","index":0}`,
		`{"type":"tool-call-start","index":0,"delta":{"message":{"tool_calls":{"id":"call_1","type":"function","function":{"name":"database_agent","arguments":""}}}}}`,
		`{"type":"tool-call-delta","index":0,"delta":{"message":{"tool_calls":{"function":{"arguments":"{\"q\":1}"}}}}}`,
		`{"type":"tool-call-end","index":0}`,
		`{"type":"message-end","delta":{"finish_reason":"TOOL_CALL","usage":{"billed_units":{"input_tokens":793,"output_tokens":61},"tokens":{"input_tokens":793,"output_tokens":61},"cached_tokens":176}}}`,
		`[DONE]`,
	}
	assert.Equal(t, want, raw)

	back, err := (&CohereAdapter{}).DecodeStreamChunk([]byte(raw[len(raw)-2]))
	require.NoError(t, err)
	require.NotNil(t, back)
	assert.Equal(t, usage, back.Usage)
	assert.Equal(t, "tool_calls", back.FinishReason)
}

func TestCohereStreamEncoder_NothingAfterFinish(t *testing.T) {
	e := NewCohereStreamEncoder(FormatOpenAI)
	e.Content(&CanonicalStreamChunk{Role: "assistant", Delta: "hi"})
	require.NotEmpty(t, e.Finish(&CanonicalStreamChunk{FinishReason: "stop"}))

	assert.Empty(t, e.Content(&CanonicalStreamChunk{Delta: "late"}))
	assert.Empty(t, e.Finish(&CanonicalStreamChunk{FinishReason: "stop"}))
}

func TestCohereStreamEncoder_Dropped(t *testing.T) {
	e := NewCohereStreamEncoder(FormatOpenAI)
	e.Content(&CanonicalStreamChunk{Role: "assistant", ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "a", ArgumentsDelta: `{"x":1}`}}})
	e.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 1, ID: "call_2", Name: "b", ArgumentsDelta: `{}`}}})
	e.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ArgumentsDelta: ` `}}})
	e.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 2, ArgumentsDelta: `{}`}}})
	e.Finish(&CanonicalStreamChunk{FinishReason: "tool_calls"})

	deltas, tools := e.Dropped()
	assert.Equal(t, 1, deltas)
	assert.Equal(t, 1, tools)
}

func TestCohereStreamEncoder_FailureCarriesError(t *testing.T) {
	tests := []struct {
		finish string
		want   string
	}{
		{finish: "error", want: "upstream reported an error while generating the message"},
		{finish: "MALFORMED_FUNCTION_CALL", want: "upstream generated a malformed tool call"},
		{finish: "content_filter", want: "content filtered"},
		{finish: "stop"},
	}
	for _, tt := range tests {
		t.Run(tt.finish, func(t *testing.T) {
			events := cohereEvents(t, encodeCohereStream(FormatOpenAI,
				&CanonicalStreamChunk{Role: "assistant", Delta: "hi"},
				&CanonicalStreamChunk{FinishReason: tt.finish},
			))
			requireCohereContract(t, events)
			var delta struct {
				Error *string `json:"error"`
			}
			require.NoError(t, json.Unmarshal(events[len(events)-2].Delta, &delta))
			if tt.want == "" {
				assert.Nil(t, delta.Error, "error is omitted when the message did not fail")
				return
			}
			require.NotNil(t, delta.Error)
			assert.Equal(t, tt.want, *delta.Error)
		})
	}
}

func TestCohereStreamEncoder_MessageEndWithoutUsage(t *testing.T) {
	events := cohereEvents(t, encodeCohereStream(FormatOpenAI, &CanonicalStreamChunk{FinishReason: "stop"}))

	assert.Equal(t,
		`{"type":"message-end","delta":{"finish_reason":"COMPLETE","usage":{"billed_units":{"input_tokens":0,"output_tokens":0},"tokens":{"input_tokens":0,"output_tokens":0}}}}`,
		events[len(events)-2].raw)
}

func TestCohereStreamEncoder_Abort(t *testing.T) {
	e := NewCohereStreamEncoder(FormatOpenAI)
	assert.False(t, e.Started())
	lines := e.Content(&CanonicalStreamChunk{Role: "assistant", Delta: "hi"})
	lines = append(lines, e.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "a", ArgumentsDelta: `{"x":`}}})...)
	lines = append(lines, e.Content(&CanonicalStreamChunk{Delta: "held"})...)
	lines = append(lines, e.Abort("upstream stream failed", &CanonicalUsage{InputTokens: 5, OutputTokens: 1, TotalTokens: 6})...)

	events := cohereEvents(t, lines)
	requireCohereContract(t, events)
	assert.Equal(t, []string{
		"message-start",
		"content-start 0", "content-delta 0 hi", "content-end 0",
		"tool-call-start 0 call_1 a", `tool-call-delta 0 {"x":`, "tool-call-end 0",
		"content-start 1", "content-delta 1 held", "content-end 1",
		"message-end ERROR",
	}, cohereGolden(t, events))
	assert.JSONEq(t,
		`{"finish_reason":"ERROR","error":"upstream stream failed","usage":{"billed_units":{"input_tokens":5,"output_tokens":1},"tokens":{"input_tokens":5,"output_tokens":1}}}`,
		string(events[len(events)-2].Delta))
	assert.True(t, e.Started())
	assert.True(t, e.Aborted())
	assert.Empty(t, e.Finish(&CanonicalStreamChunk{FinishReason: "stop"}))
	assert.Empty(t, e.Abort("again", nil))
}

func TestCohereStreamEncoder_AbortLeavesArgumentsAsTheyStand(t *testing.T) {
	e := NewCohereStreamEncoder(FormatOpenAI)
	lines := e.Content(&CanonicalStreamChunk{Role: "assistant", ToolCallDeltas: []StreamToolCallDelta{
		{Index: 0, ID: "call_1", Name: "a"},
		{Index: 1, ID: "call_2", Name: "b"},
	}})
	lines = append(lines, e.Content(&CanonicalStreamChunk{Delta: "T"})...)
	lines = append(lines, e.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 2, ArgumentsDelta: `{}`}}})...)
	lines = append(lines, e.Abort("upstream stream failed", nil)...)

	events := cohereEvents(t, lines)
	requireCohereContract(t, events)
	assert.Equal(t, []string{
		"message-start",
		"tool-call-start 0 call_1 a", "tool-call-end 0",
		"content-start 0", "content-delta 0 T", "content-end 0",
		"message-end ERROR",
	}, cohereGolden(t, events), "no arguments are invented and held text keeps its place")
	deltas, tools := e.Dropped()
	assert.Equal(t, 0, deltas)
	assert.Equal(t, 2, tools, "the held call and the nameless one never reached the client")
}

func TestCohereStreamEncoder_HeldCallSupersededByALaterOne(t *testing.T) {
	e := NewCohereStreamEncoder(FormatOpenAI)
	lines := e.Content(&CanonicalStreamChunk{Role: "assistant", ToolCallDeltas: []StreamToolCallDelta{
		{Index: 0, ID: "call_1", Name: "a"},
		{Index: 1, ID: "call_2", Name: "b"},
	}})
	lines = append(lines, e.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 2, ID: "call_3", Name: "c", ArgumentsDelta: `{"z":3}`}}})...)

	assert.Equal(t, []string{
		"message-start",
		"tool-call-start 0 call_1 a", "tool-call-delta 0 {}", "tool-call-end 0",
		"tool-call-start 1 call_2 b", "tool-call-delta 1 {}", "tool-call-end 1",
		"tool-call-start 2 call_3 c", `tool-call-delta 2 {"z":3}`,
	}, cohereGolden(t, cohereEvents(t, lines)), "the later call streams before the finish")
}

func TestCohereStreamEncoder_CallReplacedAtItsIndexSupersedesIt(t *testing.T) {
	e := NewCohereStreamEncoder(FormatOpenAI)
	lines := e.Content(&CanonicalStreamChunk{Role: "assistant", ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "a"}}})
	lines = append(lines, e.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_2", Name: "b", ArgumentsDelta: `{"y":2}`}}})...)
	streamed := cohereGolden(t, cohereEvents(t, lines))
	lines = append(lines, e.Abort("upstream stream failed", nil)...)

	want := []string{
		"message-start",
		"tool-call-start 0 call_1 a", "tool-call-delta 0 {}", "tool-call-end 0",
		"tool-call-start 1 call_2 b", `tool-call-delta 1 {"y":2}`,
	}
	assert.Equal(t, want, streamed, "the replacing call streams before the finish")
	events := cohereEvents(t, lines)
	requireCohereContract(t, events)
	assert.Equal(t, append(want, "tool-call-end 1", "message-end ERROR"), cohereGolden(t, events))
	deltas, tools := e.Dropped()
	assert.Equal(t, 0, deltas)
	assert.Equal(t, 0, tools)
}

func TestCohereStreamEncoder_SequentialCallsSupersedeOnTheirHeader(t *testing.T) {
	chunks := []*CanonicalStreamChunk{
		{Role: "assistant", ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "a"}}},
		{ToolCallDeltas: []StreamToolCallDelta{{Index: 1, ID: "call_2", Name: "b"}}},
		{Delta: "T"},
	}
	tests := []struct {
		name     string
		target   Format
		streamed []string
		aborted  []string
	}{
		{
			name:     "anthropic",
			target:   FormatAnthropic,
			streamed: []string{"message-start", "tool-call-start 0 call_1 a", "tool-call-delta 0 {}", "tool-call-end 0", "tool-call-start 1 call_2 b"},
			aborted:  []string{"tool-call-end 1", "content-start 0", "content-delta 0 T", "content-end 0", "message-end ERROR"},
		},
		{
			name:     "bedrock",
			target:   FormatBedrock,
			streamed: []string{"message-start", "tool-call-start 0 call_1 a", "tool-call-delta 0 {}", "tool-call-end 0", "tool-call-start 1 call_2 b"},
			aborted:  []string{"tool-call-end 1", "content-start 0", "content-delta 0 T", "content-end 0", "message-end ERROR"},
		},
		{
			name:     "openai holds the second header",
			target:   FormatOpenAI,
			streamed: []string{"message-start", "tool-call-start 0 call_1 a"},
			aborted:  []string{"tool-call-end 0", "content-start 0", "content-delta 0 T", "content-end 0", "message-end ERROR"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewCohereStreamEncoder(tt.target)
			var lines [][]byte
			for _, c := range chunks {
				lines = append(lines, e.Content(c)...)
			}
			assert.Equal(t, tt.streamed, cohereGolden(t, cohereEvents(t, lines)))
			lines = append(lines, e.Abort("upstream stream failed", nil)...)
			events := cohereEvents(t, lines)
			requireCohereContract(t, events)
			assert.Equal(t, append(append([]string{}, tt.streamed...), tt.aborted...), cohereGolden(t, events))
		})
	}
}

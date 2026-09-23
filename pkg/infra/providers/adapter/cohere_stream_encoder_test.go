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
	require.GreaterOrEqual(t, len(events), 2)
	require.Equal(t, "message-start", events[0].Type)
	require.Equal(t, "message-end", events[len(events)-1].Type)
	openContent, openTool := -1, -1
	nextContent, nextTool := 0, 0
	for i, ev := range events[1 : len(events)-1] {
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
		{finish: "content_filter", want: "COMPLETE"},
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
	}
	assert.Equal(t, want, raw)

	back, err := (&CohereAdapter{}).DecodeStreamChunk([]byte(raw[len(raw)-1]))
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
	e.Content(&CanonicalStreamChunk{Role: "assistant", ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "a", ArgumentsDelta: `{"x":`}}})
	e.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 1, ID: "call_2", Name: "b", ArgumentsDelta: `{}`}}})
	e.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ArgumentsDelta: `1}`}}})
	e.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 2, ArgumentsDelta: `{}`}}})
	e.Finish(&CanonicalStreamChunk{FinishReason: "tool_calls"})

	deltas, tools := e.Dropped()
	assert.Equal(t, 1, deltas)
	assert.Equal(t, 1, tools)
}

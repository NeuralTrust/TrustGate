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
		default:
			events = append(events, event.Type)
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
				"added 0 message",
				"added 1 function_call call_1",
				`arguments 1 {"x"`,
				"arguments 1 :1}",
				"added 2 function_call call_2",
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
			assert.Equal(t, tt.want, responsesEncoderEvents(t, lines))
		})
	}
}

func TestResponsesStreamEncoder_Finish(t *testing.T) {
	enc := NewResponsesStreamEncoder()
	lines := enc.Finish(&CanonicalStreamChunk{FinishReason: "tool_calls", Delta: "ignored", Usage: &CanonicalUsage{InputTokens: 1, OutputTokens: 2, TotalTokens: 3}})
	assert.Equal(t, []string{"response.function_call_arguments.done", "response.completed"}, responsesEncoderEvents(t, lines))
	assert.Empty(t, enc.Finish(&CanonicalStreamChunk{}))
}

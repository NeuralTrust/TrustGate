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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnthropicStreamEncoder_TextWaitsForIncompleteToolArguments(t *testing.T) {
	e := NewAnthropicStreamEncoder(FormatOpenAI)
	e.Content(&CanonicalStreamChunk{Role: "assistant", ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "f", ArgumentsDelta: `{"a":`}}})

	held := e.Content(&CanonicalStreamChunk{Delta: "between"})
	late := string(bytes.Join(e.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ArgumentsDelta: `1}`}}}), nil))
	end := string(bytes.Join(e.Finish(&CanonicalStreamChunk{FinishReason: "tool_calls"}), nil))

	assert.Empty(t, held)
	assert.Contains(t, late, `"index":0,"delta":{"type":"input_json_delta","partial_json":"1}"}`)
	assert.Contains(t, end, `"index":1,"delta":{"type":"text_delta","text":"between"}`)
	assert.Contains(t, end, `"stop_reason":"tool_use"`)
	deltas, tools := e.Dropped()
	assert.Zero(t, deltas)
	assert.Zero(t, tools)
}

func TestAnthropicStreamEncoder_TextAfterNoArgumentToolCallStreams(t *testing.T) {
	e := NewAnthropicStreamEncoder(FormatOpenAI)
	e.Content(&CanonicalStreamChunk{Role: "assistant", ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "now", ArgumentsDelta: ""}}})

	text := string(bytes.Join(e.Content(&CanonicalStreamChunk{Delta: "after"}), nil))
	end := string(bytes.Join(e.Finish(&CanonicalStreamChunk{FinishReason: "tool_calls"}), nil))

	assert.Contains(t, text, `"type":"content_block_stop","index":0`)
	assert.Contains(t, text, `"index":1,"delta":{"type":"text_delta","text":"after"}`)
	assert.Contains(t, end, `"stop_reason":"tool_use"`)
	assert.False(t, e.Aborted())
}

func TestAnthropicStreamEncoder_AbortsWhenToolArgumentsWereDropped(t *testing.T) {
	e := NewAnthropicStreamEncoder(FormatOpenAI)
	e.Content(&CanonicalStreamChunk{Role: "assistant", ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "f", ArgumentsDelta: `{"a":1}`}}})
	e.Content(&CanonicalStreamChunk{Delta: "text closes the complete tool block"})

	late := e.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ArgumentsDelta: ` `}}})
	end := string(bytes.Join(e.Finish(&CanonicalStreamChunk{FinishReason: "tool_calls"}), nil))

	assert.Empty(t, late)
	deltas, tools := e.Dropped()
	assert.Equal(t, 1, deltas)
	assert.Zero(t, tools)
	assert.Contains(t, end, `"type":"error"`)
	assert.Contains(t, end, anthropicTruncatedToolCallMessage)
	assert.NotContains(t, end, "message_stop")
	assert.True(t, e.Aborted())
}

func TestAnthropicStreamEncoder_FinishFailureAborts(t *testing.T) {
	tests := []struct {
		finish    string
		wantAbort bool
	}{
		{finish: "error", wantAbort: true},
		{finish: "MALFORMED_FUNCTION_CALL", wantAbort: true},
		{finish: "UNEXPECTED_TOOL_CALL", wantAbort: true},
		{finish: "TOO_MANY_TOOL_CALLS", wantAbort: true},
		{finish: "OTHER", wantAbort: false},
		{finish: "LANGUAGE", wantAbort: false},
		{finish: "stop", wantAbort: false},
	}
	for _, tt := range tests {
		t.Run(tt.finish, func(t *testing.T) {
			e := NewAnthropicStreamEncoder(FormatGemini)
			e.Content(&CanonicalStreamChunk{Role: "assistant", Delta: "hi"})

			end := string(bytes.Join(e.Finish(&CanonicalStreamChunk{FinishReason: tt.finish}), nil))

			assert.Contains(t, end, `"type":"content_block_stop","index":0`)
			assert.Equal(t, tt.wantAbort, e.Aborted())
			if tt.wantAbort {
				message, failed := FinishFailure(tt.finish)
				require.True(t, failed)
				assert.Contains(t, end, `"type":"error","error":{"type":"api_error","message":"`+message+`"}`)
				assert.NotContains(t, end, "message_stop")
				return
			}
			assert.Contains(t, end, `"stop_reason":"end_turn"`)
			assert.Contains(t, end, "message_stop")
			assert.NotContains(t, end, `"type":"error"`)
		})
	}
}

func TestAnthropicStreamEncoder_ToolCallStreaming(t *testing.T) {
	tool := func(index int, id, name, args string) *CanonicalStreamChunk {
		return &CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: index, ID: id, Name: name, ArgumentsDelta: args}}}
	}
	tests := []struct {
		name       string
		chunks     []*CanonicalStreamChunk
		wantStream []bool
	}{
		{
			name: "sequential calls both stream",
			chunks: []*CanonicalStreamChunk{
				tool(0, "call_1", "f", `{"a":`),
				tool(0, "", "", `1}`),
				tool(1, "call_2", "g", `{"b":`),
				tool(1, "", "", `2}`),
			},
			wantStream: []bool{true, true, false, true},
		},
		{
			name: "interleaved calls buffer the later one",
			chunks: []*CanonicalStreamChunk{
				tool(0, "call_1", "f", `{"a":`),
				tool(1, "call_2", "g", `{"b":`),
				tool(0, "", "", `1}`),
				tool(1, "", "", `2}`),
			},
			wantStream: []bool{true, false, true, false},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewAnthropicStreamEncoder(FormatOpenAI)
			e.Content(&CanonicalStreamChunk{Role: "assistant"})
			for i, chunk := range tt.chunks {
				lines := e.Content(chunk)
				assert.Equal(t, tt.wantStream[i], len(lines) > 0, "chunk %d", i)
			}

			end := string(bytes.Join(e.Finish(&CanonicalStreamChunk{FinishReason: "tool_calls"}), nil))

			assert.Equal(t, !tt.wantStream[len(tt.wantStream)-1], strings.Contains(end, `"index":1,"content_block":{"type":"tool_use","id":"call_2"`))
			assert.Contains(t, end, `"stop_reason":"tool_use"`)
		})
	}
}

func TestAnthropicStreamEncoder_EndTurnWhenEveryToolCallDropped(t *testing.T) {
	e := NewAnthropicStreamEncoder(FormatOpenAI)
	e.Content(&CanonicalStreamChunk{Role: "assistant", ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ArgumentsDelta: `{"a":1}`}}})

	end := string(bytes.Join(e.Finish(&CanonicalStreamChunk{FinishReason: "tool_calls"}), nil))

	assert.Contains(t, end, `"stop_reason":"end_turn"`)
	assert.NotContains(t, end, `"tool_use"`)
	deltas, tools := e.Dropped()
	assert.Zero(t, deltas)
	assert.Equal(t, 1, tools)
}

func TestAnthropicStreamEncoder_EndsOnce(t *testing.T) {
	e := NewAnthropicStreamEncoder(FormatOpenAI)
	e.Content(&CanonicalStreamChunk{Role: "assistant", Delta: "hi"})

	aborted := e.Abort("upstream stream failed")

	assert.True(t, bytes.Contains(bytes.Join(aborted, nil), []byte(`"type":"content_block_stop","index":0`)))
	assert.Empty(t, e.Finish(&CanonicalStreamChunk{FinishReason: "stop"}))
	assert.Empty(t, e.Abort("again"))
	assert.Empty(t, e.Content(&CanonicalStreamChunk{Delta: "more"}))
}

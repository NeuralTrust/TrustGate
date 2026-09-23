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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnthropicStreamEvents_WireShape(t *testing.T) {
	tests := []struct {
		name      string
		lines     [][]byte
		wantEvent string
		wantData  string
	}{
		{
			name:      "text block start",
			lines:     anthropicTextBlockStartEvent(0),
			wantEvent: "content_block_start",
			wantData:  `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
		},
		{
			name:      "tool_use block start",
			lines:     anthropicToolUseBlockStartEvent(2, "call_1", "get_weather"),
			wantEvent: "content_block_start",
			wantData:  `{"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"call_1","name":"get_weather","input":{}}}`,
		},
		{
			name:      "text delta",
			lines:     anthropicContentBlockDeltaEvent(1, anthropicBlockText, "hi"),
			wantEvent: "content_block_delta",
			wantData:  `{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"hi"}}`,
		},
		{
			name:      "input json delta",
			lines:     anthropicContentBlockDeltaEvent(2, anthropicBlockToolUse, `{"a":1}`),
			wantEvent: "content_block_delta",
			wantData:  `{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"a\":1}"}}`,
		},
		{
			name:      "block stop",
			lines:     anthropicContentBlockStopEvent(2),
			wantEvent: "content_block_stop",
			wantData:  `{"type":"content_block_stop","index":2}`,
		},
		{
			name:      "message start",
			lines:     anthropicMessageStartEvent("msg_1", "m", &CanonicalUsage{InputTokens: 10}),
			wantEvent: "message_start",
			wantData:  `{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"model":"m","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":10,"output_tokens":0}}}`,
		},
		{
			name:      "error",
			lines:     anthropicErrorEvent("upstream failed"),
			wantEvent: "error",
			wantData:  `{"type":"error","error":{"type":"api_error","message":"upstream failed"}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Len(t, tt.lines, 3)
			assert.Equal(t, "event: "+tt.wantEvent, string(tt.lines[0]))
			data, ok := strings.CutPrefix(string(tt.lines[1]), "data: ")
			require.True(t, ok)
			assert.JSONEq(t, tt.wantData, data)
			assert.Empty(t, tt.lines[2])
		})
	}
}

func TestAnthropicStopReason_SharedByEveryEncoder(t *testing.T) {
	tests := []struct {
		finish string
		want   string
	}{
		{finish: "stop", want: "end_turn"},
		{finish: "length", want: "max_tokens"},
		{finish: "tool_calls", want: "tool_use"},
		{finish: "stop_sequence", want: "stop_sequence"},
		{finish: "content_filter", want: "refusal"},
		{finish: "SAFETY", want: "refusal"},
		{finish: "RECITATION", want: "refusal"},
		{finish: "IMAGE_SAFETY", want: "refusal"},
		{finish: "model_context_window_exceeded", want: "model_context_window_exceeded"},
		{finish: "", want: "end_turn"},
		{finish: "error", want: "end_turn"},
		{finish: "MALFORMED_FUNCTION_CALL", want: "end_turn"},
		{finish: "UNEXPECTED_TOOL_CALL", want: "end_turn"},
		{finish: "TOO_MANY_TOOL_CALLS", want: "end_turn"},
		{finish: "OTHER", want: "end_turn"},
		{finish: "LANGUAGE", want: "end_turn"},
	}
	for _, tt := range tests {
		t.Run(tt.finish, func(t *testing.T) {
			lines := anthropicMessageEndEvents(tt.finish, &CanonicalUsage{OutputTokens: 5})
			require.Len(t, lines, 6)
			assert.Equal(t, "event: message_delta", string(lines[0]))
			assert.JSONEq(t, `{"type":"message_delta","delta":{"stop_reason":"`+tt.want+`","stop_sequence":null},"usage":{"input_tokens":0,"output_tokens":5}}`, strings.TrimPrefix(string(lines[1]), "data: "))
			assert.Equal(t, "event: message_stop", string(lines[3]))
			assert.JSONEq(t, `{"type":"message_stop"}`, strings.TrimPrefix(string(lines[4]), "data: "))

			a := &AnthropicAdapter{}
			body, err := a.EncodeResponse(&CanonicalResponse{Content: "ok", FinishReason: tt.finish})
			require.NoError(t, err)
			var resp struct {
				StopReason string `json:"stop_reason"`
			}
			require.NoError(t, json.Unmarshal(body, &resp))
			assert.Equal(t, tt.want, resp.StopReason, "EncodeResponse")

			if tt.finish == "" {
				return
			}
			chunkLines, err := a.EncodeStreamChunk(&CanonicalStreamChunk{FinishReason: tt.finish})
			require.NoError(t, err)
			assert.Contains(t, string(bytes.Join(chunkLines, nil)), `"stop_reason":"`+tt.want+`"`, "EncodeStreamChunk")
		})
	}
}

func TestAnthropicStopReasonUnmapped(t *testing.T) {
	tests := []struct {
		finish string
		want   bool
	}{
		{finish: "", want: false},
		{finish: "stop", want: false},
		{finish: "end_turn", want: false},
		{finish: "length", want: false},
		{finish: "tool_calls", want: false},
		{finish: "SAFETY", want: false},
		{finish: "OTHER", want: true},
		{finish: "LANGUAGE", want: true},
		{finish: "error", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.finish, func(t *testing.T) {
			assert.Equal(t, tt.want, AnthropicStopReasonUnmapped(tt.finish))
		})
	}
}

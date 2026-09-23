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

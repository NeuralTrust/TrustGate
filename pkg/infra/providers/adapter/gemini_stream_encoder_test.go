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

func geminiEncodedCalls(t *testing.T, lines [][]byte) []geminiFunctionCall {
	t.Helper()
	var calls []geminiFunctionCall
	for _, line := range lines {
		payload, ok := strings.CutPrefix(string(line), "data: ")
		if !ok {
			continue
		}
		var resp geminiResponse
		require.NoError(t, json.Unmarshal([]byte(payload), &resp))
		for _, p := range resp.Candidates[0].Content.Parts {
			if p.FunctionCall != nil {
				calls = append(calls, *p.FunctionCall)
			}
		}
	}
	return calls
}

func TestGeminiStreamEncoder_HoldsCallsUntilTheyClose(t *testing.T) {
	e := NewGeminiStreamEncoder()

	assert.Empty(t, e.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "a", Name: "search"}}}))
	assert.Empty(t, e.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ArgumentsDelta: `{"q":`}}}))
	assert.Empty(t, e.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ArgumentsDelta: `"x"}`}}}))
	assert.Empty(t, e.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "b", Name: "search", ArgumentsDelta: `{"q":"y"}`}}}), "a new id at the same index is a new call")
	assert.Empty(t, e.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 1, ArgumentsDelta: `{"q":"z"}`}}}))
	assert.True(t, e.HeldCallsComplete())

	calls := geminiEncodedCalls(t, e.Content(&CanonicalStreamChunk{Delta: "done"}))

	require.Len(t, calls, 2)
	assert.Equal(t, map[string]any{"q": "x"}, calls[0].Args)
	assert.Equal(t, map[string]any{"q": "y"}, calls[1].Args)
	assert.Equal(t, 1, e.Dropped(), "a call without a name is dropped")
	assert.Zero(t, e.Withheld())
}

func TestGeminiStreamEncoder_WithholdsArgumentsThatAreNotAnObject(t *testing.T) {
	for _, args := range []string{`{"q":`, `null`, `[1]`, `"x"`} {
		t.Run(args, func(t *testing.T) {
			e := NewGeminiStreamEncoder()
			e.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "a", Name: "search", ArgumentsDelta: args}}})
			e.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 1, ID: "b", Name: "noargs"}}})
			assert.False(t, e.HeldCallsComplete())

			lines := e.Finish(&CanonicalStreamChunk{FinishReason: "tool_calls"})

			calls := geminiEncodedCalls(t, lines)
			require.Len(t, calls, 1)
			assert.Equal(t, "noargs", calls[0].Name)
			assert.Equal(t, 1, e.Withheld())
			assert.Contains(t, string(lines[len(lines)-2]), `"finishReason":"STOP"`)
		})
	}
}

func TestGeminiStreamEncoder_WithholdsCallsOnAnUnfinishedStream(t *testing.T) {
	for _, reason := range []string{"length", "model_context_window_exceeded", "content_filter", "error"} {
		t.Run(reason, func(t *testing.T) {
			e := NewGeminiStreamEncoder()
			e.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "a", Name: "search", ArgumentsDelta: `{"q":"x"}`}}})

			assert.Empty(t, geminiEncodedCalls(t, e.Finish(&CanonicalStreamChunk{FinishReason: reason})))
			assert.Equal(t, 1, e.Withheld())
		})
	}
}

func TestGeminiStreamEncoder_HeldCallsCompleteTakesNoArgumentBytesAsNoArguments(t *testing.T) {
	e := NewGeminiStreamEncoder()
	e.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "a", Name: "list_files"}}})

	require.True(t, e.HeldCallsComplete(), "a call with no argument bytes is complete, as for a Responses client")
	calls := geminiEncodedCalls(t, e.Finish(&CanonicalStreamChunk{FinishReason: "stop"}))

	require.Len(t, calls, 1)
	assert.Equal(t, "list_files", calls[0].Name)
	assert.Empty(t, calls[0].Args)
	assert.Zero(t, e.Withheld())
}

func TestGeminiStreamEncoder_Fail(t *testing.T) {
	e := NewGeminiStreamEncoder()
	e.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "a", Name: "search", ArgumentsDelta: `{"q":"x"}`}}})

	lines := e.Fail("upstream stream failed")

	require.Len(t, lines, 2)
	assert.JSONEq(t, `{"error":{"code":500,"message":"upstream stream failed","status":"INTERNAL"}}`, strings.TrimPrefix(string(lines[0]), "data: "))
	assert.True(t, e.Failed())
	assert.Equal(t, 1, e.Withheld())
	assert.Empty(t, e.Fail("again"), "the stream ends once")
	assert.Empty(t, e.Finish(&CanonicalStreamChunk{FinishReason: "stop"}))

	e = NewGeminiStreamEncoder()
	e.Finish(&CanonicalStreamChunk{FinishReason: "stop"})
	assert.Empty(t, e.Fail("late"), "a finished stream gets no error object")
	assert.False(t, e.Failed())
}

func TestGeminiStreamEncoder_SendsTheCallIDs(t *testing.T) {
	e := NewGeminiStreamEncoder()
	e.Content(&CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "search", ArgumentsDelta: `{"q":"x"}`}}})

	calls := geminiEncodedCalls(t, e.Finish(&CanonicalStreamChunk{FinishReason: "tool_calls"}))

	require.Len(t, calls, 1)
	assert.Equal(t, "call_1", calls[0].ID)
	assert.NoError(t, e.TakeEncodeError())
}

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

package proxy

import (
	"encoding/json"
	"iter"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func linesSeq(lines ...string) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		for _, l := range lines {
			if !yield([]byte(l), nil) {
				return
			}
		}
	}
}

func collectLines(t *testing.T, seq iter.Seq2[[]byte, error]) []string {
	t.Helper()
	var out []string
	for line, err := range seq {
		require.NoError(t, err)
		out = append(out, string(line))
	}
	return out
}

func dataChunks(t *testing.T, lines []string) []map[string]any {
	t.Helper()
	var chunks []map[string]any
	for _, l := range lines {
		payload, ok := dataPayload([]byte(l))
		if !ok {
			continue
		}
		var m map[string]any
		require.NoError(t, json.Unmarshal(payload, &m))
		chunks = append(chunks, m)
	}
	return chunks
}

func chunkToolCalls(chunk map[string]any) []any {
	choices, _ := chunk["choices"].([]any)
	if len(choices) == 0 {
		return nil
	}
	choice, _ := choices[0].(map[string]any)
	delta, _ := choice["delta"].(map[string]any)
	calls, _ := delta["tool_calls"].([]any)
	return calls
}

func TestCoalesceOpenAIToolCallStream_MergesFragmentedArguments(t *testing.T) {
	out := collectLines(t, coalesceOpenAIToolCallStream(linesSeq(
		`data: {"id":"c1","object":"chat.completion.chunk","model":"gpt-4o","choices":[{"index":0,"delta":{"role":"assistant","content":null,"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"database_agent","arguments":""}}]},"finish_reason":null}]}`,
		``,
		`data: {"id":"c1","object":"chat.completion.chunk","model":"gpt-4o","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"que"}}]},"finish_reason":null}]}`,
		``,
		`data: {"id":"c1","object":"chat.completion.chunk","model":"gpt-4o","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"ry\":\"Juan\"}"}}]},"finish_reason":null}]}`,
		``,
		`data: {"id":"c1","object":"chat.completion.chunk","model":"gpt-4o","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		``,
		`data: [DONE]`,
		``,
	)))

	chunks := dataChunks(t, out)
	require.Len(t, chunks, 3)

	assert.Equal(t, "assistant", chunks[0]["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)["role"])
	assert.Empty(t, chunkToolCalls(chunks[0]))

	calls := chunkToolCalls(chunks[1])
	require.Len(t, calls, 1)
	call := calls[0].(map[string]any)
	assert.Equal(t, "call_1", call["id"])
	assert.Equal(t, "function", call["type"])
	fn := call["function"].(map[string]any)
	assert.Equal(t, "database_agent", fn["name"])
	assert.JSONEq(t, `{"query":"Juan"}`, fn["arguments"].(string))
	assert.Equal(t, "c1", chunks[1]["id"])
	assert.Equal(t, "gpt-4o", chunks[1]["model"])

	finish := chunks[2]["choices"].([]any)[0].(map[string]any)
	assert.Equal(t, "tool_calls", finish["finish_reason"])

	assert.Contains(t, out, "data: [DONE]")
}

func TestCoalesceOpenAIToolCallStream_ContentOnlyPassthroughVerbatim(t *testing.T) {
	in := []string{
		`data: {"id":"c1","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}`,
		``,
		`data: {"id":"c1","choices":[{"index":0,"delta":{"content":"hola"},"finish_reason":null}]}`,
		``,
		`data: {"id":"c1","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
		``,
		`data: [DONE]`,
		``,
	}
	out := collectLines(t, coalesceOpenAIToolCallStream(linesSeq(in...)))
	assert.Equal(t, in, out)
}

func TestCoalesceOpenAIToolCallStream_FlushesOnDoneWithoutFinishChunk(t *testing.T) {
	out := collectLines(t, coalesceOpenAIToolCallStream(linesSeq(
		`data: {"id":"c1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"f","arguments":"{\"a\":1}"}}]},"finish_reason":null}]}`,
		``,
		`data: [DONE]`,
		``,
	)))

	chunks := dataChunks(t, out)
	require.Len(t, chunks, 1)
	calls := chunkToolCalls(chunks[0])
	require.Len(t, calls, 1)
	fn := calls[0].(map[string]any)["function"].(map[string]any)
	assert.JSONEq(t, `{"a":1}`, fn["arguments"].(string))

	doneIdx, flushIdx := -1, -1
	for i, l := range out {
		if isSSEDone([]byte(l)) {
			doneIdx = i
		}
		if _, ok := dataPayload([]byte(l)); ok {
			flushIdx = i
		}
	}
	require.GreaterOrEqual(t, flushIdx, 0)
	require.GreaterOrEqual(t, doneIdx, 0)
	assert.Less(t, flushIdx, doneIdx)
}

func TestCoalesceOpenAIToolCallStream_ParallelToolCallsSortedByIndex(t *testing.T) {
	out := collectLines(t, coalesceOpenAIToolCallStream(linesSeq(
		`data: {"id":"c1","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call_b","function":{"name":"g","arguments":""}}]},"finish_reason":null}]}`,
		``,
		`data: {"id":"c1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_a","function":{"name":"f","arguments":"{}"}}]},"finish_reason":null}]}`,
		``,
		`data: {"id":"c1","choices":[{"index":1,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"{\"x\":2}"}}]},"finish_reason":null}]}`,
		``,
		`data: {"id":"c1","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		``,
		`data: [DONE]`,
		``,
	)))

	chunks := dataChunks(t, out)
	require.Len(t, chunks, 2)
	calls := chunkToolCalls(chunks[0])
	require.Len(t, calls, 2)
	first := calls[0].(map[string]any)
	second := calls[1].(map[string]any)
	assert.Equal(t, "call_a", first["id"])
	assert.Equal(t, "call_b", second["id"])
	assert.JSONEq(t, `{"x":2}`, second["function"].(map[string]any)["arguments"].(string))
}

func TestCoalesceOpenAIToolCallStream_MultiChoiceUntouched(t *testing.T) {
	in := []string{
		`data: {"id":"c1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{"}}]},"finish_reason":null},{"index":1,"delta":{"content":"x"},"finish_reason":null}]}`,
		``,
		`data: [DONE]`,
		``,
	}
	out := collectLines(t, coalesceOpenAIToolCallStream(linesSeq(in...)))
	assert.Equal(t, in, out)
}

func TestCoalesceOpenAIToolCallStream_FlushesAtSequenceEndWithoutDone(t *testing.T) {
	out := collectLines(t, coalesceOpenAIToolCallStream(linesSeq(
		`data: {"id":"c1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"f","arguments":"{}"}}]},"finish_reason":null}]}`,
		``,
	)))

	chunks := dataChunks(t, out)
	require.Len(t, chunks, 1)
	require.Len(t, chunkToolCalls(chunks[0]), 1)
}

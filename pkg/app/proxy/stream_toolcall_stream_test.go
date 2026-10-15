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
	"log/slog"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdaptStream_ChatToolArgumentDeltasPassThrough(t *testing.T) {
	function := []string{
		`data: {"id":"c1","object":"chat.completion.chunk","model":"gpt-4.1-nano","choices":[{"index":0,"delta":{"role":"assistant","content":"Once "},"finish_reason":null}]}`,
		``,
		`data: {"id":"c1","object":"chat.completion.chunk","model":"gpt-4.1-nano","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"write","arguments":""}}]},"finish_reason":null}]}`,
		``,
		`data: {"id":"c1","object":"chat.completion.chunk","model":"gpt-4.1-nano","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"text\":"}}]},"finish_reason":null}]}`,
		``,
		`data: {"id":"c1","object":"chat.completion.chunk","model":"gpt-4.1-nano","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"a cat\"}"}}]},"finish_reason":null}]}`,
		``,
		`data: {"id":"c1","object":"chat.completion.chunk","model":"gpt-4.1-nano","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		``,
		`data: [DONE]`,
		``,
	}
	custom := []string{
		`data: {"id":"c1","object":"chat.completion.chunk","model":"gpt-5.1","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"custom","custom":{"name":"bash","input":""}}]},"finish_reason":null}]}`,
		``,
		`data: {"id":"c1","object":"chat.completion.chunk","model":"gpt-5.1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"custom":{"input":"ls -la "}}]},"finish_reason":null}]}`,
		``,
		`data: {"id":"c1","object":"chat.completion.chunk","model":"gpt-5.1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"custom":{"input":"/tmp"}}]},"finish_reason":null}]}`,
		``,
		`data: {"id":"c1","object":"chat.completion.chunk","model":"gpt-5.1","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		``,
		`data: [DONE]`,
		``,
	}
	for _, target := range []adapter.Format{adapter.FormatOpenAI, adapter.FormatAzure} {
		t.Run(string(target)+"/function", func(t *testing.T) {
			out := collectLines(t, adaptStream(linesSeq(function...), adapter.NewRegistry(), adapter.FormatOpenAI, target, slog.Default(), nil))
			assert.Equal(t, function, out)
			frags := argumentFragments(t, out, "function", "arguments")
			require.Len(t, frags, 2)
			assert.Equal(t, []string{`{"text":`, `"a cat"}`}, frags)
		})
		t.Run(string(target)+"/custom", func(t *testing.T) {
			out := collectLines(t, adaptStream(linesSeq(custom...), adapter.NewRegistry(), adapter.FormatOpenAI, target, slog.Default(), nil))
			assert.Equal(t, custom, out)
			assert.Equal(t, []string{"ls -la ", "/tmp"}, argumentFragments(t, out, "custom", "input"))
		})
	}
}

func TestAdaptStream_ReencodedChatToolArgumentsStreamIncrementally(t *testing.T) {
	upstream := []string{
		`data: {"messageStart":{"role":"assistant"}}`,
		`data: {"contentBlockStart":{"contentBlockIndex":0,"start":{"toolUse":{"toolUseId":"call_1","name":"write"}}}}`,
		`data: {"contentBlockDelta":{"contentBlockIndex":0,"delta":{"toolUse":{"input":"{\"text\":"}}}}`,
		`data: {"contentBlockDelta":{"contentBlockIndex":0,"delta":{"toolUse":{"input":"\"a cat\"}"}}}}`,
		`data: {"contentBlockStop":{"contentBlockIndex":0}}`,
		`data: {"messageStop":{"stopReason":"tool_use"}}`,
		`data: {"metadata":{"usage":{"inputTokens":10,"outputTokens":7,"totalTokens":17}}}`,
	}
	for _, source := range []adapter.Format{adapter.FormatOpenAI, adapter.FormatAzure} {
		t.Run(string(source), func(t *testing.T) {
			lines := collectLines(t, adaptStream(linesSeq(upstream...), adapter.NewRegistry(), source, adapter.FormatBedrock, slog.Default(), nil))
			var beforeFinish []string
			finished := false
			for _, chunk := range dataChunks(t, lines) {
				choices, _ := chunk["choices"].([]any)
				if len(choices) == 0 {
					continue
				}
				choice, _ := choices[0].(map[string]any)
				if reason, _ := choice["finish_reason"].(string); reason != "" {
					finished = true
				}
				if finished {
					continue
				}
				beforeFinish = append(beforeFinish, toolPayloads(chunk, "function", "arguments")...)
			}
			require.Equal(t, []string{`{"text":`, `"a cat"}`}, beforeFinish)
			assert.Equal(t, `{"text":"a cat"}`, strings.Join(beforeFinish, ""))
		})
	}
}

func argumentFragments(t *testing.T, lines []string, objectKey, field string) []string {
	t.Helper()
	var out []string
	for _, chunk := range dataChunks(t, lines) {
		out = append(out, toolPayloads(chunk, objectKey, field)...)
	}
	return out
}

func toolPayloads(chunk map[string]any, objectKey, field string) []string {
	var out []string
	for _, raw := range chunkToolCalls(chunk) {
		call, _ := raw.(map[string]any)
		object, _ := call[objectKey].(map[string]any)
		if payload, ok := object[field].(string); ok && payload != "" {
			out = append(out, payload)
		}
	}
	return out
}

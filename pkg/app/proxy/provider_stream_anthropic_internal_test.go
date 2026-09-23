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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type anthropicWireEvent struct {
	Type    string `json:"type"`
	Index   *int   `json:"index"`
	Message *struct {
		ID string `json:"id"`
	} `json:"message"`
	ContentBlock *struct {
		Type  string          `json:"type"`
		Text  *string         `json:"text"`
		ID    string          `json:"id"`
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	} `json:"content_block"`
	Delta *struct {
		Type        string `json:"type"`
		Text        string `json:"text"`
		PartialJSON string `json:"partial_json"`
		StopReason  string `json:"stop_reason"`
	} `json:"delta"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

func anthropicWireEvents(t *testing.T, lines []string) []anthropicWireEvent {
	t.Helper()
	var events []anthropicWireEvent
	var name string
	for _, line := range lines {
		if n, ok := strings.CutPrefix(line, "event: "); ok {
			name = n
			continue
		}
		payload, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		var ev anthropicWireEvent
		require.NoError(t, json.Unmarshal([]byte(payload), &ev))
		require.Equal(t, name, ev.Type, "event: line names the data type")
		name = ""
		events = append(events, ev)
	}
	return events
}

var anthropicDeltaForBlock = map[string]string{
	"text":     "text_delta",
	"tool_use": "input_json_delta",
}

var generatedToolID = regexp.MustCompile(`^toolu_[A-Z2-7]{26}_(\d+)$`)

func requireAnthropicContract(t *testing.T, events []anthropicWireEvent) {
	t.Helper()
	require.GreaterOrEqual(t, len(events), 3)
	require.Equal(t, "message_start", events[0].Type)
	require.Equal(t, "message_delta", events[len(events)-2].Type)
	require.Equal(t, "message_stop", events[len(events)-1].Type)
	requireAnthropicBlocks(t, events[1:len(events)-2])
}

func requireAnthropicAborted(t *testing.T, events []anthropicWireEvent) {
	t.Helper()
	require.GreaterOrEqual(t, len(events), 2)
	require.Equal(t, "message_start", events[0].Type)
	require.Equal(t, "error", events[len(events)-1].Type)
	requireAnthropicBlocks(t, events[1:len(events)-1])
}

func requireAnthropicBlocks(t *testing.T, events []anthropicWireEvent) {
	t.Helper()
	open, next := -1, 0
	var openType string
	toolIDs := map[string]bool{}
	for i, ev := range events {
		switch ev.Type {
		case "content_block_start":
			require.Equal(t, -1, open, "event %d: block %d still open", i, open)
			require.NotNil(t, ev.Index)
			require.Equal(t, next, *ev.Index, "event %d: blocks are indexed in order", i)
			require.NotNil(t, ev.ContentBlock)
			switch ev.ContentBlock.Type {
			case "text":
				require.NotNil(t, ev.ContentBlock.Text)
				assert.Empty(t, *ev.ContentBlock.Text)
			case "tool_use":
				assert.NotEmpty(t, ev.ContentBlock.ID)
				assert.NotEmpty(t, ev.ContentBlock.Name)
				assert.False(t, toolIDs[ev.ContentBlock.ID], "event %d: tool id %s repeats", i, ev.ContentBlock.ID)
				toolIDs[ev.ContentBlock.ID] = true
				assert.JSONEq(t, `{}`, string(ev.ContentBlock.Input))
			default:
				require.Failf(t, "unknown block type", "event %d: %s", i, ev.ContentBlock.Type)
			}
			open, openType, next = *ev.Index, ev.ContentBlock.Type, next+1
		case "content_block_delta":
			require.NotNil(t, ev.Index)
			require.Equal(t, open, *ev.Index, "event %d: delta for the open block", i)
			require.NotNil(t, ev.Delta)
			require.Equal(t, anthropicDeltaForBlock[openType], ev.Delta.Type, "event %d", i)
		case "content_block_stop":
			require.NotNil(t, ev.Index)
			require.Equal(t, open, *ev.Index, "event %d: stop closes the open block", i)
			open = -1
		default:
			require.Failf(t, "unexpected event inside the message", "event %d: %s", i, ev.Type)
		}
	}
	require.Equal(t, -1, open, "every block is closed before the message ends")
}

func anthropicGolden(events []anthropicWireEvent) []string {
	out := make([]string, 0, len(events))
	for _, ev := range events {
		switch ev.Type {
		case "content_block_start":
			cb := ev.ContentBlock
			if cb.Type == "tool_use" {
				id := generatedToolID.ReplaceAllString(cb.ID, "toolu_*_$1")
				out = append(out, fmt.Sprintf("start %d tool_use %s %s", *ev.Index, id, cb.Name))
				continue
			}
			out = append(out, fmt.Sprintf("start %d %s", *ev.Index, cb.Type))
		case "content_block_delta":
			d := ev.Delta
			out = append(out, fmt.Sprintf("delta %d %s %s", *ev.Index, d.Type, d.Text+d.PartialJSON))
		case "content_block_stop":
			out = append(out, fmt.Sprintf("stop %d", *ev.Index))
		case "message_delta":
			out = append(out, "message_delta "+ev.Delta.StopReason)
		case "error":
			out = append(out, "error "+ev.Error.Type)
		default:
			out = append(out, ev.Type)
		}
	}
	return out
}

func openAITextThenToolUpstream() iter.Seq2[[]byte, error] {
	return linesSeq(
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"Let me check"}}]}`,
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""}}]}}]}`,
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"city\":\"Paris\"}"}}]}}]}`,
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":20,"completion_tokens":5,"total_tokens":25}}`,
		`data: [DONE]`,
	)
}

func openAIParallelToolsUpstream() iter.Seq2[[]byte, error] {
	return linesSeq(
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""}}]}}]}`,
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"city\":\"Paris\"}"}}]}}]}`,
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call_2","type":"function","function":{"name":"get_time","arguments":""}}]}}]}`,
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"{\"tz\":\"CET\"}"}}]}}]}`,
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: [DONE]`,
	)
}

func TestAdaptStream_AnthropicClientEventSequence(t *testing.T) {
	tests := []struct {
		name     string
		target   adapter.Format
		upstream iter.Seq2[[]byte, error]
		want     []string
	}{
		{
			name:     "openai text then tool at upstream index 0",
			target:   adapter.FormatOpenAI,
			upstream: openAITextThenToolUpstream(),
			want: []string{
				"message_start",
				"start 0 text", "delta 0 text_delta Let me check", "stop 0",
				"start 1 tool_use call_1 get_weather", `delta 1 input_json_delta {"city":"Paris"}`, "stop 1",
				"message_delta tool_use", "message_stop",
			},
		},
		{
			name:     "openai two parallel tool calls",
			target:   adapter.FormatOpenAI,
			upstream: openAIParallelToolsUpstream(),
			want: []string{
				"message_start",
				"start 0 tool_use call_1 get_weather", `delta 0 input_json_delta {"city":"Paris"}`, "stop 0",
				"start 1 tool_use call_2 get_time", `delta 1 input_json_delta {"tz":"CET"}`, "stop 1",
				"message_delta tool_use", "message_stop",
			},
		},
		{
			name:   "bedrock reasoning is not emitted",
			target: adapter.FormatBedrock,
			upstream: linesSeq(
				`data: {"messageStart":{"role":"assistant"}}`,
				`data: {"contentBlockDelta":{"contentBlockIndex":0,"delta":{"reasoningContent":{"text":"Pondering"}}}}`,
				`data: {"contentBlockDelta":{"contentBlockIndex":0,"delta":{"reasoningContent":{"signature":"sig"}}}}`,
				`data: {"contentBlockStop":{"contentBlockIndex":0}}`,
				`data: {"contentBlockDelta":{"contentBlockIndex":1,"delta":{"text":"hi"}}}`,
				`data: {"contentBlockStop":{"contentBlockIndex":1}}`,
				`data: {"messageStop":{"stopReason":"end_turn"}}`,
				`data: {"metadata":{"usage":{"inputTokens":10,"outputTokens":7,"totalTokens":17}}}`,
			),
			want: []string{
				"message_start",
				"start 0 text", "delta 0 text_delta hi", "stop 0",
				"message_delta end_turn", "message_stop",
			},
		},
		{
			name:   "bedrock text then tool",
			target: adapter.FormatBedrock,
			upstream: linesSeq(
				`data: {"messageStart":{"role":"assistant"}}`,
				`data: {"contentBlockDelta":{"contentBlockIndex":0,"delta":{"text":"Checking"}}}`,
				`data: {"contentBlockStop":{"contentBlockIndex":0}}`,
				`data: {"contentBlockStart":{"contentBlockIndex":1,"start":{"toolUse":{"toolUseId":"tooluse_1","name":"get_weather"}}}}`,
				`data: {"contentBlockDelta":{"contentBlockIndex":1,"delta":{"toolUse":{"input":"{\"city\":\"Paris\"}"}}}}`,
				`data: {"contentBlockStop":{"contentBlockIndex":1}}`,
				`data: {"messageStop":{"stopReason":"tool_use"}}`,
				`data: {"metadata":{"usage":{"inputTokens":10,"outputTokens":7,"totalTokens":17}}}`,
			),
			want: []string{
				"message_start",
				"start 0 text", "delta 0 text_delta Checking", "stop 0",
				"start 1 tool_use tooluse_1 get_weather", `delta 1 input_json_delta {"city":"Paris"}`, "stop 1",
				"message_delta tool_use", "message_stop",
			},
		},
		{
			name:   "gemini STOP with a functionCall",
			target: adapter.FormatGemini,
			upstream: linesSeq(
				`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"Checking"}]}}],"usageMetadata":{"promptTokenCount":10,"totalTokenCount":10}}`,
				`data: {"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"get_weather","args":{"city":"Paris"}}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"totalTokenCount":15}}`,
			),
			want: []string{
				"message_start",
				"start 0 text", "delta 0 text_delta Checking", "stop 0",
				"start 1 tool_use get_weather get_weather", `delta 1 input_json_delta {"city":"Paris"}`, "stop 1",
				"message_delta tool_use", "message_stop",
			},
		},
		{
			name:     "gemini 3 signed functionCall",
			target:   adapter.FormatGemini,
			upstream: gemini3SignedFunctionCallUpstream(),
			want: []string{
				"message_start",
				"start 0 tool_use call_235554 get_weather", `delta 0 input_json_delta {"city":"Paris"}`, "stop 0",
				"message_delta tool_use", "message_stop",
			},
		},
		{
			name:     "gemini 3 parallel calls in separate chunks",
			target:   adapter.FormatGemini,
			upstream: gemini3ParallelFunctionCallsUpstream(),
			want: []string{
				"message_start",
				"start 0 tool_use call_172274 get_weather", `delta 0 input_json_delta {"city":"Paris"}`, "stop 0",
				"start 1 tool_use call_172284 get_weather", `delta 1 input_json_delta {"city":"Rome"}`, "stop 1",
				"start 2 tool_use call_172286 get_weather", `delta 2 input_json_delta {"city":"Berlin"}`, "stop 2",
				"message_delta tool_use", "message_stop",
			},
		},
		{
			name:     "gemini 2.5 thought then signed functionCall",
			target:   adapter.FormatGemini,
			upstream: gemini25ThoughtThenSignedFunctionCallUpstream(),
			want: []string{
				"message_start",
				"start 0 tool_use get_weather get_weather", `delta 0 input_json_delta {"city":"Paris"}`, "stop 0",
				"message_delta tool_use", "message_stop",
			},
		},
		{
			name:   "gemini function calls reusing part index 0",
			target: adapter.FormatGemini,
			upstream: linesSeq(
				`data: {"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"get_weather","args":{"city":"Paris"}}}]}}]}`,
				`data: {"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"get_weather","args":{"city":"Rome"}}}]},"finishReason":"STOP"}]}`,
			),
			want: []string{
				"message_start",
				"start 0 tool_use get_weather get_weather", `delta 0 input_json_delta {"city":"Paris"}`, "stop 0",
				"start 1 tool_use toolu_*_1 get_weather", `delta 1 input_json_delta {"city":"Rome"}`, "stop 1",
				"message_delta tool_use", "message_stop",
			},
		},
		{
			name:   "responses text then function call",
			target: adapter.FormatOpenAIResponses,
			upstream: linesSeq(
				`data: {"type":"response.created","response":{"id":"resp_1","model":"gpt"}}`,
				`data: {"type":"response.output_item.added","output_index":0,"item":{"type":"message","role":"assistant","id":"msg_1"}}`,
				`data: {"type":"response.output_text.delta","output_index":0,"delta":"Checking"}`,
				`data: {"type":"response.output_item.added","output_index":1,"item":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"get_weather"}}`,
				`data: {"type":"response.function_call_arguments.delta","output_index":1,"delta":"{\"city\":\"Paris\"}"}`,
				`data: {"type":"response.function_call_arguments.done","output_index":1}`,
				`data: {"type":"response.completed","response":{"id":"resp_1","model":"gpt","usage":{"input_tokens":10,"output_tokens":5,"total_tokens":15}}}`,
			),
			want: []string{
				"message_start",
				"start 0 text", "delta 0 text_delta Checking", "stop 0",
				"start 1 tool_use call_1 get_weather", `delta 1 input_json_delta {"city":"Paris"}`, "stop 1",
				"message_delta tool_use", "message_stop",
			},
		},
		{
			name:   "responses function call without a message item",
			target: adapter.FormatOpenAIResponses,
			upstream: linesSeq(
				`data: {"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"get_weather"}}`,
				`data: {"type":"response.function_call_arguments.delta","output_index":0,"delta":"{\"city\":\"Paris\"}"}`,
				`data: {"type":"response.function_call_arguments.done","output_index":0}`,
				`data: {"type":"response.completed","response":{"id":"resp_1","model":"gpt","usage":{"input_tokens":10,"output_tokens":5,"total_tokens":15}}}`,
			),
			want: []string{
				"message_start",
				"start 0 tool_use call_1 get_weather", `delta 0 input_json_delta {"city":"Paris"}`, "stop 0",
				"message_delta tool_use", "message_stop",
			},
		},
		{
			name:   "openai tool deltas alternating between indices 0 and 1",
			target: adapter.FormatOpenAI,
			upstream: linesSeq(
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":"}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call_2","type":"function","function":{"name":"get_time","arguments":"{\"tz\":"}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"Paris\"}"}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"\"CET\"}"}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
				`data: [DONE]`,
			),
			want: []string{
				"message_start",
				"start 0 tool_use call_1 get_weather", `delta 0 input_json_delta {"city":`, `delta 0 input_json_delta "Paris"}`, "stop 0",
				"start 1 tool_use call_2 get_time", `delta 1 input_json_delta {"tz":"CET"}`, "stop 1",
				"message_delta tool_use", "message_stop",
			},
		},
		{
			name:   "openai max_tokens with an open tool block",
			target: adapter.FormatOpenAI,
			upstream: linesSeq(
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"ci"}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"length"}]}`,
				`data: [DONE]`,
			),
			want: []string{
				"message_start",
				"start 0 tool_use call_1 get_weather", `delta 0 input_json_delta {"ci`, "stop 0",
				"message_delta max_tokens", "message_stop",
			},
		},
		{
			name:   "openai tool arguments before the name and without an id",
			target: adapter.FormatOpenAI,
			upstream: linesSeq(
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"type":"function","function":{"arguments":"{\"city\":"}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"get_weather","arguments":"\"Paris\"}"}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
				`data: [DONE]`,
			),
			want: []string{
				"message_start",
				"start 0 tool_use toolu_*_0 get_weather", `delta 0 input_json_delta {"city":"Paris"}`, "stop 0",
				"message_delta tool_use", "message_stop",
			},
		},
		{
			name:   "openai [DONE] without a finish",
			target: adapter.FormatOpenAI,
			upstream: linesSeq(
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":20,"completion_tokens":5,"total_tokens":25}}`,
				`data: [DONE]`,
			),
			want: []string{
				"message_start",
				"start 0 text", "delta 0 text_delta hi", "stop 0",
				"message_delta end_turn", "message_stop",
			},
		},
		{
			name:   "openai nameless tool call dropped",
			target: adapter.FormatOpenAI,
			upstream: linesSeq(
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hi","tool_calls":[{"index":0,"type":"function","function":{"arguments":"{}"}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
				`data: [DONE]`,
			),
			want: []string{
				"message_start",
				"start 0 text", "delta 0 text_delta hi", "stop 0",
				"message_delta end_turn", "message_stop",
			},
		},
		{
			name:   "openai tool deltas ordered 0, 1, 1, 0",
			target: adapter.FormatOpenAI,
			upstream: linesSeq(
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":"}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call_2","type":"function","function":{"name":"get_time","arguments":"{\"tz\":"}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"\"CET\"}"}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"Paris\"}"}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
				`data: [DONE]`,
			),
			want: []string{
				"message_start",
				"start 0 tool_use call_1 get_weather", `delta 0 input_json_delta {"city":`, `delta 0 input_json_delta "Paris"}`, "stop 0",
				"start 1 tool_use call_2 get_time", `delta 1 input_json_delta {"tz":"CET"}`, "stop 1",
				"message_delta tool_use", "message_stop",
			},
		},
		{
			name:   "openai text between two argument deltas of the open tool",
			target: adapter.FormatOpenAI,
			upstream: linesSeq(
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":"}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"hmm"}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"Paris\"}"}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
				`data: [DONE]`,
			),
			want: []string{
				"message_start",
				"start 0 tool_use call_1 get_weather", `delta 0 input_json_delta {"city":`, `delta 0 input_json_delta "Paris"}`, "stop 0",
				"start 1 text", "delta 1 text_delta hmm", "stop 1",
				"message_delta tool_use", "message_stop",
			},
		},
		{
			name:   "openai whole tool calls in one chunk each",
			target: adapter.FormatOpenAI,
			upstream: linesSeq(
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Paris\"}"}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call_2","type":"function","function":{"name":"get_time","arguments":"{\"tz\":\"CET\"}"}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":2,"id":"call_3","type":"function","function":{"name":"get_date","arguments":"{}"}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
				`data: [DONE]`,
			),
			want: []string{
				"message_start",
				"start 0 tool_use call_1 get_weather", `delta 0 input_json_delta {"city":"Paris"}`, "stop 0",
				"start 1 tool_use call_2 get_time", `delta 1 input_json_delta {"tz":"CET"}`, "stop 1",
				"start 2 tool_use call_3 get_date", `delta 2 input_json_delta {}`, "stop 2",
				"message_delta tool_use", "message_stop",
			},
		},
		{
			name:   "openai text while a call waits for its second delta",
			target: adapter.FormatOpenAI,
			upstream: linesSeq(
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Paris\"}"}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call_2","type":"function","function":{"name":"get_time","arguments":"{\"tz\":"}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"note"}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"\"CET\"}"}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
				`data: [DONE]`,
			),
			want: []string{
				"message_start",
				"start 0 tool_use call_1 get_weather", `delta 0 input_json_delta {"city":"Paris"}`, "stop 0",
				"start 1 text", "delta 1 text_delta note", "stop 1",
				"start 2 tool_use call_2 get_time", `delta 2 input_json_delta {"tz":"CET"}`, "stop 2",
				"message_delta tool_use", "message_stop",
			},
		},
		{
			name:   "gemini OTHER ends the turn",
			target: adapter.FormatGemini,
			upstream: linesSeq(
				`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]},"finishReason":"OTHER"}]}`,
			),
			want: []string{
				"message_start",
				"start 0 text", "delta 0 text_delta hi", "stop 0",
				"message_delta end_turn", "message_stop",
			},
		},
		{
			name:   "gemini LANGUAGE ends the turn",
			target: adapter.FormatGemini,
			upstream: linesSeq(
				`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]},"finishReason":"LANGUAGE"}]}`,
			),
			want: []string{
				"message_start",
				"start 0 text", "delta 0 text_delta hi", "stop 0",
				"message_delta end_turn", "message_stop",
			},
		},
		{
			name:     "openai text only",
			target:   adapter.FormatOpenAI,
			upstream: openAIUpstreamWithIncludeUsage(),
			want: []string{
				"message_start",
				"start 0 text", "delta 0 text_delta hi", "stop 0",
				"message_delta end_turn", "message_stop",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := collectLines(t, adaptStream(tt.upstream, adapter.NewRegistry(), adapter.FormatAnthropic, tt.target, slog.Default(), nil))

			events := anthropicWireEvents(t, lines)
			requireAnthropicContract(t, events)
			assert.Equal(t, tt.want, anthropicGolden(events))
		})
	}
}

func TestAdaptStream_AnthropicClientGetsOneMessageStart(t *testing.T) {
	upstream := linesSeq(
		`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"a"}]}}],"modelVersion":"gemini-2.5","responseId":"r1","usageMetadata":{"promptTokenCount":10,"totalTokenCount":10}}`,
		`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"b"}]}}],"usageMetadata":{"promptTokenCount":10,"totalTokenCount":10}}`,
		`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"c"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":3,"totalTokenCount":13}}`,
	)
	lines := collectLines(t, adaptStream(upstream, adapter.NewRegistry(), adapter.FormatAnthropic, adapter.FormatGemini, slog.Default(), nil))

	events := anthropicWireEvents(t, lines)
	requireAnthropicContract(t, events)
	assert.Equal(t, []string{
		"message_start",
		"start 0 text", "delta 0 text_delta a", "delta 0 text_delta b", "delta 0 text_delta c", "stop 0",
		"message_delta end_turn", "message_stop",
	}, anthropicGolden(events))

	var start struct {
		Message struct {
			Usage json.RawMessage `json:"usage"`
		} `json:"message"`
	}
	payload, ok := strings.CutPrefix(lines[1], "data: ")
	require.True(t, ok)
	require.NoError(t, json.Unmarshal([]byte(payload), &start))
	assert.JSONEq(t, `{"input_tokens":10,"output_tokens":0}`, string(start.Message.Usage))
}

func TestAdaptStream_AnthropicClientGetsErrorWhenUpstreamStopsEarly(t *testing.T) {
	upstreamErr := errors.New("upstream reset")
	toolThenArgs := []string{
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""}}]}}]}`,
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"ci"}}]}}]}`,
	}
	finished := append(slices.Clone(toolThenArgs),
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
	)
	aborted := []string{
		"message_start",
		"start 0 tool_use call_1 get_weather", `delta 0 input_json_delta {"ci`, "stop 0",
		"error api_error",
	}
	tests := []struct {
		name     string
		upstream []string
		failErr  error
		wantErr  error
		want     []string
	}{
		{name: "error mid-stream with an open tool block", upstream: toolThenArgs, failErr: upstreamErr, wantErr: upstreamErr, want: aborted},
		{name: "upstream ends without a finish", upstream: toolThenArgs, want: aborted},
		{
			name:     "error after the finish",
			upstream: finished,
			failErr:  upstreamErr,
			wantErr:  upstreamErr,
			want: []string{
				"message_start",
				"start 0 tool_use call_1 get_weather", `delta 0 input_json_delta {"ci`, "stop 0",
				"message_delta tool_use", "message_stop",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := func(yield func([]byte, error) bool) {
				for _, l := range tt.upstream {
					if !yield([]byte(l), nil) {
						return
					}
				}
				if tt.failErr != nil {
					yield(nil, tt.failErr)
				}
			}
			var lines []string
			var gotErr error
			for line, err := range adaptStream(upstream, adapter.NewRegistry(), adapter.FormatAnthropic, adapter.FormatOpenAI, slog.Default(), nil) {
				if err != nil {
					gotErr = err
					break
				}
				lines = append(lines, string(line))
			}

			if tt.wantErr == nil {
				require.NoError(t, gotErr, "an upstream that did not fail ends the sequence cleanly")
			} else {
				assert.ErrorIs(t, gotErr, tt.wantErr)
				_, notified := errors.AsType[*ClientNotifiedStreamError](gotErr)
				assert.True(t, notified, "the client already has its terminal event")
			}
			events := anthropicWireEvents(t, lines)
			assert.Equal(t, tt.want, anthropicGolden(events))
			if events[len(events)-1].Type == "error" {
				requireAnthropicAborted(t, events)
				assert.NotEmpty(t, events[len(events)-1].Error.Message)
				return
			}
			requireAnthropicContract(t, events)
		})
	}
}

func TestAdaptStream_AnthropicClientMessageID(t *testing.T) {
	tests := []struct {
		name     string
		target   adapter.Format
		upstream iter.Seq2[[]byte, error]
		want     *regexp.Regexp
	}{
		{name: "upstream id kept", target: adapter.FormatOpenAI, upstream: openAITextThenToolUpstream(), want: regexp.MustCompile(`^c$`)},
		{
			name:   "generated when upstream has none",
			target: adapter.FormatGemini,
			upstream: linesSeq(
				`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]},"finishReason":"STOP"}]}`,
			),
			want: regexp.MustCompile(`^msg_[A-Z2-7]{26}$`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := collectLines(t, adaptStream(tt.upstream, adapter.NewRegistry(), adapter.FormatAnthropic, tt.target, slog.Default(), nil))

			events := anthropicWireEvents(t, lines)
			requireAnthropicContract(t, events)
			require.NotNil(t, events[0].Message)
			assert.Regexp(t, tt.want, events[0].Message.ID)
		})
	}
}

func TestAdaptStream_AnthropicClientToolResultsPairWithUpstreamCalls(t *testing.T) {
	upstream := linesSeq(
		`data: {"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"get_weather","args":{"city":"Paris"}}}]}}]}`,
		`data: {"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"get_weather","args":{"city":"Rome"}}}]},"finishReason":"STOP"}]}`,
	)
	registry := adapter.NewRegistry()
	events := anthropicWireEvents(t, collectLines(t, adaptStream(upstream, registry, adapter.FormatAnthropic, adapter.FormatGemini, slog.Default(), nil)))
	requireAnthropicContract(t, events)

	var toolUses, toolResults []map[string]any
	for _, ev := range events {
		if ev.Type != "content_block_start" || ev.ContentBlock.Type != "tool_use" {
			continue
		}
		toolUses = append(toolUses, map[string]any{"type": "tool_use", "id": ev.ContentBlock.ID, "name": ev.ContentBlock.Name, "input": map[string]any{}})
		toolResults = append(toolResults, map[string]any{"type": "tool_result", "tool_use_id": ev.ContentBlock.ID, "content": "sunny in " + ev.ContentBlock.ID})
	}
	require.Len(t, toolUses, 2)
	require.NotEqual(t, toolUses[0]["id"], toolUses[1]["id"])
	ids := []string{toolUses[0]["id"].(string), toolUses[1]["id"].(string)}
	body, err := json.Marshal(map[string]any{
		"model":      "m",
		"max_tokens": 100,
		"messages": []map[string]any{
			{"role": "user", "content": "weather in Paris and Rome?"},
			{"role": "assistant", "content": toolUses},
			{"role": "user", "content": toolResults},
		},
	})
	require.NoError(t, err)

	tests := []struct {
		target adapter.Format
		pairs  func(t *testing.T, body []byte) (calls, results []string)
		want   []string
	}{
		{target: adapter.FormatGemini, pairs: geminiToolPairs, want: []string{"get_weather", "get_weather"}},
		{target: adapter.FormatVertex, pairs: geminiToolPairs, want: []string{"get_weather", "get_weather"}},
		{target: adapter.FormatOpenAI, pairs: openAIToolPairs, want: ids},
		{target: adapter.FormatBedrock, pairs: bedrockToolPairs, want: ids},
	}
	for _, tt := range tests {
		t.Run(string(tt.target), func(t *testing.T) {
			adapted, err := registry.AdaptRequest(body, adapter.FormatAnthropic, tt.target)
			require.NoError(t, err)

			calls, results := tt.pairs(t, adapted)
			assert.Equal(t, tt.want, calls, "calls")
			assert.Equal(t, tt.want, results, "results")
		})
	}
}

func geminiToolPairs(t *testing.T, body []byte) (calls, results []string) {
	t.Helper()
	var req struct {
		Contents []struct {
			Parts []struct {
				FunctionCall     *struct{ Name string } `json:"functionCall"`
				FunctionResponse *struct{ Name string } `json:"functionResponse"`
			} `json:"parts"`
		} `json:"contents"`
	}
	require.NoError(t, json.Unmarshal(body, &req))
	for _, c := range req.Contents {
		for _, p := range c.Parts {
			if p.FunctionCall != nil {
				calls = append(calls, p.FunctionCall.Name)
			}
			if p.FunctionResponse != nil {
				results = append(results, p.FunctionResponse.Name)
			}
		}
	}
	return calls, results
}

func openAIToolPairs(t *testing.T, body []byte) (calls, results []string) {
	t.Helper()
	var req struct {
		Messages []struct {
			ToolCalls  []struct{ ID string } `json:"tool_calls"`
			ToolCallID string                `json:"tool_call_id"`
		} `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(body, &req))
	for _, m := range req.Messages {
		for _, tc := range m.ToolCalls {
			calls = append(calls, tc.ID)
		}
		if m.ToolCallID != "" {
			results = append(results, m.ToolCallID)
		}
	}
	return calls, results
}

func bedrockToolPairs(t *testing.T, body []byte) (calls, results []string) {
	t.Helper()
	var req struct {
		Messages []struct {
			Content []struct {
				ToolUse    *struct{ ToolUseID string } `json:"toolUse"`
				ToolResult *struct{ ToolUseID string } `json:"toolResult"`
			} `json:"content"`
		} `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(body, &req))
	for _, m := range req.Messages {
		for _, b := range m.Content {
			if b.ToolUse != nil {
				calls = append(calls, b.ToolUse.ToolUseID)
			}
			if b.ToolResult != nil {
				results = append(results, b.ToolResult.ToolUseID)
			}
		}
	}
	return calls, results
}

func TestAdaptStream_AnthropicClientGetsErrorForUpstreamFailures(t *testing.T) {
	textChunk := `data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"}}]}`
	textAborted := []string{"message_start", "start 0 text", "delta 0 text_delta hi", "stop 0", "error api_error"}
	geminiFinish := func(reason string) []string {
		return []string{`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]},"finishReason":"` + reason + `"}]}`}
	}
	tests := []struct {
		name        string
		target      adapter.Format
		upstream    []string
		want        []string
		wantMessage string
		wantErr     bool
	}{
		{
			name:        "openai error payload then [DONE]",
			target:      adapter.FormatOpenAI,
			upstream:    []string{textChunk, `data: {"error":{"message":"The server had an error","type":"server_error"}}`, `data: [DONE]`},
			want:        textAborted,
			wantMessage: "upstream stream failed",
			wantErr:     true,
		},
		{
			name:        "openrouter error payload then [DONE]",
			target:      adapter.FormatOpenRouter,
			upstream:    []string{textChunk, `data: {"id":"gen-1","object":"chat.completion.chunk","choices":[],"error":{"code":502,"message":"Provider returned error"}}`, `data: [DONE]`},
			want:        textAborted,
			wantMessage: "upstream stream failed",
			wantErr:     true,
		},
		{
			name:   "openrouter error payload with its failure finish and usage",
			target: adapter.FormatOpenRouter,
			upstream: []string{
				textChunk,
				`data: {"id":"gen-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"error"}],"error":{"code":502,"message":"Provider returned error"},"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`,
				`data: [DONE]`,
			},
			want:        textAborted,
			wantMessage: "upstream stream failed",
			wantErr:     true,
		},
		{
			name:   "openrouter finish_reason error",
			target: adapter.FormatOpenRouter,
			upstream: []string{
				textChunk,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"error"}]}`,
				`data: [DONE]`,
			},
			want:        textAborted,
			wantMessage: "upstream reported an error while generating the message",
		},
		{name: "gemini MALFORMED_FUNCTION_CALL", target: adapter.FormatGemini, upstream: geminiFinish("MALFORMED_FUNCTION_CALL"), want: textAborted, wantMessage: "upstream generated a malformed tool call"},
		{name: "gemini UNEXPECTED_TOOL_CALL", target: adapter.FormatGemini, upstream: geminiFinish("UNEXPECTED_TOOL_CALL"), want: textAborted, wantMessage: "upstream called a tool that was not declared"},
		{name: "gemini TOO_MANY_TOOL_CALLS", target: adapter.FormatGemini, upstream: geminiFinish("TOO_MANY_TOOL_CALLS"), want: textAborted, wantMessage: "upstream made too many tool calls"},
		{
			name:   "openai late argument delta for a stopped tool block",
			target: adapter.FormatOpenAI,
			upstream: []string{
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Paris\"}"}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call_2","type":"function","function":{"name":"get_time","arguments":"{\"tz\":"}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"\"CET\"}"}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":" "}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
				`data: [DONE]`,
			},
			want: []string{
				"message_start",
				"start 0 tool_use call_1 get_weather", `delta 0 input_json_delta {"city":"Paris"}`, "stop 0",
				"start 1 tool_use call_2 get_time", `delta 1 input_json_delta {"tz":"CET"}`, "stop 1",
				"error api_error",
			},
			wantMessage: "upstream tool call arguments could not be streamed intact",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var lines []string
			var gotErr error
			for line, err := range adaptStream(linesSeq(tt.upstream...), adapter.NewRegistry(), adapter.FormatAnthropic, tt.target, slog.Default(), nil) {
				if err != nil {
					gotErr = err
					break
				}
				lines = append(lines, string(line))
			}

			if tt.wantErr {
				_, notified := errors.AsType[*ClientNotifiedStreamError](gotErr)
				assert.True(t, notified, "the client already has its error event")
				_, upstream := errors.AsType[*adapter.UpstreamStreamError](gotErr)
				assert.True(t, upstream, "the sequence error is the upstream's")
			} else {
				require.NoError(t, gotErr, "an upstream that did not fail ends the sequence cleanly")
			}
			events := anthropicWireEvents(t, lines)
			assert.Equal(t, tt.want, anthropicGolden(events))
			requireAnthropicAborted(t, events)
			if tt.wantMessage != "" {
				assert.Equal(t, tt.wantMessage, events[len(events)-1].Error.Message)
			}
			for _, l := range lines {
				assert.NotContains(t, l, "message_stop")
				assert.NotContains(t, l, "end_turn")
			}
		})
	}
}

func TestAdaptStream_AnthropicClientUpstreamErrorLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	upstream := linesSeq(
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"}}]}`,
		`data: {"error":{"message":"The server had an error","type":"server_error","code":"internal"}}`,
		`data: [DONE]`,
	)

	var lines []string
	var gotErr error
	for line, err := range adaptStream(upstream, adapter.NewRegistry(), adapter.FormatAnthropic, adapter.FormatOpenAI, logger, nil) {
		if err != nil {
			gotErr = err
			break
		}
		lines = append(lines, string(line))
	}

	_, notified := errors.AsType[*ClientNotifiedStreamError](gotErr)
	require.True(t, notified)
	events := anthropicWireEvents(t, lines)
	assert.Equal(t, "upstream stream failed", events[len(events)-1].Error.Message, "the client does not get the upstream's message")
	var entry map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &entry), buf.String())
	assert.Equal(t, "WARN", entry["level"])
	assert.Equal(t, "server_error", entry["error_type"])
	assert.Equal(t, "internal", entry["error_code"])
	assert.Equal(t, "The server had an error", entry["error_message"])
	assert.Equal(t, true, entry["client_aborted"])
}

func TestAdaptStream_UpstreamErrorPayloadIgnoredForOtherDeferredClients(t *testing.T) {
	text := `data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"}}]}`
	finish := `data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`
	usage := `data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`
	errorPayload := `data: {"error":{"message":"The server had an error","type":"server_error"}}`
	terminal := map[adapter.Format]string{
		adapter.FormatGemini:          `"finishReason":"STOP"`,
		adapter.FormatOpenAIResponses: `"type":"response.completed"`,
		adapter.FormatBedrock:         "messageStop",
	}
	tests := []struct {
		name     string
		upstream []string
	}{
		{name: "error after a held finish", upstream: []string{text, finish, errorPayload, `data: [DONE]`}},
		{name: "error after the flushed finish", upstream: []string{text, finish, usage, errorPayload, `data: [DONE]`}},
	}
	for _, tt := range tests {
		for source, want := range terminal {
			t.Run(tt.name+"/"+string(source), func(t *testing.T) {
				lines := collectLines(t, adaptStream(linesSeq(tt.upstream...), adapter.NewRegistry(), source, adapter.FormatOpenAI, slog.Default(), nil))

				joined := strings.Join(lines, "\n")
				assert.Equal(t, 1, strings.Count(joined, want), "the client gets the finish once")
				assert.NotContains(t, joined, "The server had an error")
			})
		}
	}
}

func TestAdaptStream_UpstreamErrorPayloadKeepsOpenAIClientStreamUnchanged(t *testing.T) {
	text := `data: {"id":"gen-1","model":"m","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"}}]}`
	textOut := `data: {"id":"gen-1","object":"chat.completion.chunk","model":"m","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"}}]}`
	finish := `data: {"id":"gen-1","model":"m","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`
	finishOut := `data: {"id":"gen-1","object":"chat.completion.chunk","model":"m","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`
	combined := `data: {"id":"gen-1","model":"m","object":"chat.completion.chunk","error":{"code":502,"message":"Provider returned error"},` +
		`"choices":[{"index":0,"delta":{},"finish_reason":"error"}],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`
	combinedOut := `data: {"id":"gen-1","object":"chat.completion.chunk","model":"m","choices":[{"index":0,"delta":{},"finish_reason":"error"}],` +
		`"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`
	pureError := `data: {"error":{"message":"The server had an error","type":"server_error","code":"internal"}}`
	openRouterError := `data: {"id":"gen-1","object":"chat.completion.chunk","choices":[],"error":{"code":502,"message":"Provider returned error"}}`
	tests := []struct {
		name         string
		upstream     []string
		want         []string
		wantObserved int
	}{
		{name: "error payload alone", upstream: []string{text, pureError, `data: [DONE]`}, want: []string{textOut, "", "data: [DONE]", ""}, wantObserved: 1},
		{name: "openrouter error payload", upstream: []string{text, openRouterError, `data: [DONE]`}, want: []string{textOut, "", "data: [DONE]", ""}, wantObserved: 1},
		{
			name:         "error payload with its failure finish and usage",
			upstream:     []string{text, combined, `data: [DONE]`},
			want:         []string{textOut, "", combinedOut, "", "data: [DONE]", ""},
			wantObserved: 2,
		},
		{name: "error payload after the finish", upstream: []string{text, finish, pureError}, want: []string{textOut, "", finishOut, ""}, wantObserved: 2},
	}
	for _, target := range []adapter.Format{adapter.FormatOpenRouter, adapter.FormatGroq} {
		for _, tt := range tests {
			t.Run(string(target)+"/"+tt.name, func(t *testing.T) {
				var observed int
				onChunk := func(*adapter.CanonicalStreamChunk) { observed++ }

				lines := collectLines(t, adaptStream(linesSeq(tt.upstream...), adapter.NewRegistry(), adapter.FormatOpenAI, target, slog.Default(), onChunk))

				assert.Equal(t, tt.want, lines)
				assert.Equal(t, tt.wantObserved, observed, "the observer skips a chunk carrying only the error")
			})
		}
	}
}

func TestAdaptStream_FinishReasonErrorKeepsTheFinishForOtherClients(t *testing.T) {
	upstream := linesSeq(
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"}}]}`,
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"error"}]}`,
		`data: [DONE]`,
	)

	lines := collectLines(t, adaptStream(upstream, adapter.NewRegistry(), adapter.FormatGemini, adapter.FormatOpenRouter, slog.Default(), nil))

	assert.Contains(t, strings.Join(lines, "\n"), `"finishReason":"error"`)
}

func TestAdaptStream_AnthropicClientGetsContentSentWithTheUpstreamError(t *testing.T) {
	upstream := linesSeq(
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"}}]}`,
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":" there"}}],`+
			`"error":{"message":"The server had an error","type":"server_error"},"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`,
		`data: [DONE]`,
	)
	var observed int
	var usage *adapter.CanonicalUsage
	onChunk := func(chunk *adapter.CanonicalStreamChunk) {
		observed++
		usage = adapter.MergeUsage(usage, chunk.Usage)
	}

	var lines []string
	var gotErr error
	for line, err := range adaptStream(upstream, adapter.NewRegistry(), adapter.FormatAnthropic, adapter.FormatOpenAI, slog.Default(), onChunk) {
		if err != nil {
			gotErr = err
			break
		}
		lines = append(lines, string(line))
	}

	_, notified := errors.AsType[*ClientNotifiedStreamError](gotErr)
	assert.True(t, notified, "the client already has its error event")
	events := anthropicWireEvents(t, lines)
	assert.Equal(t, []string{
		"message_start", "start 0 text", "delta 0 text_delta hi", "delta 0 text_delta  there", "stop 0", "error api_error",
	}, anthropicGolden(events))
	requireAnthropicAborted(t, events)
	assert.Equal(t, 2, observed, "the observer gets the chunk carrying the error with its content")
	require.NotNil(t, usage)
	assert.Equal(t, 5, usage.InputTokens)
	assert.Equal(t, 2, usage.OutputTokens)
}

func TestAdaptStream_AnthropicClientUpstreamErrorAfterTheFinishKeepsTheUsage(t *testing.T) {
	text := `data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"}}]}`
	upstreamErr := errors.New("upstream reset")
	tests := []struct {
		name     string
		upstream []string
		failErr  error
		wantErr  error
	}{
		{
			name: "error payload with usage then [DONE]",
			upstream: []string{
				text,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
				`data: {"error":{"message":"The server had an error","type":"server_error"},"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`,
				`data: [DONE]`,
			},
		},
		{
			name: "raw error after a finish with usage",
			upstream: []string{
				text,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`,
			},
			failErr: upstreamErr,
			wantErr: upstreamErr,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := func(yield func([]byte, error) bool) {
				for _, l := range tt.upstream {
					if !yield([]byte(l), nil) {
						return
					}
				}
				if tt.failErr != nil {
					yield(nil, tt.failErr)
				}
			}

			var lines []string
			var gotErr error
			for line, err := range adaptStream(upstream, adapter.NewRegistry(), adapter.FormatAnthropic, adapter.FormatOpenAI, slog.Default(), nil) {
				if err != nil {
					gotErr = err
					break
				}
				lines = append(lines, string(line))
			}

			_, notified := errors.AsType[*ClientNotifiedStreamError](gotErr)
			require.True(t, notified, "the client already has its terminal event")
			if tt.wantErr != nil {
				assert.ErrorIs(t, gotErr, tt.wantErr)
			} else {
				_, upstream := errors.AsType[*adapter.UpstreamStreamError](gotErr)
				assert.True(t, upstream, "the sequence error is the upstream's")
			}
			events := anthropicWireEvents(t, lines)
			assert.Equal(t, []string{
				"message_start", "start 0 text", "delta 0 text_delta hi", "stop 0", "message_delta end_turn", "message_stop",
			}, anthropicGolden(events))
			requireAnthropicContract(t, events)
			_, typed := typedEvents(t, lines)
			delta := eventOfType(t, typed, "message_delta")
			assert.JSONEq(t, `{"input_tokens":5,"output_tokens":1}`, string(delta.Usage))
		})
	}
}

func TestAdaptStream_UpstreamErrorWithFailureFinishGetsOneTerminalForOtherDeferredClients(t *testing.T) {
	upstream := []string{
		`data: {"id":"gen-1","model":"m","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"}}],"usage":{"prompt_tokens":5,"completion_tokens":0,"total_tokens":5}}`,
		`data: {"id":"gen-1","model":"m","object":"chat.completion.chunk","error":{"code":502,"message":"Provider returned error"},` +
			`"choices":[{"index":0,"delta":{},"finish_reason":"error"}],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`,
		`data: [DONE]`,
	}
	tests := []struct {
		source   adapter.Format
		terminal string
		finish   string
		usage    string
	}{
		{source: adapter.FormatGemini, terminal: `"finishReason":`, finish: `"finishReason":"error"`, usage: `"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":1,"totalTokenCount":6}`},
		{source: adapter.FormatOpenAIResponses, terminal: `"type":"response.completed"`, finish: `"status":"completed"`, usage: `"usage":{"input_tokens":5,"output_tokens":1,"total_tokens":6}`},
		{source: adapter.FormatBedrock, terminal: `"messageStop"`, finish: `"stopReason":"error"`, usage: `"usage":{"inputTokens":5,"outputTokens":1,"totalTokens":6}`},
	}
	for _, tt := range tests {
		t.Run(string(tt.source), func(t *testing.T) {
			lines := collectLines(t, adaptStream(linesSeq(upstream...), adapter.NewRegistry(), tt.source, adapter.FormatOpenRouter, slog.Default(), nil))

			joined := strings.Join(lines, "\n")
			assert.Equal(t, 1, strings.Count(joined, tt.terminal), "the client gets one terminal event")
			assert.Contains(t, joined, tt.finish)
			assert.Equal(t, 1, strings.Count(joined, tt.usage), "the client gets the merged usage once")
			assert.NotContains(t, joined, "Provider returned error")
		})
	}
}

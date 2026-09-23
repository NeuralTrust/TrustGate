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
	"fmt"
	"iter"
	"log/slog"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type cohereClientEvent struct {
	Type  string `json:"type"`
	Index *int   `json:"index"`
	Delta *struct {
		FinishReason string `json:"finish_reason"`
		Message      *struct {
			Content *struct {
				Text string `json:"text"`
			} `json:"content"`
			ToolCalls *struct {
				ID       string `json:"id"`
				Type     string `json:"type"`
				Function struct {
					Name      string  `json:"name"`
					Arguments *string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
		Usage *struct {
			BilledUnits  *cohereClientTokens `json:"billed_units"`
			Tokens       *cohereClientTokens `json:"tokens"`
			CachedTokens int                 `json:"cached_tokens"`
		} `json:"usage"`
	} `json:"delta"`
}

type cohereClientTokens struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

func cohereClientEvents(t *testing.T, lines []string) []cohereClientEvent {
	t.Helper()
	var events []cohereClientEvent
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
		var ev cohereClientEvent
		require.NoError(t, json.Unmarshal([]byte(payload), &ev))
		require.Equal(t, name, ev.Type, "event: line names the data type")
		name = ""
		events = append(events, ev)
	}
	return events
}

func requireCohereClientContract(t *testing.T, events []cohereClientEvent) {
	t.Helper()
	require.GreaterOrEqual(t, len(events), 2)
	require.Equal(t, "message-start", events[0].Type)
	last := events[len(events)-1]
	require.Equal(t, "message-end", last.Type)
	require.NotNil(t, last.Delta)
	assert.NotEmpty(t, last.Delta.FinishReason)
	openContent, openTool, nextTool := -1, -1, 0
	for i, ev := range events[1 : len(events)-1] {
		require.NotNil(t, ev.Index, "event %d %s carries an index", i, ev.Type)
		switch ev.Type {
		case "content-start":
			require.Equal(t, -1, openTool)
			require.Equal(t, -1, openContent)
			openContent = *ev.Index
		case "content-delta":
			require.Equal(t, openContent, *ev.Index)
		case "content-end":
			require.Equal(t, openContent, *ev.Index)
			openContent = -1
		case "tool-call-start":
			require.Equal(t, -1, openContent)
			require.Equal(t, -1, openTool)
			require.Equal(t, nextTool, *ev.Index)
			tc := ev.Delta.Message.ToolCalls
			assert.NotEmpty(t, tc.ID)
			assert.Equal(t, "function", tc.Type)
			assert.NotEmpty(t, tc.Function.Name)
			require.NotNil(t, tc.Function.Arguments)
			assert.Empty(t, *tc.Function.Arguments)
			openTool, nextTool = *ev.Index, nextTool+1
		case "tool-call-delta":
			require.Equal(t, openTool, *ev.Index)
		case "tool-call-end":
			require.Equal(t, openTool, *ev.Index)
			openTool = -1
		default:
			require.Failf(t, "unexpected event inside the message", "event %d: %s", i, ev.Type)
		}
	}
	require.Equal(t, -1, openContent)
	require.Equal(t, -1, openTool)
}

func cohereClientGolden(events []cohereClientEvent) []string {
	out := make([]string, 0, len(events))
	for _, ev := range events {
		switch ev.Type {
		case "content-start", "content-end", "tool-call-end":
			out = append(out, fmt.Sprintf("%s %d", ev.Type, *ev.Index))
		case "content-delta":
			out = append(out, fmt.Sprintf("content-delta %d %s", *ev.Index, ev.Delta.Message.Content.Text))
		case "tool-call-start":
			tc := ev.Delta.Message.ToolCalls
			out = append(out, fmt.Sprintf("tool-call-start %d %s %s", *ev.Index, tc.ID, tc.Function.Name))
		case "tool-call-delta":
			out = append(out, fmt.Sprintf("tool-call-delta %d %s", *ev.Index, *ev.Delta.Message.ToolCalls.Function.Arguments))
		case "message-end":
			line := "message-end " + ev.Delta.FinishReason
			if u := ev.Delta.Usage; u != nil {
				line += fmt.Sprintf(" billed=%d/%d tokens=%d/%d cached=%d",
					u.BilledUnits.InputTokens, u.BilledUnits.OutputTokens,
					u.Tokens.InputTokens, u.Tokens.OutputTokens, u.CachedTokens)
			}
			out = append(out, line)
		default:
			out = append(out, ev.Type)
		}
	}
	return out
}

func TestAdaptStream_CohereClientEventSequence(t *testing.T) {
	tests := []struct {
		name     string
		target   adapter.Format
		upstream iter.Seq2[[]byte, error]
		want     []string
	}{
		{
			name:     "openai text only with include_usage",
			target:   adapter.FormatOpenAI,
			upstream: openAIUpstreamWithIncludeUsage(),
			want: []string{
				"message-start",
				"content-start 0", "content-delta 0 hi", "content-end 0",
				"message-end COMPLETE billed=2000/10 tokens=2000/10 cached=1000",
			},
		},
		{
			name:     "openai text then tool call with trailing usage",
			target:   adapter.FormatOpenAI,
			upstream: openAITextThenToolUpstream(),
			want: []string{
				"message-start",
				"content-start 0", "content-delta 0 Let me check", "content-end 0",
				"tool-call-start 0 call_1 get_weather", `tool-call-delta 0 {"city":"Paris"}`, "tool-call-end 0",
				"message-end TOOL_CALL billed=20/5 tokens=20/5 cached=0",
			},
		},
		{
			name:     "openai two parallel tool calls",
			target:   adapter.FormatOpenAI,
			upstream: openAIParallelToolsUpstream(),
			want: []string{
				"message-start",
				"tool-call-start 0 call_1 get_weather", `tool-call-delta 0 {"city":"Paris"}`, "tool-call-end 0",
				"tool-call-start 1 call_2 get_time", `tool-call-delta 1 {"tz":"CET"}`, "tool-call-end 1",
				"message-end TOOL_CALL",
			},
		},
		{
			name:   "anthropic text then tool",
			target: adapter.FormatAnthropic,
			upstream: linesSeq(
				`data: {"type":"message_start","message":{"id":"msg_1","model":"claude","role":"assistant","usage":{"input_tokens":30,"cache_read_input_tokens":12,"output_tokens":1}}}`,
				`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
				`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Checking"}}`,
				`data: {"type":"content_block_stop","index":0}`,
				`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"get_weather","input":{}}}`,
				`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"city\":"}}`,
				`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\"Paris\"}"}}`,
				`data: {"type":"content_block_stop","index":1}`,
				`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":9}}`,
				`data: {"type":"message_stop"}`,
			),
			want: []string{
				"message-start",
				"content-start 0", "content-delta 0 Checking", "content-end 0",
				"tool-call-start 0 toolu_1 get_weather", `tool-call-delta 0 {"city":`, `tool-call-delta 0 "Paris"}`, "tool-call-end 0",
				"message-end TOOL_CALL billed=42/9 tokens=42/9 cached=12",
			},
		},
		{
			name:   "bedrock text then tool with trailing metadata",
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
				"message-start",
				"content-start 0", "content-delta 0 Checking", "content-end 0",
				"tool-call-start 0 tooluse_1 get_weather", `tool-call-delta 0 {"city":"Paris"}`, "tool-call-end 0",
				"message-end TOOL_CALL billed=10/7 tokens=10/7 cached=0",
			},
		},
		{
			name:   "gemini STOP with a functionCall",
			target: adapter.FormatGemini,
			upstream: linesSeq(
				`data: {"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"get_weather","args":{"city":"Paris"}}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"totalTokenCount":15}}`,
			),
			want: []string{
				"message-start",
				"tool-call-start 0 get_weather get_weather", `tool-call-delta 0 {"city":"Paris"}`, "tool-call-end 0",
				"message-end TOOL_CALL billed=10/5 tokens=10/5 cached=0",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := collectLines(t, adaptStream(tt.upstream, adapter.NewRegistry(), adapter.FormatCohere, tt.target, slog.Default(), nil))

			events := cohereClientEvents(t, lines)
			requireCohereClientContract(t, events)
			assert.Equal(t, tt.want, cohereClientGolden(events))
		})
	}
}

func TestAdaptStream_CohereClientDoneWithoutFinishEndsTheMessage(t *testing.T) {
	upstream := linesSeq(
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"}}]}`,
		`data: [DONE]`,
	)

	lines := collectLines(t, adaptStream(upstream, adapter.NewRegistry(), adapter.FormatCohere, adapter.FormatOpenAI, slog.Default(), nil))

	events := cohereClientEvents(t, lines)
	requireCohereClientContract(t, events)
	assert.Equal(t, "message-end COMPLETE", cohereClientGolden(events)[len(events)-1])
}

func TestAdaptStream_CohereToCoherePassthroughUnchanged(t *testing.T) {
	upstream := strings.Split(cohereUpstreamToolCallStream, "\n")

	lines := collectLines(t, adaptStream(linesSeq(upstream...), adapter.NewRegistry(), adapter.FormatCohere, adapter.FormatCohere, slog.Default(), nil))

	assert.Equal(t, upstream, lines)
}

const cohereUpstreamToolCallStream = `event: message-start
data: {"id":"93b3f521-090e-4ebc-bac4-f7c557e63c00","type":"message-start","delta":{"message":{"role":"assistant","content":[],"tool_plan":"","tool_calls":[],"citations":[]}}}

event: tool-plan-delta
data: {"type":"tool-plan-delta","delta":{"message":{"tool_plan":"Voy"}}}

event: tool-call-start
data: {"type":"tool-call-start","index":0,"delta":{"message":{"tool_calls":{"id":"database_agent_3v76fs3zjrgq","type":"function","function":{"name":"database_agent","arguments":""}}}}}

event: tool-call-delta
data: {"type":"tool-call-delta","index":0,"delta":{"message":{"tool_calls":{"function":{"arguments":"{\"query\":"}}}}}

event: tool-call-delta
data: {"type":"tool-call-delta","index":0,"delta":{"message":{"tool_calls":{"function":{"arguments":" \"Juan\"}"}}}}}

event: tool-call-end
data: {"type":"tool-call-end","index":0}

event: message-end
data: {"type":"message-end","delta":{"finish_reason":"TOOL_CALL","usage":{"billed_units":{"input_tokens":50,"output_tokens":26},"tokens":{"input_tokens":793,"output_tokens":61},"cached_tokens":176}}}

data: [DONE]`

func TestAdaptStream_CohereUpstreamToolCallReachesOtherClients(t *testing.T) {
	upstream := func() iter.Seq2[[]byte, error] {
		return linesSeq(strings.Split(cohereUpstreamToolCallStream, "\n")...)
	}

	t.Run("openai", func(t *testing.T) {
		lines := collectLines(t, adaptStream(upstream(), adapter.NewRegistry(), adapter.FormatOpenAI, adapter.FormatCohere, slog.Default(), nil))

		var id, name, args, finish string
		for _, chunk := range dataChunks(t, lines) {
			for _, c := range chunk["choices"].([]any) {
				choice := c.(map[string]any)
				if f, ok := choice["finish_reason"].(string); ok && f != "" {
					finish = f
				}
				delta, _ := choice["delta"].(map[string]any)
				calls, _ := delta["tool_calls"].([]any)
				for _, raw := range calls {
					call := raw.(map[string]any)
					if v, ok := call["id"].(string); ok && v != "" {
						id = v
					}
					fn := call["function"].(map[string]any)
					if v, ok := fn["name"].(string); ok && v != "" {
						name = v
					}
					if v, ok := fn["arguments"].(string); ok {
						args += v
					}
				}
			}
		}
		assert.Equal(t, "database_agent_3v76fs3zjrgq", id)
		assert.Equal(t, "database_agent", name)
		assert.JSONEq(t, `{"query":"Juan"}`, args)
		assert.Equal(t, "tool_calls", finish)
		assert.Equal(t, "data: [DONE]", lines[len(lines)-2])
	})

	t.Run("anthropic", func(t *testing.T) {
		lines := collectLines(t, adaptStream(upstream(), adapter.NewRegistry(), adapter.FormatAnthropic, adapter.FormatCohere, slog.Default(), nil))

		events := anthropicWireEvents(t, lines)
		requireAnthropicContract(t, events)
		assert.Equal(t, []string{
			"message_start",
			"start 0 tool_use database_agent_3v76fs3zjrgq database_agent",
			`delta 0 input_json_delta {"query":`, `delta 0 input_json_delta  "Juan"}`, "stop 0",
			"message_delta tool_use", "message_stop",
		}, anthropicGolden(events))
	})
}

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
		Error        string `json:"error"`
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
		if payload == "[DONE]" {
			require.Empty(t, name, "[DONE] has no event: line")
			events = append(events, cohereClientEvent{Type: payload})
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
	require.GreaterOrEqual(t, len(events), 3)
	require.Equal(t, "message-start", events[0].Type)
	require.Equal(t, "[DONE]", events[len(events)-1].Type, "[DONE] follows message-end")
	end := events[len(events)-2]
	require.Equal(t, "message-end", end.Type)
	require.NotNil(t, end.Delta)
	assert.NotEmpty(t, end.Delta.FinishReason)
	require.NotNil(t, end.Delta.Usage, "message-end carries usage")
	require.NotNil(t, end.Delta.Usage.BilledUnits, "message-end carries usage.billed_units")
	require.NotNil(t, end.Delta.Usage.Tokens, "message-end carries usage.tokens")
	openContent, openTool, nextTool := -1, -1, 0
	for i, ev := range events[1 : len(events)-2] {
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
		case "[DONE]":
			continue
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
				"message-end TOOL_CALL billed=0/0 tokens=0/0 cached=0",
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
	golden := cohereClientGolden(events)
	assert.Equal(t, "message-end COMPLETE billed=0/0 tokens=0/0 cached=0", golden[len(golden)-1])
}

func collectLinesAndError(seq iter.Seq2[[]byte, error]) ([]string, error) {
	var lines []string
	for line, err := range seq {
		if err != nil {
			return lines, err
		}
		lines = append(lines, string(line))
	}
	return lines, nil
}

func TestAdaptStream_CohereClientUpstreamErrorEndsWithError(t *testing.T) {
	text := `data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"}}],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`
	tool := `data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"ci"}}]}}]}`
	finish := `data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`
	errorPayload := `data: {"error":{"message":"The server had an error","type":"server_error","code":"internal"}}`
	transportErr := errors.New("connection reset")
	tests := []struct {
		name      string
		upstream  []string
		transport error
		want      []string
	}{
		{
			name:     "error payload after text",
			upstream: []string{text, errorPayload, `data: [DONE]`},
			want: []string{
				"message-start", "content-start 0", "content-delta 0 hi", "content-end 0",
				"message-end ERROR billed=5/1 tokens=5/1 cached=0",
			},
		},
		{
			name:     "error payload with an open tool call",
			upstream: []string{tool, errorPayload},
			want: []string{
				"message-start", "tool-call-start 0 call_1 get_weather", `tool-call-delta 0 {"ci`, "tool-call-end 0",
				"message-end ERROR billed=0/0 tokens=0/0 cached=0",
			},
		},
		{
			name:     "error payload after a held finish",
			upstream: []string{text, finish, errorPayload, `data: [DONE]`},
			want: []string{
				"message-start", "content-start 0", "content-delta 0 hi", "content-end 0",
				"message-end ERROR billed=5/1 tokens=5/1 cached=0",
			},
		},
		{
			name:     "error payload before any output",
			upstream: []string{errorPayload, `data: [DONE]`},
			want:     []string{"message-start", "message-end ERROR billed=0/0 tokens=0/0 cached=0"},
		},
		{
			name:      "transport error after text",
			upstream:  []string{text},
			transport: transportErr,
			want: []string{
				"message-start", "content-start 0", "content-delta 0 hi", "content-end 0",
				"message-end ERROR billed=5/1 tokens=5/1 cached=0",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, nil))
			upstream := func(yield func([]byte, error) bool) {
				for _, l := range tt.upstream {
					if !yield([]byte(l), nil) {
						return
					}
				}
				if tt.transport != nil {
					yield(nil, tt.transport)
				}
			}

			lines, gotErr := collectLinesAndError(adaptStream(upstream, adapter.NewRegistry(), adapter.FormatCohere, adapter.FormatOpenAI, logger, nil))

			_, notified := errors.AsType[*ClientNotifiedStreamError](gotErr)
			require.True(t, notified, "the client already has its terminal event")
			events := cohereClientEvents(t, lines)
			requireCohereClientContract(t, events)
			assert.Equal(t, tt.want, cohereClientGolden(events))
			assert.Equal(t, "upstream stream failed", events[len(events)-2].Delta.Error, "the client does not get the upstream's message")
			assert.NotContains(t, strings.Join(lines, "\n"), "The server had an error")
			var entry map[string]any
			require.NoError(t, json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &entry), buf.String())
			assert.Equal(t, "WARN", entry["level"])
			assert.Equal(t, true, entry["client_aborted"])
			if tt.transport != nil {
				assert.ErrorIs(t, gotErr, tt.transport)
				assert.Equal(t, "connection reset", entry["error"])
				return
			}
			_, upstreamErr := errors.AsType[*adapter.UpstreamStreamError](gotErr)
			assert.True(t, upstreamErr, "the sequence error is the upstream's")
			assert.Equal(t, "server_error", entry["error_type"])
			assert.Equal(t, "internal", entry["error_code"])
			assert.Equal(t, "The server had an error", entry["error_message"])
		})
	}
}

func TestAdaptStream_CohereClientTransportErrorBeforeOutputKeepsTheSequenceError(t *testing.T) {
	transportErr := errors.New("connection reset")
	upstream := func(yield func([]byte, error) bool) {
		yield(nil, transportErr)
	}

	lines, gotErr := collectLinesAndError(adaptStream(upstream, adapter.NewRegistry(), adapter.FormatCohere, adapter.FormatOpenAI, slog.Default(), nil))

	assert.Empty(t, lines)
	assert.ErrorIs(t, gotErr, transportErr)
	_, notified := errors.AsType[*ClientNotifiedStreamError](gotErr)
	assert.False(t, notified, "the transport reports the failure to a client that got nothing")
}

func TestAdaptStream_CohereClientGetsEmptyObjectForNoArgumentTools(t *testing.T) {
	upstreamLines := []string{
		`data: {"type":"message_start","message":{"id":"msg_1","model":"claude","role":"assistant","usage":{"input_tokens":3,"output_tokens":1}}}`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"list_files","input":{}}}`,
		`data: {"type":"content_block_stop","index":0}`,
		`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_2","name":"get_time","input":{}}}`,
		`data: {"type":"content_block_stop","index":1}`,
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":4}}`,
		`data: {"type":"message_stop"}`,
	}
	consumed := 0
	upstream := func(yield func([]byte, error) bool) {
		for _, l := range upstreamLines {
			consumed++
			if !yield([]byte(l), nil) {
				return
			}
		}
	}

	var lines []string
	secondStartedAt := 0
	for line, err := range adaptStream(upstream, adapter.NewRegistry(), adapter.FormatCohere, adapter.FormatAnthropic, slog.Default(), nil) {
		require.NoError(t, err)
		lines = append(lines, string(line))
		if strings.HasPrefix(string(line), "data: ") && strings.Contains(string(line), `"tool-call-start"`) && strings.Contains(string(line), "get_time") {
			secondStartedAt = consumed
		}
	}

	assert.Equal(t, 4, secondStartedAt, "the second call starts when it arrives, not at the finish")
	events := cohereClientEvents(t, lines)
	requireCohereClientContract(t, events)
	assert.Equal(t, []string{
		"message-start",
		"tool-call-start 0 toolu_1 list_files", "tool-call-delta 0 {}", "tool-call-end 0",
		"tool-call-start 1 toolu_2 get_time", "tool-call-delta 1 {}", "tool-call-end 1",
		"message-end TOOL_CALL billed=3/4 tokens=3/4 cached=0",
	}, cohereClientGolden(events))
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

		var id, name, args, finish, content string
		for _, chunk := range dataChunks(t, lines) {
			for _, c := range chunk["choices"].([]any) {
				choice := c.(map[string]any)
				if f, ok := choice["finish_reason"].(string); ok && f != "" {
					finish = f
				}
				delta, _ := choice["delta"].(map[string]any)
				if v, ok := delta["content"].(string); ok {
					content += v
				}
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
		assert.Equal(t, "Voy", content, "the tool plan reaches the client as text")
		assert.Equal(t, "tool_calls", finish)
		assert.Equal(t, "data: [DONE]", lines[len(lines)-2])
	})

	t.Run("anthropic", func(t *testing.T) {
		lines := collectLines(t, adaptStream(upstream(), adapter.NewRegistry(), adapter.FormatAnthropic, adapter.FormatCohere, slog.Default(), nil))

		events := anthropicWireEvents(t, lines)
		requireAnthropicContract(t, events)
		assert.Equal(t, []string{
			"message_start",
			"start 0 text", "delta 0 text_delta Voy", "stop 0",
			"start 1 tool_use database_agent_3v76fs3zjrgq database_agent",
			`delta 1 input_json_delta {"query":`, `delta 1 input_json_delta  "Juan"}`, "stop 1",
			"message_delta tool_use", "message_stop",
		}, anthropicGolden(events))
	})
}

func TestAdaptStream_CohereToolPlanRoundTripsThroughAnOpenAIClient(t *testing.T) {
	registry := adapter.NewRegistry()
	lines := collectLines(t, adaptStream(linesSeq(strings.Split(cohereUpstreamToolCallStream, "\n")...), registry, adapter.FormatOpenAI, adapter.FormatCohere, slog.Default(), nil))
	var content, id, name, args string
	for _, chunk := range dataChunks(t, lines) {
		for _, c := range chunk["choices"].([]any) {
			delta, _ := c.(map[string]any)["delta"].(map[string]any)
			if v, ok := delta["content"].(string); ok {
				content += v
			}
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
	next, err := json.Marshal(map[string]any{
		"model": "command-a",
		"messages": []map[string]any{
			{"role": "user", "content": "who is Juan?"},
			{"role": "assistant", "content": content, "tool_calls": []map[string]any{
				{"id": id, "type": "function", "function": map[string]any{"name": name, "arguments": args}},
			}},
			{"role": "tool", "tool_call_id": id, "content": "Juan is a user"},
		},
	})
	require.NoError(t, err)

	body, err := registry.AdaptRequest(next, adapter.FormatOpenAI, adapter.FormatCohere)
	require.NoError(t, err)

	var req struct {
		Messages []map[string]json.RawMessage `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(body, &req))
	require.Len(t, req.Messages, 3)
	assistant := req.Messages[1]
	assert.JSONEq(t, `"assistant"`, string(assistant["role"]))
	assert.JSONEq(t, `"Voy"`, string(assistant["tool_plan"]))
	assert.NotContains(t, assistant, "content", "the plan is not sent as assistant content")
	assert.JSONEq(t, `[{"id":"database_agent_3v76fs3zjrgq","type":"function","function":{"name":"database_agent","arguments":"{\"query\": \"Juan\"}"}}]`, string(assistant["tool_calls"]))
}

func logEntries(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var entries []map[string]any
	for line := range bytes.Lines(buf.Bytes()) {
		var entry map[string]any
		require.NoError(t, json.Unmarshal(line, &entry), string(line))
		entries = append(entries, entry)
	}
	return entries
}

func logMessages(entries []map[string]any) []any {
	messages := make([]any, 0, len(entries))
	for _, entry := range entries {
		messages = append(messages, entry["msg"])
	}
	return messages
}

func TestAdaptStream_CohereClientTransportErrorAfterTheFinishDeliversIt(t *testing.T) {
	const incomplete = "stream usage may be incomplete: upstream failed before sending output tokens"
	text := `data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"}}],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`
	finish := `data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`
	transportErr := errors.New("connection reset")
	tests := []struct {
		name           string
		upstream       []string
		want           []string
		wantIncomplete bool
	}{
		{
			name:     "finish then transport error before include_usage",
			upstream: []string{text, finish},
			want: []string{
				"message-start", "content-start 0", "content-delta 0 hi", "content-end 0",
				"message-end COMPLETE billed=5/1 tokens=5/1 cached=0",
			},
		},
		{
			name:           "content-less finish then transport error",
			upstream:       []string{finish},
			want:           []string{"message-start", "message-end COMPLETE billed=0/0 tokens=0/0 cached=0"},
			wantIncomplete: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, nil))
			upstream := func(yield func([]byte, error) bool) {
				for _, l := range tt.upstream {
					if !yield([]byte(l), nil) {
						return
					}
				}
				yield(nil, transportErr)
			}

			lines, gotErr := collectLinesAndError(adaptStream(upstream, adapter.NewRegistry(), adapter.FormatCohere, adapter.FormatOpenAI, logger, nil))

			assert.ErrorIs(t, gotErr, transportErr)
			_, notified := errors.AsType[*ClientNotifiedStreamError](gotErr)
			assert.True(t, notified, "the client already has its message-end and [DONE]")
			events := cohereClientEvents(t, lines)
			requireCohereClientContract(t, events)
			assert.Equal(t, tt.want, cohereClientGolden(events))
			assert.Empty(t, events[len(events)-2].Delta.Error)
			entries := logEntries(t, &buf)
			messages := logMessages(entries)
			if tt.wantIncomplete {
				assert.Contains(t, messages, incomplete)
			} else {
				assert.NotContains(t, messages, incomplete)
			}
			last := entries[len(entries)-1]
			assert.Equal(t, "upstream stream failed; the client stream ended with its terminal event", last["msg"])
			assert.Equal(t, false, last["client_aborted"])
		})
	}
}

func TestAdaptStream_CohereClientUpstreamEndWithoutFinishEndsWithError(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	upstream := linesSeq(
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"}}],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`,
	)

	lines, gotErr := collectLinesAndError(adaptStream(upstream, adapter.NewRegistry(), adapter.FormatCohere, adapter.FormatOpenAI, logger, nil))

	require.NoError(t, gotErr)
	events := cohereClientEvents(t, lines)
	requireCohereClientContract(t, events)
	assert.Equal(t, []string{
		"message-start", "content-start 0", "content-delta 0 hi", "content-end 0",
		"message-end ERROR billed=5/1 tokens=5/1 cached=0",
	}, cohereClientGolden(events))
	assert.Equal(t, "upstream stream ended before the message finished", events[len(events)-2].Delta.Error)
	assert.Contains(t, logMessages(logEntries(t, &buf)), "upstream stream ended without a finish; aborted the client stream with an error event")
}

func TestAdaptStream_CohereClientAbortLogsDroppedToolCalls(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	upstream := linesSeq(
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"a","arguments":"{\"x\":"}}]}}]}`,
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call_2","type":"function","function":{"name":"b","arguments":"{\"y\":"}}]}}]}`,
		`data: {"error":{"message":"The server had an error","type":"server_error","code":"internal"}}`,
	)

	lines, gotErr := collectLinesAndError(adaptStream(upstream, adapter.NewRegistry(), adapter.FormatCohere, adapter.FormatOpenAI, logger, nil))

	_, notified := errors.AsType[*ClientNotifiedStreamError](gotErr)
	require.True(t, notified)
	events := cohereClientEvents(t, lines)
	requireCohereClientContract(t, events)
	assert.Equal(t, []string{
		"message-start", "tool-call-start 0 call_1 a", `tool-call-delta 0 {"x":`, "tool-call-end 0",
		"message-end ERROR billed=0/0 tokens=0/0 cached=0",
	}, cohereClientGolden(events))
	var dropped map[string]any
	for _, entry := range logEntries(t, &buf) {
		if entry["msg"] == "cohere stream dropped tool call content" {
			dropped = entry
		}
	}
	require.NotNil(t, dropped, buf.String())
	assert.Equal(t, float64(1), dropped["dropped_tool_calls"])
	assert.Equal(t, float64(0), dropped["argument_deltas"])
}

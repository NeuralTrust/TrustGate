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
	"errors"
	"iter"
	"log/slog"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdaptStream_BedrockClientGetsOneMergedMetadataAfterMessageStop(t *testing.T) {
	upstream := linesSeq(
		`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude","usage":{"input_tokens":10,"output_tokens":1,"cache_read_input_tokens":1000,"cache_creation_input_tokens":300,"cache_creation":{"ephemeral_5m_input_tokens":100,"ephemeral_1h_input_tokens":200}}}}`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}`,
		`data: {"type":"content_block_stop","index":0}`,
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}`,
		`data: {"type":"message_stop"}`,
	)

	events := converseEvents(t, collectLines(t, adaptStream(upstream, adapter.NewRegistry(), adapter.FormatBedrock, adapter.FormatAnthropic, slog.Default(), nil)))
	require.NotEmpty(t, events)

	var metadata []*adapter.ConverseMetadata
	for _, ev := range events {
		if ev.Metadata != nil {
			metadata = append(metadata, ev.Metadata)
		}
	}
	require.Len(t, metadata, 1, "exactly one metadata event")
	last := events[len(events)-1]
	require.NotNil(t, last.Metadata, "metadata closes the stream")
	require.NotNil(t, events[len(events)-2].MessageStop, "metadata follows messageStop")

	assert.Equal(t, &adapter.ConverseUsage{
		InputTokens: 10, OutputTokens: 7, TotalTokens: 1317,
		CacheReadInputTokens: 1000, CacheWriteInputTokens: 300,
		CacheDetails: []adapter.ConverseCacheDetail{{InputTokens: 200, TTL: "1h"}, {InputTokens: 100, TTL: "5m"}},
	}, last.Metadata.Usage)
}

func TestAdaptStream_BedrockClientWithoutUsageEmitsNoMetadata(t *testing.T) {
	upstream := linesSeq(
		`data: {"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"}}]}`,
		`data: {"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
		`data: [DONE]`,
	)

	lines := collectLines(t, adaptStream(upstream, adapter.NewRegistry(), adapter.FormatBedrock, adapter.FormatOpenAI, slog.Default(), nil))

	joined := strings.Join(lines, "\n")
	assert.Contains(t, joined, `"messageStop"`)
	assert.NotContains(t, joined, `"metadata"`)
}

func converseEvents(t *testing.T, lines []string) []adapter.ConverseStreamEvent {
	t.Helper()
	var events []adapter.ConverseStreamEvent
	for _, line := range lines {
		payload, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		var ev adapter.ConverseStreamEvent
		require.NoError(t, json.Unmarshal([]byte(payload), &ev))
		events = append(events, ev)
	}
	return events
}

func TestAdaptStream_BedrockClientUpstreamErrorEmitsNoMetadata(t *testing.T) {
	upstreamErr := errors.New("upstream reset")
	upstream := func(yield func([]byte, error) bool) {
		for _, l := range []string{
			`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude","usage":{"input_tokens":10,"output_tokens":1,"cache_read_input_tokens":1000}}}`,
			`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
			`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}`,
		} {
			if !yield([]byte(l), nil) {
				return
			}
		}
		yield(nil, upstreamErr)
	}

	var lines []string
	var gotErr error
	for line, err := range adaptStream(upstream, adapter.NewRegistry(), adapter.FormatBedrock, adapter.FormatAnthropic, slog.Default(), nil) {
		if err != nil {
			gotErr = err
			continue
		}
		require.NoError(t, gotErr, "nothing may follow the upstream error")
		lines = append(lines, string(line))
	}

	require.ErrorIs(t, gotErr, upstreamErr)
	require.NotEmpty(t, lines)
	for _, ev := range converseEvents(t, lines) {
		assert.Nil(t, ev.Metadata, "no trailing metadata after an upstream error")
	}
}

func TestAdaptStream_BedrockClientStopsWhenYieldReturnsFalse(t *testing.T) {
	var pulled int
	upstream := func(yield func([]byte, error) bool) {
		for _, l := range []string{
			`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude","usage":{"input_tokens":10,"output_tokens":1,"cache_read_input_tokens":1000}}}`,
			`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
			`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}`,
			`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}`,
			`data: {"type":"message_stop"}`,
		} {
			pulled++
			if !yield([]byte(l), nil) {
				return
			}
		}
	}

	var received int
	for _, err := range adaptStream(upstream, adapter.NewRegistry(), adapter.FormatBedrock, adapter.FormatAnthropic, slog.Default(), nil) {
		require.NoError(t, err)
		received++
		break
	}

	assert.Equal(t, 1, received)
	assert.Equal(t, 1, pulled, "the upstream is not read past the rejected line")
}

func TestAdaptStream_BedrockClientFromOpenAIIncludeUsageChunk(t *testing.T) {
	upstream := linesSeq(
		`data: {"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"}}]}`,
		`data: {"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
		`data: {"id":"c","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":2000,"completion_tokens":10,"total_tokens":2010,"prompt_tokens_details":{"cached_tokens":1000}}}`,
		`data: [DONE]`,
	)

	events := converseEvents(t, collectLines(t, adaptStream(upstream, adapter.NewRegistry(), adapter.FormatBedrock, adapter.FormatOpenAI, slog.Default(), nil)))
	require.GreaterOrEqual(t, len(events), 2)

	var metadata int
	for _, ev := range events {
		if ev.Metadata != nil {
			metadata++
		}
	}
	require.Equal(t, 1, metadata, "exactly one metadata event")
	last := events[len(events)-1]
	require.NotNil(t, last.Metadata, "metadata closes the stream")
	require.NotNil(t, events[len(events)-2].MessageStop, "metadata follows messageStop")
	assert.Equal(t, &adapter.ConverseUsage{
		InputTokens: 1000, OutputTokens: 10, TotalTokens: 2010, CacheReadInputTokens: 1000,
	}, last.Metadata.Usage)
}

type sseTestEvent struct {
	Type     string          `json:"type"`
	Usage    json.RawMessage `json:"usage"`
	Response json.RawMessage `json:"response"`
}

func typedEvents(t *testing.T, lines []string) ([]string, []sseTestEvent) {
	t.Helper()
	var types []string
	var events []sseTestEvent
	for _, line := range lines {
		payload, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		var ev sseTestEvent
		require.NoError(t, json.Unmarshal([]byte(payload), &ev))
		types = append(types, ev.Type)
		events = append(events, ev)
	}
	return types, events
}

func eventOfType(t *testing.T, events []sseTestEvent, typ string) sseTestEvent {
	t.Helper()
	var found []sseTestEvent
	for _, ev := range events {
		if ev.Type == typ {
			found = append(found, ev)
		}
	}
	require.Len(t, found, 1, "exactly one %s event", typ)
	return found[0]
}

func bedrockUpstreamWithTrailingMetadata() iter.Seq2[[]byte, error] {
	return linesSeq(
		`data: {"messageStart":{"role":"assistant"}}`,
		`data: {"contentBlockDelta":{"contentBlockIndex":0,"delta":{"text":"hi"}}}`,
		`data: {"contentBlockStop":{"contentBlockIndex":0}}`,
		`data: {"messageStop":{"stopReason":"end_turn"}}`,
		`data: {"metadata":{"usage":{"inputTokens":10,"outputTokens":7,"totalTokens":1317,"cacheReadInputTokens":1000,"cacheWriteInputTokens":300,"cacheDetails":[{"inputTokens":200,"ttl":"1h"},{"inputTokens":100,"ttl":"5m"}]}}}`,
	)
}

func openAIUpstreamWithIncludeUsage() iter.Seq2[[]byte, error] {
	return linesSeq(
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"}}]}`,
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":2000,"completion_tokens":10,"total_tokens":2010,"prompt_tokens_details":{"cached_tokens":1000}}}`,
		`data: [DONE]`,
	)
}

func TestAdaptStream_AnthropicClientGetsTrailingUsageInMessageDelta(t *testing.T) {
	tests := []struct {
		name      string
		upstream  iter.Seq2[[]byte, error]
		target    adapter.Format
		wantUsage string
	}{
		{
			name:      "bedrock metadata after messageStop",
			upstream:  bedrockUpstreamWithTrailingMetadata(),
			target:    adapter.FormatBedrock,
			wantUsage: `{"input_tokens":10,"output_tokens":7,"cache_creation_input_tokens":300,"cache_read_input_tokens":1000,"cache_creation":{"ephemeral_5m_input_tokens":100,"ephemeral_1h_input_tokens":200}}`,
		},
		{
			name:      "openai include_usage chunk after finish",
			upstream:  openAIUpstreamWithIncludeUsage(),
			target:    adapter.FormatOpenAI,
			wantUsage: `{"input_tokens":1000,"output_tokens":10,"cache_read_input_tokens":1000}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := collectLines(t, adaptStream(tt.upstream, adapter.NewRegistry(), adapter.FormatAnthropic, tt.target, slog.Default(), nil))

			types, events := typedEvents(t, lines)
			assert.Equal(t, []string{
				"message_start", "content_block_start", "content_block_delta",
				"content_block_stop", "message_delta", "message_stop",
			}, types)
			assert.JSONEq(t, tt.wantUsage, string(eventOfType(t, events, "message_delta").Usage))
		})
	}
}

func TestAdaptStream_ResponsesClientGetsTrailingUsageInCompleted(t *testing.T) {
	tests := []struct {
		name      string
		upstream  iter.Seq2[[]byte, error]
		target    adapter.Format
		wantTypes []string
		wantUsage string
		wantID    string
		wantModel string
	}{
		{
			name:      "openai include_usage chunk after finish",
			upstream:  openAIUpstreamWithIncludeUsage(),
			target:    adapter.FormatOpenAI,
			wantTypes: []string{"response.output_item.added", "response.output_text.delta", "response.completed"},
			wantUsage: `{"input_tokens":2000,"output_tokens":10,"total_tokens":2010,"input_tokens_details":{"cached_tokens":1000}}`,
			wantID:    "c",
			wantModel: "gpt",
		},
		{
			name: "anthropic usage on message_start and message_delta",
			upstream: linesSeq(
				`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude","usage":{"input_tokens":10,"output_tokens":1,"cache_read_input_tokens":1000,"cache_creation_input_tokens":300}}}`,
				`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
				`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}`,
				`data: {"type":"content_block_stop","index":0}`,
				`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}`,
				`data: {"type":"message_stop"}`,
			),
			target:    adapter.FormatAnthropic,
			wantTypes: []string{"response.output_item.added", "response.output_text.delta", "response.completed"},
			wantUsage: `{"input_tokens":1310,"output_tokens":7,"total_tokens":1317,"input_tokens_details":{"cached_tokens":1000,"cache_write_tokens":300}}`,
			wantID:    "msg_1",
			wantModel: "claude",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := collectLines(t, adaptStream(tt.upstream, adapter.NewRegistry(), adapter.FormatOpenAIResponses, tt.target, slog.Default(), nil))

			types, events := typedEvents(t, lines)
			assert.Equal(t, tt.wantTypes, types)
			var completed struct {
				ID    string          `json:"id"`
				Model string          `json:"model"`
				Usage json.RawMessage `json:"usage"`
			}
			require.NoError(t, json.Unmarshal(eventOfType(t, events, "response.completed").Response, &completed))
			assert.JSONEq(t, tt.wantUsage, string(completed.Usage))
			assert.Equal(t, tt.wantID, completed.ID)
			assert.Equal(t, tt.wantModel, completed.Model)
		})
	}
}

func bedrockFinishedUpstream(pulled *int) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		for _, l := range []string{
			`data: {"messageStart":{"role":"assistant"}}`,
			`data: {"contentBlockDelta":{"contentBlockIndex":0,"delta":{"text":"hi"}}}`,
			`data: {"messageStop":{"stopReason":"end_turn"}}`,
			`data: {"metadata":{"usage":{"inputTokens":10,"outputTokens":7,"totalTokens":17}}}`,
		} {
			*pulled++
			if !yield([]byte(l), nil) {
				return
			}
		}
	}
}

func TestAdaptStream_DeferredFinishFlushedBeforeUpstreamError(t *testing.T) {
	upstreamErr := errors.New("upstream reset")
	started := `data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"}}],"usage":{"prompt_tokens":20,"completion_tokens":1,"total_tokens":21}}`
	finished := `data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`
	terminals := map[adapter.Format][2]string{
		adapter.FormatAnthropic:       {`"type":"message_stop"`, `"output_tokens":1}`},
		adapter.FormatOpenAIResponses: {`"type":"response.completed"`, `"total_tokens":21`},
		adapter.FormatBedrock:         {`"metadata"`, `"totalTokens":21`},
	}
	for source, want := range terminals {
		terminal, usage := want[0], want[1]
		for name, upstream := range map[string][]string{"finished": {started, finished}, "unfinished": {started}} {
			t.Run(string(source)+"/"+name, func(t *testing.T) {
				failing := func(yield func([]byte, error) bool) {
					for _, l := range upstream {
						if !yield([]byte(l), nil) {
							return
						}
					}
					yield(nil, upstreamErr)
				}
				var data []string
				var gotErr error
				for line, err := range adaptStream(failing, adapter.NewRegistry(), source, adapter.FormatOpenAI, slog.Default(), nil) {
					if err != nil {
						gotErr = err
						continue
					}
					require.NoError(t, gotErr, "nothing may follow the upstream error")
					if strings.HasPrefix(string(line), "data: ") {
						data = append(data, string(line))
					}
				}

				require.ErrorIs(t, gotErr, upstreamErr)
				require.NotEmpty(t, data)
				joined := strings.Join(data, "\n")
				if name == "unfinished" {
					assert.NotContains(t, joined, terminal)
					assert.NotContains(t, joined, `"messageStop"`)
					return
				}
				assert.Equal(t, 1, strings.Count(joined, terminal))
				assert.Contains(t, data[len(data)-1], terminal, "the held finish is the last event before the error")
				assert.Contains(t, strings.Join(data[len(data)-2:], "\n"), usage, "it carries the usage merged so far")
			})
		}
	}
}

func TestAdaptStream_DeferredFinishFlushedOnTerminalSignal(t *testing.T) {
	tests := []struct {
		name           string
		source, target adapter.Format
		lines          []string
		terminal       string
	}{
		{
			name: "anthropic message_delta", source: adapter.FormatBedrock, target: adapter.FormatAnthropic,
			lines: []string{
				`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude","usage":{"input_tokens":10,"output_tokens":1}}}`,
				`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}`,
			},
			terminal: `"metadata"`,
		},
		{
			name: "bedrock metadata after messageStop", source: adapter.FormatAnthropic, target: adapter.FormatBedrock,
			lines: []string{
				`data: {"messageStart":{"role":"assistant"}}`,
				`data: {"messageStop":{"stopReason":"end_turn"}}`,
				`data: {"metadata":{"usage":{"inputTokens":10,"outputTokens":7,"totalTokens":17}}}`,
			},
			terminal: `"type":"message_stop"`,
		},
		{
			name: "openai include_usage chunk", source: adapter.FormatOpenAIResponses, target: adapter.FormatOpenAI,
			lines: []string{
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"},"finish_reason":"stop"}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":20,"completion_tokens":1,"total_tokens":21}}`,
			},
			terminal: `"type":"response.completed"`,
		},
		{
			name: "openai [DONE] without usage", source: adapter.FormatAnthropic, target: adapter.FormatOpenAI,
			lines: []string{
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"},"finish_reason":"stop"}]}`,
				`data: [DONE]`,
			},
			terminal: `"type":"message_stop"`,
		},
		{
			name: "responses response.completed", source: adapter.FormatAnthropic, target: adapter.FormatOpenAIResponses,
			lines: []string{
				`data: {"type":"response.output_item.added","output_index":0,"item":{"type":"message","role":"assistant"}}`,
				`data: {"type":"response.completed","response":{"id":"r","model":"gpt","usage":{"input_tokens":10,"output_tokens":2,"total_tokens":12}}}`,
			},
			terminal: `"type":"message_stop"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pulled, pulledAtFlush, flushes int
			upstream := func(yield func([]byte, error) bool) {
				for _, l := range append(tt.lines, `: ping`) {
					pulled++
					if !yield([]byte(l), nil) {
						return
					}
				}
			}
			for line, err := range adaptStream(upstream, adapter.NewRegistry(), tt.source, tt.target, slog.Default(), nil) {
				require.NoError(t, err)
				if strings.Contains(string(line), tt.terminal) {
					flushes++
					pulledAtFlush = pulled
				}
			}

			assert.Equal(t, 1, flushes)
			assert.Equal(t, len(tt.lines), pulledAtFlush, "flushed before the trailing line is read")
		})
	}
}

func TestAdaptStream_DeferredFinishStopsWhenYieldReturnsFalse(t *testing.T) {
	for _, source := range []adapter.Format{adapter.FormatAnthropic, adapter.FormatOpenAIResponses} {
		t.Run(string(source), func(t *testing.T) {
			var pulled, received int
			for _, err := range adaptStream(bedrockFinishedUpstream(&pulled), adapter.NewRegistry(), source, adapter.FormatBedrock, slog.Default(), nil) {
				require.NoError(t, err)
				received++
				break
			}

			assert.Equal(t, 1, received)
			assert.Equal(t, 1, pulled, "the upstream is not read past the rejected line")
		})
	}
}

func openAIToolCallUpstream() iter.Seq2[[]byte, error] {
	return linesSeq(
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""}}]}}]}`,
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"city\":\"Paris\"}"}}]}}]}`,
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":2000,"completion_tokens":10,"total_tokens":2010,"prompt_tokens_details":{"cached_tokens":1000}}}`,
		`data: [DONE]`,
	)
}

func TestAdaptStream_AnthropicClientGetsToolUseStopReasonWithUsage(t *testing.T) {
	lines := collectLines(t, adaptStream(openAIToolCallUpstream(), adapter.NewRegistry(), adapter.FormatAnthropic, adapter.FormatOpenAI, slog.Default(), nil))

	types, events := typedEvents(t, lines)
	assert.Equal(t, "message_stop", types[len(types)-1])
	var delta struct {
		Delta struct {
			StopReason string `json:"stop_reason"`
		} `json:"delta"`
	}
	for _, line := range lines {
		if payload, ok := strings.CutPrefix(line, "data: "); ok && strings.Contains(payload, `"message_delta"`) {
			require.NoError(t, json.Unmarshal([]byte(payload), &delta))
		}
	}
	assert.Equal(t, "tool_use", delta.Delta.StopReason)
	assert.JSONEq(t, `{"input_tokens":1000,"output_tokens":10,"cache_read_input_tokens":1000}`, string(eventOfType(t, events, "message_delta").Usage))
}

func TestAdaptStream_DeferredUsageNotFlushedWithoutFinish(t *testing.T) {
	upstream := func() iter.Seq2[[]byte, error] {
		return linesSeq(
			`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude","usage":{"input_tokens":10,"output_tokens":1,"cache_read_input_tokens":1000}}}`,
			`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
			`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}`,
			`data: {"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`,
		)
	}

	for _, ev := range converseEvents(t, collectLines(t, adaptStream(upstream(), adapter.NewRegistry(), adapter.FormatBedrock, adapter.FormatAnthropic, slog.Default(), nil))) {
		assert.Nil(t, ev.Metadata, "no metadata for an unfinished stream")
		assert.Nil(t, ev.MessageStop)
	}

	types, _ := typedEvents(t, collectLines(t, adaptStream(upstream(), adapter.NewRegistry(), adapter.FormatOpenAIResponses, adapter.FormatAnthropic, slog.Default(), nil)))
	assert.NotContains(t, types, "response.completed")
}

type countedLine struct {
	line   string
	pulled int
}

func adaptCounted(t *testing.T, lines []string, source, target adapter.Format) []countedLine {
	t.Helper()
	var pulled int
	upstream := func(yield func([]byte, error) bool) {
		for _, l := range lines {
			pulled++
			if !yield([]byte(l), nil) {
				return
			}
		}
	}
	var out []countedLine
	for line, err := range adaptStream(upstream, adapter.NewRegistry(), source, target, slog.Default(), nil) {
		require.NoError(t, err)
		out = append(out, countedLine{line: string(line), pulled: pulled})
	}
	return out
}

func lineWith(t *testing.T, lines []countedLine, marker string) countedLine {
	t.Helper()
	var found []countedLine
	for _, l := range lines {
		if strings.Contains(l.line, marker) {
			found = append(found, l)
		}
	}
	require.Len(t, found, 1, "exactly one line with %s", marker)
	return found[0]
}

func TestAdaptStream_DeferredFinishWaitsForFinalUsage(t *testing.T) {
	tests := []struct {
		name           string
		source, target adapter.Format
		lines          []string
		terminal       string
		wantPulled     int
		wantUsage      string
	}{
		{
			name: "gemini usageMetadata on every chunk", source: adapter.FormatAnthropic, target: adapter.FormatGemini,
			lines: []string{
				`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]}}],"usageMetadata":{"promptTokenCount":1000,"candidatesTokenCount":1,"totalTokenCount":1001,"cachedContentTokenCount":800}}`,
				`data: {"candidates":[{"content":{"role":"model","parts":[{"text":" there"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":1000,"candidatesTokenCount":4,"totalTokenCount":1004}}`,
				`data: {"candidates":[{"content":{"role":"model","parts":[]}}],"usageMetadata":{"promptTokenCount":1000,"candidatesTokenCount":6,"totalTokenCount":1006}}`,
			},
			terminal:   `"type":"message_delta"`,
			wantPulled: 3,
			wantUsage:  `"usage":{"input_tokens":200,"output_tokens":6,"cache_read_input_tokens":800}`,
		},
		{
			name: "anthropic message_start usage above message_delta", source: adapter.FormatOpenAIResponses, target: adapter.FormatAnthropic,
			lines: []string{
				`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude","usage":{"input_tokens":10,"output_tokens":1,"cache_read_input_tokens":1000,"cache_creation_input_tokens":300}}}`,
				`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}`,
				`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"input_tokens":4,"output_tokens":7,"cache_read_input_tokens":0}}`,
				`data: {"type":"message_stop"}`,
			},
			terminal:   `"type":"response.completed"`,
			wantPulled: 3,
			wantUsage:  `"usage":{"input_tokens":1310,"output_tokens":7,"total_tokens":1317,"input_tokens_details":{"cached_tokens":1000,"cache_write_tokens":300}}`,
		},
		{
			name: "anthropic message_start usage above message_delta to bedrock", source: adapter.FormatBedrock, target: adapter.FormatAnthropic,
			lines: []string{
				`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude","usage":{"input_tokens":10,"output_tokens":1,"cache_read_input_tokens":1000}}}`,
				`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"input_tokens":4,"output_tokens":7,"cache_read_input_tokens":0}}`,
				`data: {"type":"message_stop"}`,
			},
			terminal:   `"metadata"`,
			wantPulled: 2,
			wantUsage:  `"usage":{"inputTokens":10,"outputTokens":7,"totalTokens":1017,"cacheReadInputTokens":1000}`,
		},
		{
			name: "openai finish chunk with usage then a usage chunk", source: adapter.FormatAnthropic, target: adapter.FormatOpenAI,
			lines: []string{
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":20,"completion_tokens":1,"total_tokens":21}}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":20,"completion_tokens":9,"total_tokens":29}}`,
				`: ping`,
			},
			terminal:   `"type":"message_delta"`,
			wantPulled: 3,
			wantUsage:  `"usage":{"input_tokens":20,"output_tokens":9}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flushed := lineWith(t, adaptCounted(t, tt.lines, tt.source, tt.target), tt.terminal)

			assert.Equal(t, tt.wantPulled, flushed.pulled)
			assert.Contains(t, flushed.line, tt.wantUsage)
		})
	}
}

func TestAdaptStream_DeferredFinishDropsChunksAfterFlush(t *testing.T) {
	tests := []struct {
		name           string
		source, target adapter.Format
		lines          []string
		terminal       string
	}{
		{
			name: "anthropic content and usage after message_delta", source: adapter.FormatOpenAIResponses, target: adapter.FormatAnthropic,
			lines: []string{
				`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude","usage":{"input_tokens":10,"output_tokens":1}}}`,
				`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}`,
				`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"late"}}`,
				`data: {"type":"message_delta","delta":{},"usage":{"output_tokens":99}}`,
				`data: {"type":"message_stop"}`,
			},
			terminal: `"type":"response.completed"`,
		},
		{
			name: "bedrock content and usage after metadata", source: adapter.FormatAnthropic, target: adapter.FormatBedrock,
			lines: []string{
				`data: {"messageStart":{"role":"assistant"}}`,
				`data: {"messageStop":{"stopReason":"end_turn"}}`,
				`data: {"metadata":{"usage":{"inputTokens":10,"outputTokens":7,"totalTokens":17}}}`,
				`data: {"contentBlockDelta":{"contentBlockIndex":0,"delta":{"text":"late"}}}`,
				`data: {"metadata":{"usage":{"inputTokens":10,"outputTokens":99,"totalTokens":109}}}`,
			},
			terminal: `"type":"message_stop"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := adaptCounted(t, tt.lines, tt.source, tt.target)

			var data []string
			for _, l := range lines {
				if strings.HasPrefix(l.line, "data: ") {
					data = append(data, l.line)
				}
			}
			require.NotEmpty(t, data)
			assert.Contains(t, data[len(data)-1], tt.terminal, "nothing follows the terminal event")
			joined := strings.Join(data, "\n")
			assert.NotContains(t, joined, "late")
			assert.NotContains(t, joined, "99")
		})
	}
}

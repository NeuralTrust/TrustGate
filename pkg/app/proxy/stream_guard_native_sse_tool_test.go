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
	"context"
	"iter"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func sseEvent(eventType string, fields map[string]any) []string {
	fields["type"] = eventType
	return []string{"event: " + eventType, sseData(fields), ""}
}

func joinEvents(events ...[]string) []string {
	var out []string
	for _, e := range events {
		out = append(out, e...)
	}
	return out
}

func responsesTextPrelude() []string {
	return sseEvent("response.output_text.delta", map[string]any{"output_index": 0, "content_index": 0, "delta": "Ready."})
}

func responsesCompleted() []string {
	return sseEvent("response.completed", map[string]any{"response": map[string]any{}})
}

func customItem(status, input string) map[string]any {
	return map[string]any{"id": "ctc_1", "call_id": "call_1", "type": "custom_tool_call", "name": "shell", "input": input, "status": status}
}

func customAdded(input string) []string {
	return sseEvent("response.output_item.added", map[string]any{"output_index": 1, "item": customItem("in_progress", input)})
}

func customDelta(delta string) []string {
	return sseEvent("response.custom_tool_call_input.delta", map[string]any{"output_index": 1, "item_id": "ctc_1", "delta": delta})
}

func customInputDone(input string) []string {
	return sseEvent("response.custom_tool_call_input.done", map[string]any{"output_index": 1, "item_id": "ctc_1", "input": input})
}

func customItemDone(input string) []string {
	return sseEvent("response.output_item.done", map[string]any{"output_index": 1, "item": customItem("completed", input)})
}

func runNativeSSEGuard(t *testing.T, runner segmentRunner, format adapter.Format, src iter.Seq2[[]byte, error], cfg streamGuardConfig) (*streamGuard, []string) {
	t.Helper()
	cfg.holdNativeTools = true
	g := newStreamGuard(runner, adapter.NewRegistry(), format, stageInputFixture(), cfg, newGuardLogger())
	out, pe := g.Run(context.Background(), src)
	require.Nil(t, pe)
	got, err := collectGuardOutput(t, g, out)
	require.NoError(t, err)
	return g, got
}

func sliceSource(lines []string) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		for _, line := range lines {
			if !yield([]byte(line), nil) {
				return
			}
		}
	}
}

// assertCustomCallInspected checks the guard was shown the whole input: as the
// text of the call's own inspection, or as a custom call of a segment.
func assertCustomCallInspected(t *testing.T, runner *toolGuardStub, input string) {
	t.Helper()
	for _, seg := range runner.segments {
		if seg.Text == input {
			return
		}
		for _, tc := range seg.ToolCalls {
			if tc.Arguments == input {
				assert.Equal(t, adapter.ToolKindCustom, tc.Kind)
				return
			}
		}
	}
	t.Fatalf("no segment carried the custom tool call with input %q", input)
}

// A custom tool's free-form input is held and inspected whichever events carry
// it, on a native Responses stream.
func TestStreamGuard_NativeSSECustomToolInputOnEveryCarrier(t *testing.T) {
	const input = "echo hello && rm -rf /"
	half := len(input) / 2
	cases := []struct {
		name  string
		lines []string
	}{
		{
			name: "input deltas",
			lines: joinEvents(responsesTextPrelude(), customAdded(""), customDelta(input[:half]), customDelta(input[half:]),
				customInputDone(input), customItemDone(input), responsesCompleted()),
		},
		{
			name:  "input done only",
			lines: joinEvents(responsesTextPrelude(), customAdded(""), customInputDone(input), customItemDone(input), responsesCompleted()),
		},
		{
			name:  "output item done only",
			lines: joinEvents(responsesTextPrelude(), customAdded(""), customItemDone(input), responsesCompleted()),
		},
		{
			name:  "output item added",
			lines: joinEvents(responsesTextPrelude(), customAdded(input), customInputDone(input), customItemDone(input), responsesCompleted()),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &toolGuardStub{pattern: "rm -rf"}
			g, got := runNativeSSEGuard(t, runner, adapter.FormatOpenAIResponses, sliceSource(tc.lines),
				streamGuardConfig{headChars: 5, minChars: 8})
			assert.True(t, g.wasCut())
			assert.NotContains(t, strings.Join(got, "\n"), "rm -rf")
			assertCustomCallInspected(t, runner, input)
		})
	}
}

func TestStreamGuard_NativeSSECustomToolAllowedVerbatim(t *testing.T) {
	const input = "ls -la /tmp/report"
	lines := joinEvents(responsesTextPrelude(), customAdded(""), customDelta(input[:5]), customDelta(input[5:]),
		customInputDone(input), customItemDone(input), responsesCompleted())
	runner := &toolGuardStub{pattern: "rm -rf"}
	g, got := runNativeSSEGuard(t, runner, adapter.FormatOpenAIResponses, sliceSource(lines),
		streamGuardConfig{headChars: 5, minChars: 8})
	assert.False(t, g.wasCut())
	assert.Equal(t, lines, got)
	assertCustomCallInspected(t, runner, input)
}

// The full input a boundary event states is what a client runs, so one that
// disagrees with the deltas the guard inspected is refused.
func TestStreamGuard_NativeSSECustomToolSnapshotMismatchRefused(t *testing.T) {
	cases := map[string][]string{
		"input done": joinEvents(responsesTextPrelude(), customAdded(""), customDelta("ls -la"),
			customInputDone("rm -rf /"), customItemDone("rm -rf /"), responsesCompleted()),
		"output item done": joinEvents(responsesTextPrelude(), customAdded(""), customDelta("ls -la"),
			customInputDone("ls -la"), customItemDone("rm -rf /"), responsesCompleted()),
	}
	for name, lines := range cases {
		t.Run(name, func(t *testing.T) {
			g, got := runNativeSSEGuard(t, &toolGuardStub{}, adapter.FormatOpenAIResponses, sliceSource(lines),
				streamGuardConfig{headChars: 5, minChars: 8, onError: streamFailOpen})
			assert.True(t, g.wasCut())
			assert.Equal(t, streamToolArgsMessage, g.cutMessage)
			assert.NotContains(t, strings.Join(got, "\n"), "rm -rf")
		})
	}
}

// A Responses client of a chat upstream gets custom tool calls re-encoded as
// custom_tool_call items, which the guard holds and inspects the same way.
func TestStreamGuard_CrossFormatCustomToolCall(t *testing.T) {
	upstream := func(input string) iter.Seq2[[]byte, error] {
		return linesSeq(
			`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"Running."}}]}`,
			sseData(map[string]any{"id": "c", "model": "gpt", "object": "chat.completion.chunk", "choices": []any{map[string]any{"index": 0, "delta": map[string]any{
				"tool_calls": []any{map[string]any{"index": 0, "id": "call_1", "type": "custom", "custom": map[string]any{"name": "shell", "input": input}}},
			}}}}),
			`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
			`data: [DONE]`,
		)
	}
	adapted := func(input string) iter.Seq2[[]byte, error] {
		return adaptStream(upstream(input), adapter.NewRegistry(), adapter.FormatOpenAIResponses, adapter.FormatOpenAI, slog.Default(), nil)
	}

	t.Run("blocked", func(t *testing.T) {
		const input = "echo hello && rm -rf /"
		runner := &toolGuardStub{pattern: "rm -rf"}
		g, got := runNativeSSEGuard(t, runner, adapter.FormatOpenAIResponses, adapted(input),
			streamGuardConfig{headChars: 5, minChars: 8})
		assert.True(t, g.wasCut())
		assert.NotContains(t, strings.Join(got, "\n"), "rm -rf")
		assertCustomCallInspected(t, runner, input)
	})

	t.Run("allowed", func(t *testing.T) {
		const input = "ls -la /tmp/report"
		runner := &toolGuardStub{pattern: "rm -rf"}
		g, got := runNativeSSEGuard(t, runner, adapter.FormatOpenAIResponses, adapted(input),
			streamGuardConfig{headChars: 5, minChars: 8})
		assert.False(t, g.wasCut())
		assert.Contains(t, strings.Join(got, "\n"), `"type":"response.custom_tool_call_input.delta"`)
		assertCustomCallInspected(t, runner, input)
	})
}

// A client-executed item whose input the guard cannot read is refused rather
// than released, whichever event names it.
func TestStreamGuard_NativeSSEUnreadableToolItemRefused(t *testing.T) {
	item := func(kind, status string) map[string]any {
		return map[string]any{"id": "it_1", "call_id": "call_1", "type": kind, "status": status,
			"action": map[string]any{"type": "exec", "command": []string{"rm", "-rf", "/"}}}
	}
	for _, kind := range []string{"local_shell_call", "computer_call", "shell_call"} {
		t.Run(kind, func(t *testing.T) {
			full := joinEvents(responsesTextPrelude(),
				sseEvent("response.output_item.added", map[string]any{"output_index": 1, "item": item(kind, "in_progress")}),
				sseEvent("response.output_item.done", map[string]any{"output_index": 1, "item": item(kind, "completed")}),
				responsesCompleted())
			doneOnly := joinEvents(responsesTextPrelude(),
				sseEvent("response.output_item.done", map[string]any{"output_index": 1, "item": item(kind, "completed")}),
				responsesCompleted())
			for name, lines := range map[string][]string{"added and done": full, "done only": doneOnly} {
				t.Run(name, func(t *testing.T) {
					g, got := runNativeSSEGuard(t, &toolGuardStub{}, adapter.FormatOpenAIResponses, sliceSource(lines),
						streamGuardConfig{headChars: 5, minChars: 8, onError: streamFailOpen})
					assert.True(t, g.wasCut())
					assert.Equal(t, streamToolUnreadableMessage, g.cutMessage)
					assert.NotContains(t, strings.Join(got, "\n"), kind)
				})
			}
		})
	}

	t.Run("at the head", func(t *testing.T) {
		lines := joinEvents(
			sseEvent("response.output_item.added", map[string]any{"output_index": 0, "item": item("local_shell_call", "in_progress")}),
			responsesCompleted())
		g := newStreamGuard(&toolGuardStub{}, adapter.NewRegistry(), adapter.FormatOpenAIResponses, stageInputFixture(),
			streamGuardConfig{headChars: 4096, holdNativeTools: true}, newGuardLogger())
		_, pe := g.Run(context.Background(), sliceSource(lines))
		require.NotNil(t, pe)
		assert.Equal(t, streamUnverifiableType, pe.Type)
		assert.Equal(t, streamToolUnreadableMessage, pe.Message)
	})

	t.Run("a hosted call is not refused", func(t *testing.T) {
		lines := joinEvents(responsesTextPrelude(),
			sseEvent("response.output_item.added", map[string]any{"output_index": 1, "item": map[string]any{"id": "ws_1", "type": "web_search_call", "status": "in_progress"}}),
			sseEvent("response.output_item.done", map[string]any{"output_index": 1, "item": map[string]any{"id": "ws_1", "type": "web_search_call", "status": "completed"}}),
			responsesCompleted())
		g, got := runNativeSSEGuard(t, &toolGuardStub{}, adapter.FormatOpenAIResponses, sliceSource(lines),
			streamGuardConfig{headChars: 5, minChars: 8})
		assert.False(t, g.wasCut())
		assert.Equal(t, lines, got)
	})
}

// The input of an Anthropic server_tool_use or mcp_tool_use block can arrive
// whole on content_block_start, which the decoder does not surface as a call.
func TestStreamGuard_NativeSSEAnthropicToolStartInputInspected(t *testing.T) {
	const args = `{"command":"rm -rf /"}`
	for _, blockType := range []string{"mcp_tool_use", "server_tool_use"} {
		t.Run(blockType, func(t *testing.T) {
			lines := []string{
				"event: content_block_start",
				`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`, "",
				"event: content_block_delta",
				`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Ready."}}`, "",
				"event: content_block_stop",
				`data: {"type":"content_block_stop","index":0}`, "",
				"event: content_block_start",
				`data: {"type":"content_block_start","index":1,"content_block":{"type":"` + blockType + `","id":"mcptoolu_1","name":"run_shell","server_name":"ops","input":` + args + `}}`, "",
				"event: content_block_stop",
				`data: {"type":"content_block_stop","index":1}`, "",
				"event: message_stop",
				`data: {"type":"message_stop"}`, "",
			}
			runner := &toolGuardStub{pattern: "rm -rf"}
			g, got := runNativeSSEGuard(t, runner, adapter.FormatAnthropic, sliceSource(lines),
				streamGuardConfig{headChars: 5, minChars: 8})
			assert.True(t, g.wasCut())
			assert.NotContains(t, strings.Join(got, "\n"), "rm -rf")
		})
	}
}

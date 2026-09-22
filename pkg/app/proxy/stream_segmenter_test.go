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
	"errors"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/require"
)

type segmenterFixture struct {
	name      string
	format    adapter.Format
	lines     []string
	wantUnits []streamUnit
	wantText  string
}

func segmenterFixtures() []segmenterFixture {
	return []segmenterFixture{
		{
			name:   "openai chat",
			format: adapter.FormatOpenAI,
			lines: []string{
				`data: {"id":"c1","model":"gpt-5","choices":[{"index":0,"delta":{"role":"assistant"}}]}`, "",
				`data: {"id":"c1","choices":[{"index":0,"delta":{"content":"Hello"}}]}`, "",
				`data: {"id":"c1","choices":[{"index":0,"delta":{"content":" world"}}]}`, "",
				`data: {"id":"c1","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`, "",
				`data: {"id":"c1","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}`, "",
				"data: [DONE]", "",
			},
			wantUnits: []streamUnit{unitOpaque, unitText, unitText, unitTerminal, unitUsage, unitTerminal},
			wantText:  "Hello world",
		},
		{
			name:   "openrouter keepalive comment",
			format: adapter.FormatOpenRouter,
			lines: []string{
				": OPENROUTER PROCESSING", "",
				`data: {"id":"c2","choices":[{"index":0,"delta":{"content":"ok"}}]}`, "",
			},
			wantUnits: []streamUnit{unitOpaque, unitOpaque, unitText},
			wantText:  "ok",
		},
		{
			name:   "blank separator with an empty buffer",
			format: adapter.FormatOpenAI,
			lines: []string{
				`data: {"id":"c5","choices":[{"index":0,"delta":{"content":"a"}}]}`, "", "",
				"data: [DONE]", "",
			},
			wantUnits: []streamUnit{unitText, unitOpaque, unitTerminal},
			wantText:  "a",
		},
		{
			name:   "groq provider extension",
			format: adapter.FormatGroq,
			lines: []string{
				`data: {"id":"c3","choices":[{"index":0,"delta":{"content":"hi"}}]}`, "",
				`data: {"id":"c3","choices":[],"x_groq":{"id":"req_1"}}`, "",
			},
			wantUnits: []streamUnit{unitText, unitOpaque},
			wantText:  "hi",
		},
		{
			name:   "anthropic multi-line events",
			format: adapter.FormatAnthropic,
			lines: []string{
				"event: message_start",
				`data: {"type":"message_start","message":{"id":"msg_1","model":"claude-sonnet-4"}}`, "",
				"event: ping",
				`data: {"type":"ping"}`, "",
				"event: content_block_start",
				`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`, "",
				"event: content_block_delta",
				`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hola"}}`, "",
				"event: content_block_delta",
				`data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"hmm"}}`, "",
				"event: message_delta",
				`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":4}}`, "",
				"event: message_stop",
				`data: {"type":"message_stop"}`, "",
			},
			wantUnits: []streamUnit{unitOpaque, unitOpaque, unitOpaque, unitText, unitText, unitUsage, unitTerminal},
			wantText:  "Hola",
		},
		{
			name:   "anthropic error event ends the stream",
			format: adapter.FormatAnthropic,
			lines: []string{
				"event: content_block_delta",
				`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"half"}}`, "",
				"event: error",
				`data: {"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`, "",
			},
			wantUnits: []streamUnit{unitText, unitTerminal},
			wantText:  "half",
		},
		{
			name:   "cohere multi-line events",
			format: adapter.FormatCohere,
			lines: []string{
				"event: content-delta",
				`data: {"type":"content-delta","index":0,"delta":{"message":{"content":{"text":"Hi"}}}}`, "",
				"event: message-end",
				`data: {"type":"message-end","delta":{"finish_reason":"COMPLETE","usage":{"tokens":{"input_tokens":1,"output_tokens":2}}}}`, "",
			},
			wantUnits: []streamUnit{unitText, unitTerminal},
			wantText:  "Hi",
		},
		{
			name:   "openai responses multi-line events",
			format: adapter.FormatOpenAIResponses,
			lines: []string{
				"event: response.output_item.added",
				`data: {"type":"response.output_item.added","output_index":0,"item":{"type":"message","role":"assistant","id":"m1"}}`, "",
				"event: response.output_text.delta",
				`data: {"type":"response.output_text.delta","output_index":0,"delta":"Hey"}`, "",
				"event: response.completed",
				`data: {"type":"response.completed","response":{"id":"resp_1","model":"gpt-5"}}`, "",
			},
			wantUnits: []streamUnit{unitOpaque, unitText, unitTerminal},
			wantText:  "Hey",
		},
		{
			name:   "openai responses tool call before the response ends",
			format: adapter.FormatOpenAIResponses,
			lines: []string{
				"event: response.output_item.added",
				`data: {"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"get_weather"}}`, "",
				"event: response.function_call_arguments.delta",
				`data: {"type":"response.function_call_arguments.delta","output_index":0,"delta":"{\"city\":"}`, "",
				"event: response.function_call_arguments.delta",
				`data: {"type":"response.function_call_arguments.delta","output_index":0,"delta":"\"Paris\"}"}`, "",
				"event: response.function_call_arguments.done",
				`data: {"type":"response.function_call_arguments.done","output_index":0,"arguments":"{\"city\":\"Paris\"}"}`, "",
				"event: response.output_text.delta",
				`data: {"type":"response.output_text.delta","output_index":1,"delta":"Sunny in Paris"}`, "",
				"event: response.completed",
				`data: {"type":"response.completed","response":{"id":"resp_2","model":"gpt-5"}}`, "",
			},
			wantUnits: []streamUnit{unitText, unitText, unitText, unitText, unitText, unitTerminal},
			wantText:  "Sunny in Paris",
		},
		{
			name:   "openai responses error event ends the stream",
			format: adapter.FormatOpenAIResponses,
			lines: []string{
				"event: response.output_text.delta",
				`data: {"type":"response.output_text.delta","output_index":0,"delta":"par"}`, "",
				"event: error",
				`data: {"type":"error","code":"server_error","message":"boom"}`, "",
			},
			wantUnits: []streamUnit{unitText, unitTerminal},
			wantText:  "par",
		},
		{
			name:   "gemini single-line events",
			format: adapter.FormatGemini,
			lines: []string{
				`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"Bonjour"}]}}]}`, "",
				`data: {"candidates":[{"content":{"parts":[]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":2,"totalTokenCount":3}}`, "",
			},
			wantUnits: []streamUnit{unitText, unitTerminal},
			wantText:  "Bonjour",
		},
	}
}

func TestSegmenter_ClassifiesEventsAndPreservesBytes(t *testing.T) {
	t.Parallel()
	for _, fixture := range segmenterFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			t.Parallel()
			seg := newSegmenter(adapter.NewRegistry(), fixture.format)

			var units []streamUnit
			var text string
			var replay []string
			for _, line := range fixture.lines {
				ev, err := seg.feed([]byte(line))
				require.NoError(t, err)
				if ev == nil {
					continue
				}
				units = append(units, ev.unit)
				text += ev.text
				for _, l := range ev.lines {
					replay = append(replay, string(l))
				}
			}
			trailing, err := seg.flush()
			require.NoError(t, err)
			require.Nil(t, trailing, "every fixture ends on a separator")

			require.Equal(t, fixture.wantUnits, units)
			require.Equal(t, fixture.wantText, text)
			require.Equal(t, fixture.lines, replay, "released lines must reproduce the input byte for byte")
		})
	}
}

// TestSegmenter_ResponsesToolCallDoneIsNotTerminal pins the rule that keeps the
// guard alive past the first tool call. response.function_call_arguments.done
// decodes to FinishReason "tool_calls" and is emitted once per call before
// response.completed, so a finish-reason-means-terminal rule would mark the
// first tool call final and leave everything after it uninspected.
func TestSegmenter_ResponsesToolCallDoneIsNotTerminal(t *testing.T) {
	t.Parallel()
	seg := newSegmenter(adapter.NewRegistry(), adapter.FormatOpenAIResponses)

	_, err := seg.feed([]byte("event: response.function_call_arguments.done"))
	require.NoError(t, err)
	_, err = seg.feed([]byte(`data: {"type":"response.function_call_arguments.done","output_index":0,"arguments":"{}"}`))
	require.NoError(t, err)
	ev, err := seg.feed([]byte(""))
	require.NoError(t, err)
	require.NotNil(t, ev)

	require.Equal(t, unitText, ev.unit, "a tool call closing is not the response ending")
}

func TestSegmenter_FlushClosesAnEventLeftOpen(t *testing.T) {
	t.Parallel()
	seg := newSegmenter(adapter.NewRegistry(), adapter.FormatAnthropic)

	ev, err := seg.feed([]byte("event: content_block_delta"))
	require.NoError(t, err)
	require.Nil(t, ev)
	ev, err = seg.feed([]byte(`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"tail"}}`))
	require.NoError(t, err)
	require.Nil(t, ev, "the event is still open without its separator")

	ev, err = seg.flush()
	require.NoError(t, err)
	require.NotNil(t, ev)
	require.Equal(t, unitText, ev.unit)
	require.Equal(t, "tail", ev.text)
	require.Len(t, ev.lines, 2)
}

func TestSegmenter_ReasoningAndToolCallsAreHeldWithTheirBlock(t *testing.T) {
	t.Parallel()
	seg := newSegmenter(adapter.NewRegistry(), adapter.FormatOpenAI)

	line := `data: {"id":"c","choices":[{"index":0,"delta":{"reasoning_content":"why","tool_calls":[{"index":0,"id":"call_1","function":{"name":"f","arguments":"{\"a\":1}"}}]}}]}`
	_, err := seg.feed([]byte(line))
	require.NoError(t, err)
	ev, err := seg.feed([]byte(""))
	require.NoError(t, err)
	require.NotNil(t, ev)

	require.Equal(t, unitText, ev.unit)
	require.Equal(t, "why", ev.reasoning)
	require.Len(t, ev.toolCalls, 1)
	require.Equal(t, len("why")+len(`{"a":1}`), ev.chars())
}

type failingCodec struct{}

func (failingCodec) DecodeStreamChunkFor([]byte, adapter.Format) (*adapter.CanonicalStreamChunk, error) {
	return nil, errors.New("no adapter")
}

// The encode direction stays real: a stream the codec cannot decode is still
// owed an honest terminator when the guard cuts it.
func (failingCodec) EncodeStreamChunkFor(
	canonical *adapter.CanonicalStreamChunk,
	source adapter.Format,
) ([][]byte, error) {
	return adapter.NewRegistry().EncodeStreamChunkFor(canonical, source)
}

func TestSegmenter_DecodeFailureStillYieldsTheEvent(t *testing.T) {
	t.Parallel()
	seg := newSegmenter(failingCodec{}, adapter.FormatOpenAI)

	_, err := seg.feed([]byte(`data: {"choices":[{"delta":{"content":"x"}}]}`))
	require.NoError(t, err)
	ev, err := seg.feed([]byte(""))

	require.Error(t, err)
	require.NotNil(t, ev, "the caller must still be able to release the original lines")
	require.Equal(t, unitOpaque, ev.unit)
	require.Len(t, ev.lines, 2)
}

type fakeBlockClock struct {
	now  time.Time
	idle bool
}

func (c *fakeBlockClock) Now() time.Time  { return c.now }
func (c *fakeBlockClock) GuardIdle() bool { return c.idle }

func TestBlockGate_CloseTriggers(t *testing.T) {
	t.Parallel()
	base := time.Unix(0, 0)
	tests := []struct {
		name    string
		event   *streamEvent
		idle    bool
		elapsed time.Duration
		want    bool
	}{
		{
			name:  "terminal closes even mid-call",
			event: &streamEvent{unit: unitTerminal},
		},
		{
			name:  "floor reached while the guard is idle",
			event: &streamEvent{unit: unitText, text: "0123456789"},
			idle:  true,
			want:  true,
		},
		{
			name:  "floor reached but a call is still in flight",
			event: &streamEvent{unit: unitText, text: "0123456789"},
		},
		{
			name:  "below the floor with the guard idle",
			event: &streamEvent{unit: unitText, text: "short"},
			idle:  true,
		},
		{
			name:    "ceiling closes a block a call in flight would hold",
			event:   &streamEvent{unit: unitText, text: "short"},
			elapsed: 800 * time.Millisecond,
			want:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			clock := &fakeBlockClock{now: base, idle: tt.idle}
			gate := newBlockGate(clock, 10, 800*time.Millisecond)

			gate.admit(tt.event)
			clock.now = base.Add(tt.elapsed)

			if tt.event.unit == unitTerminal {
				require.True(t, gate.shouldClose(tt.event))
				return
			}
			require.Equal(t, tt.want, gate.shouldClose(tt.event))

			gate.reset()
			require.False(t, gate.shouldClose(tt.event), "a reset block is empty and cannot close")
		})
	}
}

// TestBlockGate_ZeroMaxHoldIsClamped covers the degenerate ceiling: an
// unclamped zero would satisfy elapsed >= maxHold on the first event and turn
// the block loop into one guard call per event.
func TestBlockGate_ZeroMaxHoldIsClamped(t *testing.T) {
	t.Parallel()
	base := time.Unix(0, 0)
	clock := &fakeBlockClock{now: base}
	gate := newBlockGate(clock, 10, 0)
	ev := &streamEvent{unit: unitText, text: "short"}

	gate.admit(ev)
	require.False(t, gate.shouldClose(ev), "a zero ceiling must not close the block it just opened")

	clock.now = base.Add(minBlockMaxHold)
	require.True(t, gate.shouldClose(ev), "the clamped ceiling still closes the block")
}

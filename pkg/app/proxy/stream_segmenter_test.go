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
	"testing"

	"github.com/stretchr/testify/require"
)

type segmenterFixture struct {
	name  string
	lines []string
}

func segmenterFixtures() []segmenterFixture {
	return []segmenterFixture{
		{
			name: "openai chat",
			lines: []string{
				`data: {"id":"c1","model":"gpt-5","choices":[{"index":0,"delta":{"role":"assistant"}}]}`, "",
				`data: {"id":"c1","choices":[{"index":0,"delta":{"content":"Hello"}}]}`, "",
				`data: {"id":"c1","choices":[{"index":0,"delta":{"content":" world"}}]}`, "",
				`data: {"id":"c1","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`, "",
				`data: {"id":"c1","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}`, "",
				"data: [DONE]", "",
			},
		},
		{
			name: "openrouter keepalive comment",
			lines: []string{
				": OPENROUTER PROCESSING", "",
				`data: {"id":"c2","choices":[{"index":0,"delta":{"content":"ok"}}]}`, "",
			},
		},
		{
			name: "blank separator with an empty buffer",
			lines: []string{
				`data: {"id":"c5","choices":[{"index":0,"delta":{"content":"a"}}]}`, "", "",
				"data: [DONE]", "",
			},
		},
		{
			name: "groq provider extension",
			lines: []string{
				`data: {"id":"c3","choices":[{"index":0,"delta":{"content":"hi"}}]}`, "",
				`data: {"id":"c3","choices":[],"x_groq":{"id":"req_1"}}`, "",
			},
		},
		{
			name: "anthropic multi-line events",
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
		},
		{
			name: "anthropic error event ends the stream",
			lines: []string{
				"event: content_block_delta",
				`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"half"}}`, "",
				"event: error",
				`data: {"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`, "",
			},
		},
		{
			name: "cohere multi-line events",
			lines: []string{
				"event: content-delta",
				`data: {"type":"content-delta","index":0,"delta":{"message":{"content":{"text":"Hi"}}}}`, "",
				"event: message-end",
				`data: {"type":"message-end","delta":{"finish_reason":"COMPLETE","usage":{"tokens":{"input_tokens":1,"output_tokens":2}}}}`, "",
			},
		},
		{
			name: "openai responses multi-line events",
			lines: []string{
				"event: response.output_item.added",
				`data: {"type":"response.output_item.added","output_index":0,"item":{"type":"message","role":"assistant","id":"m1"}}`, "",
				"event: response.output_text.delta",
				`data: {"type":"response.output_text.delta","output_index":0,"delta":"Hey"}`, "",
				"event: response.completed",
				`data: {"type":"response.completed","response":{"id":"resp_1","model":"gpt-5"}}`, "",
			},
		},
		{
			name: "openai responses tool call before the response ends",
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
		},
		{
			name: "openai responses error event ends the stream",
			lines: []string{
				"event: response.output_text.delta",
				`data: {"type":"response.output_text.delta","output_index":0,"delta":"par"}`, "",
				"event: error",
				`data: {"type":"error","code":"server_error","message":"boom"}`, "",
			},
		},
		{
			name: "gemini single-line events",
			lines: []string{
				`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"Bonjour"}]}}]}`, "",
				`data: {"candidates":[{"content":{"parts":[]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":2,"totalTokenCount":3}}`, "",
			},
		},
	}
}

func TestSegmenter_PreservesBytes(t *testing.T) {
	t.Parallel()
	for _, fixture := range segmenterFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			t.Parallel()
			seg := newSegmenter()

			var replay []string
			for _, line := range fixture.lines {
				ev := seg.feed([]byte(line))
				if ev == nil {
					continue
				}
				for _, l := range ev.lines {
					replay = append(replay, string(l))
				}
			}
			require.Nil(t, seg.flush(), "every fixture ends on a separator")

			require.Equal(t, fixture.lines, replay, "released lines must reproduce the input byte for byte")
		})
	}
}

func TestSegmenter_FlushClosesAnEventLeftOpen(t *testing.T) {
	t.Parallel()
	seg := newSegmenter()

	require.Nil(t, seg.feed([]byte("event: content_block_delta")))
	require.Nil(t,
		seg.feed([]byte(`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"tail"}}`)),
		"the event is still open without its separator")

	ev := seg.flush()
	require.NotNil(t, ev)
	require.Len(t, ev.lines, 2)
	require.Nil(t, seg.flush(), "flush leaves nothing stranded")
}

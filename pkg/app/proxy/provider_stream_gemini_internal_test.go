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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

type geminiClientPart struct {
	Text         string `json:"text"`
	FunctionCall *struct {
		ID   string          `json:"id"`
		Name string          `json:"name"`
		Args json.RawMessage `json:"args"`
	} `json:"functionCall"`
}

type geminiClientError struct {
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error"`
}

type geminiClientChunk struct {
	Candidates []struct {
		Content struct {
			Role  string             `json:"role"`
			Parts []geminiClientPart `json:"parts"`
		} `json:"content"`
		FinishReason string `json:"finishReason"`
	} `json:"candidates"`
	UsageMetadata json.RawMessage `json:"usageMetadata"`
}

type geminiClientStream struct {
	chunks []geminiClientChunk
	parts  []string
	errors []geminiClientError
}

func decodeGeminiClientStream(t *testing.T, lines []string) geminiClientStream {
	t.Helper()
	var s geminiClientStream
	for _, line := range lines {
		payload, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		var e geminiClientError
		require.NoError(t, json.Unmarshal([]byte(payload), &e), payload)
		if e.Error != nil {
			s.errors = append(s.errors, e)
			continue
		}
		require.Empty(t, s.errors, "nothing follows the error object")
		var c geminiClientChunk
		require.NoError(t, json.Unmarshal([]byte(payload), &c), payload)
		require.Len(t, c.Candidates, 1)
		s.chunks = append(s.chunks, c)
		for _, p := range c.Candidates[0].Content.Parts {
			switch {
			case p.FunctionCall != nil:
				args := string(p.FunctionCall.Args)
				if args == "" {
					args = "{}"
				}
				s.parts = append(s.parts, "call "+p.FunctionCall.Name+" "+compactJSON(t, args))
			case p.Text != "":
				s.parts = append(s.parts, "text "+p.Text)
			}
		}
	}
	return s
}

func compactJSON(t *testing.T, raw string) string {
	t.Helper()
	var v any
	require.NoError(t, json.Unmarshal([]byte(raw), &v))
	out, err := json.Marshal(v)
	require.NoError(t, err)
	return string(out)
}

// assertOneFinishLast checks the finish and usageMetadata ride once, on the
// last chunk, and that no functionCall arrives in more than one piece.
func (s geminiClientStream) assertOneFinishLast(t *testing.T, reason string) geminiClientChunk {
	t.Helper()
	require.NotEmpty(t, s.chunks)
	for _, c := range s.chunks[:len(s.chunks)-1] {
		assert.Empty(t, c.Candidates[0].FinishReason, "the finish is sent once")
		assert.Empty(t, c.UsageMetadata, "usageMetadata is sent once")
	}
	last := s.chunks[len(s.chunks)-1]
	assert.Equal(t, reason, last.Candidates[0].FinishReason)
	return last
}

func adaptGemini(t *testing.T, target adapter.Format, lines ...string) geminiClientStream {
	t.Helper()
	return decodeGeminiClientStream(t, collectLines(t, adaptStream(linesSeq(lines...), adapter.NewRegistry(), adapter.FormatGemini, target, slog.Default(), nil)))
}

func TestAdaptStream_GeminiClientGetsWholeFunctionCallArgs(t *testing.T) {
	tests := []struct {
		name      string
		target    adapter.Format
		lines     []string
		wantParts []string
		wantUsage string
	}{
		{
			name:   "bedrock converse nova",
			target: adapter.FormatBedrock,
			lines: []string{
				`data: {"messageStart":{"role":"assistant"}}`,
				`data: {"contentBlockDelta":{"contentBlockIndex":0,"delta":{"text":"Let me look "}}}`,
				`data: {"contentBlockDelta":{"contentBlockIndex":0,"delta":{"text":"that up."}}}`,
				`data: {"contentBlockStop":{"contentBlockIndex":0}}`,
				`data: {"contentBlockStart":{"contentBlockIndex":1,"start":{"toolUse":{"toolUseId":"tooluse_a","name":"web_search"}}}}`,
				`data: {"contentBlockDelta":{"contentBlockIndex":1,"delta":{"toolUse":{"input":"{\"que"}}}}`,
				`data: {"contentBlockDelta":{"contentBlockIndex":1,"delta":{"toolUse":{"input":"ry\":\"weather in "}}}}`,
				`data: {"contentBlockDelta":{"contentBlockIndex":1,"delta":{"toolUse":{"input":"Paris\"}"}}}}`,
				`data: {"contentBlockStop":{"contentBlockIndex":1}}`,
				`data: {"contentBlockStart":{"contentBlockIndex":2,"start":{"toolUse":{"toolUseId":"tooluse_b","name":"get_time"}}}}`,
				`data: {"contentBlockDelta":{"contentBlockIndex":2,"delta":{"toolUse":{"input":"{\"tz\":"}}}}`,
				`data: {"contentBlockDelta":{"contentBlockIndex":2,"delta":{"toolUse":{"input":"\"Europe/Paris\"}"}}}}`,
				`data: {"contentBlockStop":{"contentBlockIndex":2}}`,
				`data: {"messageStop":{"stopReason":"tool_use"}}`,
				`data: {"metadata":{"usage":{"inputTokens":120,"outputTokens":40,"totalTokens":160},"metrics":{"latencyMs":800}}}`,
			},
			wantParts: []string{
				"text Let me look ",
				"text that up.",
				`call web_search {"query":"weather in Paris"}`,
				`call get_time {"tz":"Europe/Paris"}`,
			},
			wantUsage: `{"promptTokenCount":120,"candidatesTokenCount":40,"totalTokenCount":160}`,
		},
		{
			name:   "anthropic input_json_delta",
			target: adapter.FormatAnthropic,
			lines: []string{
				`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude","usage":{"input_tokens":50,"output_tokens":1}}}`,
				`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
				`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Checking."}}`,
				`data: {"type":"content_block_stop","index":0}`,
				`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"web_search","input":{}}}`,
				`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":""}}`,
				`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"query\": \"wea"}}`,
				`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"ther\"}"}}`,
				`data: {"type":"content_block_stop","index":1}`,
				`data: {"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_2","name":"get_time","input":{}}}`,
				`data: {"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"tz\": \"UTC\"}"}}`,
				`data: {"type":"content_block_stop","index":2}`,
				`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":30}}`,
				`data: {"type":"message_stop"}`,
			},
			wantParts: []string{
				"text Checking.",
				`call web_search {"query":"weather"}`,
				`call get_time {"tz":"UTC"}`,
			},
			wantUsage: `{"promptTokenCount":50,"candidatesTokenCount":30,"totalTokenCount":80}`,
		},
		{
			name:   "openai chat parallel tool_calls",
			target: adapter.FormatOpenAI,
			lines: []string{
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"On it."}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"web_search","arguments":""}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"query\":"}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"weather\"}"}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call_2","type":"function","function":{"name":"get_time","arguments":""}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"{\"tz\":\"UTC\"}"}}]}}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":70,"completion_tokens":20,"total_tokens":90}}`,
				`data: [DONE]`,
			},
			wantParts: []string{
				"text On it.",
				`call web_search {"query":"weather"}`,
				`call get_time {"tz":"UTC"}`,
			},
			wantUsage: `{"promptTokenCount":70,"candidatesTokenCount":20,"totalTokenCount":90}`,
		},
		{
			name:   "cohere v2 tool-call-delta",
			target: adapter.FormatCohere,
			lines: []string{
				`data: {"type":"message-start","id":"m1","delta":{"message":{"role":"assistant"}}}`,
				`data: {"type":"tool-plan-delta","delta":{"message":{"tool_plan":"I will search."}}}`,
				`data: {"type":"tool-call-start","index":0,"delta":{"message":{"tool_calls":{"id":"tc_1","type":"function","function":{"name":"web_search","arguments":""}}}}}`,
				`data: {"type":"tool-call-delta","index":0,"delta":{"message":{"tool_calls":{"function":{"arguments":"{\"query\": "}}}}}`,
				`data: {"type":"tool-call-delta","index":0,"delta":{"message":{"tool_calls":{"function":{"arguments":"\"weather\"}"}}}}}`,
				`data: {"type":"tool-call-end","index":0}`,
				`data: {"type":"message-end","delta":{"finish_reason":"TOOL_CALL","usage":{"billed_units":{"input_tokens":10,"output_tokens":5},"tokens":{"input_tokens":10,"output_tokens":5}}}}`,
			},
			wantParts: []string{
				"text I will search.",
				`call web_search {"query":"weather"}`,
			},
		},
		{
			name:   "mistral whole arguments",
			target: adapter.FormatMistral,
			lines: []string{
				`data: {"id":"m","model":"mistral-large","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":""}}]}`,
				`data: {"id":"m","model":"mistral-large","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"id":"abc123def","function":{"name":"web_search","arguments":"{\"query\": \"weather\"}"},"index":0},{"id":"ghi456jkl","function":{"name":"get_time","arguments":"{\"tz\": \"UTC\"}"},"index":1}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":30,"completion_tokens":12,"total_tokens":42}}`,
				`data: [DONE]`,
			},
			wantParts: []string{
				`call web_search {"query":"weather"}`,
				`call get_time {"tz":"UTC"}`,
			},
			wantUsage: `{"promptTokenCount":30,"candidatesTokenCount":12,"totalTokenCount":42}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := adaptGemini(t, tt.target, tt.lines...)

			assert.Equal(t, tt.wantParts, s.parts)
			last := s.assertOneFinishLast(t, "STOP")
			if tt.wantUsage != "" {
				assert.JSONEq(t, tt.wantUsage, string(last.UsageMetadata))
			}
			var callChunks int
			for _, c := range s.chunks {
				for _, p := range c.Candidates[0].Content.Parts {
					if p.FunctionCall != nil {
						callChunks++
						break
					}
				}
			}
			assert.Equal(t, 1, callChunks, "parallel calls arrive together, each once")
		})
	}
}

func TestAdaptStream_GeminiClientKeepsTextAfterCallsInOrder(t *testing.T) {
	tests := []struct {
		name   string
		target adapter.Format
		lines  []string
	}{
		{
			name:   "bedrock",
			target: adapter.FormatBedrock,
			lines: []string{
				`data: {"messageStart":{"role":"assistant"}}`,
				`data: {"contentBlockDelta":{"contentBlockIndex":0,"delta":{"text":"Before."}}}`,
				`data: {"contentBlockStop":{"contentBlockIndex":0}}`,
				`data: {"contentBlockStart":{"contentBlockIndex":1,"start":{"toolUse":{"toolUseId":"tooluse_a","name":"web_search"}}}}`,
				`data: {"contentBlockDelta":{"contentBlockIndex":1,"delta":{"toolUse":{"input":"{\"query\":"}}}}`,
				`data: {"contentBlockDelta":{"contentBlockIndex":1,"delta":{"toolUse":{"input":"\"weather\"}"}}}}`,
				`data: {"contentBlockStop":{"contentBlockIndex":1}}`,
				`data: {"contentBlockDelta":{"contentBlockIndex":2,"delta":{"text":"After."}}}`,
				`data: {"contentBlockStop":{"contentBlockIndex":2}}`,
				`data: {"contentBlockStart":{"contentBlockIndex":3,"start":{"toolUse":{"toolUseId":"tooluse_b","name":"get_time"}}}}`,
				`data: {"contentBlockDelta":{"contentBlockIndex":3,"delta":{"toolUse":{"input":"{\"tz\":\"UTC\"}"}}}}`,
				`data: {"contentBlockStop":{"contentBlockIndex":3}}`,
				`data: {"messageStop":{"stopReason":"tool_use"}}`,
				`data: {"metadata":{"usage":{"inputTokens":10,"outputTokens":5,"totalTokens":15}}}`,
			},
		},
		{
			name:   "anthropic",
			target: adapter.FormatAnthropic,
			lines: []string{
				`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude","usage":{"input_tokens":10,"output_tokens":1}}}`,
				`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
				`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Before."}}`,
				`data: {"type":"content_block_stop","index":0}`,
				`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"web_search","input":{}}}`,
				`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"query\":"}}`,
				`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\"weather\"}"}}`,
				`data: {"type":"content_block_stop","index":1}`,
				`data: {"type":"content_block_start","index":2,"content_block":{"type":"text","text":""}}`,
				`data: {"type":"content_block_delta","index":2,"delta":{"type":"text_delta","text":"After."}}`,
				`data: {"type":"content_block_stop","index":2}`,
				`data: {"type":"content_block_start","index":3,"content_block":{"type":"tool_use","id":"toolu_2","name":"get_time","input":{}}}`,
				`data: {"type":"content_block_delta","index":3,"delta":{"type":"input_json_delta","partial_json":"{\"tz\":\"UTC\"}"}}`,
				`data: {"type":"content_block_stop","index":3}`,
				`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":5}}`,
				`data: {"type":"message_stop"}`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := adaptGemini(t, tt.target, tt.lines...)

			assert.Equal(t, []string{
				"text Before.",
				`call web_search {"query":"weather"}`,
				"text After.",
				`call get_time {"tz":"UTC"}`,
			}, s.parts)
			s.assertOneFinishLast(t, "STOP")
		})
	}
}

func TestAdaptStream_GeminiClientWithholdsCallsThatMayBeCut(t *testing.T) {
	bedrockCall := []string{
		`data: {"messageStart":{"role":"assistant"}}`,
		`data: {"contentBlockDelta":{"contentBlockIndex":0,"delta":{"text":"Searching."}}}`,
		`data: {"contentBlockStart":{"contentBlockIndex":1,"start":{"toolUse":{"toolUseId":"tooluse_a","name":"web_search"}}}}`,
		`data: {"contentBlockDelta":{"contentBlockIndex":1,"delta":{"toolUse":{"input":"{\"query\":\"wea"}}}}`,
	}
	openAICall := []string{
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"web_search","arguments":""}}]}}]}`,
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"query\":\"wea"}}]}}]}`,
	}
	tests := []struct {
		name       string
		target     adapter.Format
		lines      []string
		wantParts  []string
		wantFinish string
	}{
		{
			name:      "bedrock ends mid arguments",
			target:    adapter.FormatBedrock,
			lines:     bedrockCall,
			wantParts: []string{"text Searching."},
		},
		{
			name:   "bedrock max_tokens",
			target: adapter.FormatBedrock,
			lines: append(append([]string{}, bedrockCall...),
				`data: {"contentBlockDelta":{"contentBlockIndex":1,"delta":{"toolUse":{"input":"ther\"}"}}}}`,
				`data: {"messageStop":{"stopReason":"max_tokens"}}`,
				`data: {"metadata":{"usage":{"inputTokens":10,"outputTokens":5,"totalTokens":15}}}`,
			),
			wantParts:  []string{"text Searching."},
			wantFinish: "MAX_TOKENS",
		},
		{
			name:       "openai [DONE] without a finish mid arguments",
			target:     adapter.FormatOpenAI,
			lines:      append(append([]string{}, openAICall...), `data: [DONE]`),
			wantFinish: "",
		},
		{
			name:   "openai [DONE] without a finish after whole arguments",
			target: adapter.FormatOpenAI,
			lines: append(append([]string{}, openAICall...),
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"ther\"}"}}]}}]}`,
				`data: [DONE]`,
			),
			wantParts:  []string{`call web_search {"query":"weather"}`},
			wantFinish: "STOP",
		},
		{
			name:   "anthropic finish with arguments that never parse",
			target: adapter.FormatAnthropic,
			lines: []string{
				`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude","usage":{"input_tokens":10,"output_tokens":1}}}`,
				`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"web_search","input":{}}}`,
				`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"query\":"}}`,
				`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_2","name":"get_time","input":{}}}`,
				`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":5}}`,
				`data: {"type":"message_stop"}`,
			},
			wantParts:  []string{`call get_time {}`},
			wantFinish: "STOP",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := adaptGemini(t, tt.target, tt.lines...)

			assert.Equal(t, tt.wantParts, s.parts)
			var finishes []string
			for _, c := range s.chunks {
				if r := c.Candidates[0].FinishReason; r != "" {
					finishes = append(finishes, r)
				}
			}
			if tt.wantFinish == "" {
				assert.Empty(t, finishes)
				return
			}
			assert.Equal(t, []string{tt.wantFinish}, finishes)
			s.assertOneFinishLast(t, tt.wantFinish)
		})
	}
}

func TestAdaptStream_GeminiClientWithholdsCallsOnUpstreamFailure(t *testing.T) {
	boom := errors.New("connection reset")
	var upstream iter.Seq2[[]byte, error] = func(yield func([]byte, error) bool) {
		for _, l := range []string{
			`data: {"messageStart":{"role":"assistant"}}`,
			`data: {"contentBlockStart":{"contentBlockIndex":0,"start":{"toolUse":{"toolUseId":"tooluse_a","name":"web_search"}}}}`,
			`data: {"contentBlockDelta":{"contentBlockIndex":0,"delta":{"toolUse":{"input":"{\"query\":\"weather\"}"}}}}`,
		} {
			if !yield([]byte(l), nil) {
				return
			}
		}
		yield(nil, boom)
	}

	lines, err := collectLinesAndError(adaptStream(upstream, adapter.NewRegistry(), adapter.FormatGemini, adapter.FormatBedrock, slog.Default(), nil))

	require.ErrorIs(t, err, boom)
	_, notified := errors.AsType[*ClientNotifiedStreamError](err)
	assert.True(t, notified, "the client already has its error object")
	s := decodeGeminiClientStream(t, lines)
	assert.Empty(t, s.parts, "no call reaches the client without a finish")
	s.assertFailed(t)
}

func (s geminiClientStream) assertFailed(t *testing.T) {
	t.Helper()
	require.Len(t, s.errors, 1, "the client gets one error object")
	assert.Equal(t, 500, s.errors[0].Error.Code)
	assert.Equal(t, "INTERNAL", s.errors[0].Error.Status)
	assert.Equal(t, "upstream stream failed", s.errors[0].Error.Message, "the client does not get the upstream's message")
	for _, c := range s.chunks {
		assert.Empty(t, c.Candidates[0].FinishReason, "a failed stream has no finish")
	}
}

func TestAdaptStream_GeminiClientWithholdsCallsOnUpstreamErrorPayload(t *testing.T) {
	name := `data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"delete_all","arguments":""}}]}}]}`
	whole := `data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{}"}}]}}]}`
	cut := `data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call_2","function":{"name":"second","arguments":"{\"a\":"}}]}}]}`
	text := `data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"}}]}`
	errorPayload := `data: {"error":{"message":"The server had an error","type":"server_error","code":500}}`
	tests := []struct {
		name      string
		upstream  []string
		wantParts []string
	}{
		{name: "name-only call", upstream: []string{name, errorPayload, `data: [DONE]`}},
		{name: "whole and cut calls", upstream: []string{name, whole, cut, errorPayload, `data: [DONE]`}},
		{name: "text before the error", upstream: []string{text, errorPayload, `data: [DONE]`}, wantParts: []string{"text hi"}},
		{
			name: "error with content",
			upstream: []string{
				text,
				`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":" there"}}],"error":{"message":"The server had an error","type":"server_error"}}`,
				`data: [DONE]`,
			},
			wantParts: []string{"text hi", "text  there"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines, err := collectLinesAndError(adaptStream(linesSeq(tt.upstream...), adapter.NewRegistry(), adapter.FormatGemini, adapter.FormatOpenAI, slog.Default(), nil))

			_, notified := errors.AsType[*ClientNotifiedStreamError](err)
			require.True(t, notified, "the client already has its error object, got %v", err)
			_, upstream := errors.AsType[*adapter.UpstreamStreamError](err)
			assert.True(t, upstream, "the sequence error is the upstream's")
			s := decodeGeminiClientStream(t, lines)
			assert.Equal(t, tt.wantParts, s.parts)
			s.assertFailed(t)
			assert.NotContains(t, strings.Join(lines, "\n"), "The server had an error")
		})
	}
}

func TestAdaptStream_GeminiClientUpstreamErrorAfterTheFinishKeepsTheFinish(t *testing.T) {
	text := `data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"}}]}`
	finish := `data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`
	usage := `data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`
	errorPayload := `data: {"error":{"message":"The server had an error","type":"server_error"}}`
	for name, upstream := range map[string][]string{
		"error after a held finish":      {text, finish, errorPayload, `data: [DONE]`},
		"error after the flushed finish": {text, finish, usage, errorPayload, `data: [DONE]`},
	} {
		t.Run(name, func(t *testing.T) {
			lines, err := collectLinesAndError(adaptStream(linesSeq(upstream...), adapter.NewRegistry(), adapter.FormatGemini, adapter.FormatOpenAI, slog.Default(), nil))

			_, notified := errors.AsType[*ClientNotifiedStreamError](err)
			require.True(t, notified, "the client already has its finish, got %v", err)
			s := decodeGeminiClientStream(t, lines)
			assert.Empty(t, s.errors, "a finished stream gets no error object")
			assert.Equal(t, []string{"text hi"}, s.parts)
			s.assertOneFinishLast(t, "STOP")
		})
	}
}

func TestAdaptStream_GeminiClientDoneWithoutFinishCompletesNoArgCalls(t *testing.T) {
	name := `data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"list_files","arguments":""}}]}}]}`

	s := adaptGemini(t, adapter.FormatOpenAI, name, `data: [DONE]`)

	assert.Equal(t, []string{"call list_files {}"}, s.parts, "a call with no argument bytes is a call to a tool that takes none")
	s.assertOneFinishLast(t, "STOP")
}

func TestAdaptStream_GeminiClientGetsTheCallIDs(t *testing.T) {
	s := adaptGemini(t, adapter.FormatOpenAI,
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Paris\"}"}}]}}]}`,
		`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: [DONE]`,
	)

	var ids []string
	for _, c := range s.chunks {
		for _, p := range c.Candidates[0].Content.Parts {
			if p.FunctionCall != nil {
				ids = append(ids, p.FunctionCall.ID)
			}
		}
	}
	assert.Equal(t, []string{"call_1"}, ids)
}

func TestAdaptStream_GeminiClientWithholdsCallsOnContextWindowExceeded(t *testing.T) {
	s := adaptGemini(t, adapter.FormatAnthropic,
		`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude","usage":{"input_tokens":10,"output_tokens":1}}}`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"web_search","input":{}}}`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"query\":\"weather\"}"}}`,
		`data: {"type":"message_delta","delta":{"stop_reason":"model_context_window_exceeded"},"usage":{"output_tokens":5}}`,
		`data: {"type":"message_stop"}`,
	)

	assert.Empty(t, s.parts, "a call cut at the context window is withheld")
	s.assertOneFinishLast(t, "MAX_TOKENS")
}

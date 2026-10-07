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

package proxy_test

import (
	"context"
	"encoding/json"
	"errors"
	"iter"
	"strings"
	"testing"

	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	providermocks "github.com/NeuralTrust/TrustGate/pkg/infra/providers/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	anthropicChatStart  = `data: {"type":"message_start","message":{"id":"msg_chat","role":"assistant","model":"claude-chat","usage":{"input_tokens":10,"output_tokens":1,"cache_read_input_tokens":20,"cache_creation_input_tokens":5}}}`
	anthropicChatText   = `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}`
	anthropicChatFinish = `data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}`
	anthropicChatStop   = `data: {"type":"message_stop"}`
)

type anthropicChatChunk struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Object  string `json:"object"`
	Choices []struct {
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens        int `json:"prompt_tokens"`
		CompletionTokens    int `json:"completion_tokens"`
		TotalTokens         int `json:"total_tokens"`
		PromptTokensDetails struct {
			CachedTokens     int `json:"cached_tokens"`
			CacheWriteTokens int `json:"cache_write_tokens"`
		} `json:"prompt_tokens_details"`
	} `json:"usage"`
}

func TestInvokeStream_AnthropicChatCompletion(t *testing.T) {
	for _, format := range []adapter.Format{adapter.FormatOpenAI, adapter.FormatAzure} {
		for _, includeUsage := range []bool{false, true} {
			name := string(format) + "/without_usage"
			if includeUsage {
				name = string(format) + "/include_usage"
			}
			t.Run(name, func(t *testing.T) {
				client := providermocks.NewClient(t)
				client.EXPECT().CompletionsStream(mock.Anything, mock.Anything, mock.MatchedBy(func(body []byte) bool {
					var request map[string]json.RawMessage
					require.NoError(t, json.Unmarshal(body, &request))
					assert.JSONEq(t, "64", string(request["max_tokens"]))
					assert.JSONEq(t, "true", string(request["stream"]))
					assert.NotContains(t, request, "thinking")
					assert.NotContains(t, request, "stream_options")
					return true
				})).Return(seqOf([]byte(anthropicChatStart), []byte(anthropicChatText), []byte(anthropicChatFinish), []byte(anthropicChatStop)), nil).Once()
				body := `{"model":"claude-chat","messages":[{"role":"user","content":"hi"}],"stream":true,"max_completion_tokens":64}`
				if includeUsage {
					body = strings.TrimSuffix(body, "}") + `,"stream_options":{"include_usage":true}}`
				}
				invoker := newStreamInvoker(t, "anthropic", client)
				response, err := invoker.InvokeStream(context.Background(), apiKeyTarget("anthropic"), &infracontext.RequestContext{Body: []byte(body), SourceFormat: string(format)})
				require.NoError(t, err)
				lines := collectStream(t, response.Stream)
				require.GreaterOrEqual(t, len(lines), 2)
				assert.Equal(t, "data: [DONE]", lines[len(lines)-2])
				assert.Equal(t, 1, strings.Count(strings.Join(lines, "\n"), "[DONE]"))
				var usageCount, finishCount int
				var text strings.Builder
				for _, line := range lines {
					payload, ok := strings.CutPrefix(line, "data: ")
					if !ok || payload == "[DONE]" {
						continue
					}
					var chunk anthropicChatChunk
					require.NoError(t, json.Unmarshal([]byte(payload), &chunk))
					assert.Equal(t, "msg_chat", chunk.ID)
					assert.Equal(t, "claude-chat", chunk.Model)
					assert.Equal(t, "chat.completion.chunk", chunk.Object)
					for _, choice := range chunk.Choices {
						text.WriteString(choice.Delta.Content)
						if choice.FinishReason != nil {
							finishCount++
							assert.Equal(t, "stop", *choice.FinishReason)
						}
					}
					if chunk.Usage != nil {
						usageCount++
						assert.Empty(t, chunk.Choices)
						assert.Equal(t, 35, chunk.Usage.PromptTokens)
						assert.Equal(t, 7, chunk.Usage.CompletionTokens)
						assert.Equal(t, 42, chunk.Usage.TotalTokens)
						assert.Equal(t, 20, chunk.Usage.PromptTokensDetails.CachedTokens)
						assert.Equal(t, 5, chunk.Usage.PromptTokensDetails.CacheWriteTokens)
					}
				}
				assert.Equal(t, "hello", text.String())
				assert.Equal(t, 1, finishCount)
				if includeUsage {
					assert.Equal(t, 1, usageCount)
				} else {
					assert.Zero(t, usageCount)
				}
			})
		}
	}
}

func TestInvokeStream_AnthropicChatFailureHasNoSuccessTerminal(t *testing.T) {
	transportErr := errors.New("upstream reset")
	for _, tc := range []struct {
		name  string
		lines []string
		err   error
	}{
		{name: "premature EOF", lines: []string{anthropicChatStart, anthropicChatText}},
		{name: "missing message stop", lines: []string{anthropicChatStart, anthropicChatText, anthropicChatFinish}},
		{name: "error event", lines: []string{anthropicChatStart, anthropicChatText, `data: {"type":"error","error":{"type":"overloaded_error","message":"private upstream detail"}}`}},
		{name: "error after finish", lines: []string{anthropicChatStart, anthropicChatFinish, `data: {"type":"error","error":{"type":"overloaded_error","message":"private upstream detail"}}`, anthropicChatStop}},
		{name: "transport error", lines: []string{anthropicChatStart, anthropicChatText}, err: transportErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := iter.Seq2[[]byte, error](func(yield func([]byte, error) bool) {
				for _, line := range tc.lines {
					if !yield([]byte(line), nil) {
						return
					}
				}
				if tc.err != nil {
					yield(nil, tc.err)
				}
			})
			client := providermocks.NewClient(t)
			client.EXPECT().CompletionsStream(mock.Anything, mock.Anything, mock.Anything).Return(upstream, nil).Once()
			invoker := newStreamInvoker(t, "anthropic", client)
			body := []byte(`{"model":"claude-chat","messages":[{"role":"user","content":"hi"}],"stream":true,"max_completion_tokens":64,"stream_options":{"include_usage":true}}`)
			response, err := invoker.InvokeStream(context.Background(), apiKeyTarget("anthropic"), &infracontext.RequestContext{Body: body, SourceFormat: "openai"})
			require.NoError(t, err)
			var lines []string
			var streamErr error
			for line, err := range response.Stream {
				if err != nil {
					streamErr = err
					continue
				}
				lines = append(lines, string(line))
			}
			require.Error(t, streamErr)
			if tc.err != nil {
				assert.ErrorIs(t, streamErr, transportErr)
			}
			joined := strings.Join(lines, "\n")
			assert.NotContains(t, joined, "[DONE]")
			assert.NotContains(t, joined, "private upstream detail")
			assert.NotContains(t, joined, `"usage"`)
			assert.NotContains(t, joined, `"finish_reason":"stop"`)
		})
	}
}

func TestInvokeStream_AnthropicNativeStreamUnchanged(t *testing.T) {
	upstream := [][]byte{[]byte(anthropicChatStart), {}, []byte(anthropicChatText), {}, []byte(anthropicChatFinish), {}, []byte(anthropicChatStop), {}}
	client := providermocks.NewClient(t)
	client.EXPECT().CompletionsStream(mock.Anything, mock.Anything, mock.Anything).Return(seqOf(upstream...), nil).Once()
	invoker := newStreamInvoker(t, "anthropic", client)
	body := []byte(`{"model":"claude-chat","messages":[{"role":"user","content":"hi"}],"stream":true,"max_tokens":64,"thinking":{"type":"disabled"}}`)
	response, err := invoker.InvokeStream(context.Background(), apiKeyTarget("anthropic"), &infracontext.RequestContext{Body: body, SourceFormat: "anthropic"})
	require.NoError(t, err)
	var expected []string
	for _, line := range upstream {
		expected = append(expected, string(line))
	}
	assert.Equal(t, expected, collectStream(t, response.Stream))
}

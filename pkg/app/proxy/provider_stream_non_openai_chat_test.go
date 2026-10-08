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

type nonOpenAIChatFixture struct {
	provider, model, id, responseModel string
	start, text, finish, terminal      string
	future, malformed, failure         string
	tool                               []string
	toolFinish, nativeBody             string
}

type nonOpenAIChatFailure struct {
	name  string
	lines []string
	err   error
}

func nonOpenAIChatFixtures() []nonOpenAIChatFixture {
	return []nonOpenAIChatFixture{
		{
			provider: "google", model: "gemini-chat", id: "gemini-chat-id", responseModel: "gemini-chat-version",
			start:      `data: {"responseId":"gemini-chat-id","modelVersion":"gemini-chat-version","candidates":[{"content":{"role":"model","parts":[]}}],"usageMetadata":{"promptTokenCount":35,"candidatesTokenCount":1,"totalTokenCount":36,"cachedContentTokenCount":20}}`,
			text:       `data: {"candidates":[{"content":{"parts":[{"text":"hello"}]}}]}`,
			finish:     `data: {"candidates":[{"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":35,"candidatesTokenCount":7,"totalTokenCount":42,"cachedContentTokenCount":20}}`,
			future:     `data: {"futureEvent":{"usage":"opaque"}}`,
			malformed:  `data: {"candidates":[{"content":{"parts":[{"text":42}]}}]}`,
			failure:    `data: {"error":{"code":503,"message":"private upstream detail","status":"UNAVAILABLE"}}`,
			tool:       []string{`data: {"candidates":[{"content":{"parts":[{"functionCall":{"id":"call_non_openai","name":"lookup","args":{"answer":42}}}]}}]}`},
			toolFinish: `data: {"candidates":[{"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":35,"candidatesTokenCount":7,"totalTokenCount":42,"cachedContentTokenCount":20}}`,
			nativeBody: `{"model":"gemini-chat","contents":[{"role":"user","parts":[{"text":"hi"}]}]}`,
		},
		{
			provider: "bedrock", model: "amazon.nova-micro-v1:0", responseModel: "amazon.nova-micro-v1:0",
			start:     `data: {"messageStart":{"role":"assistant"}}`,
			text:      `data: {"contentBlockDelta":{"contentBlockIndex":0,"delta":{"text":"hello"}}}`,
			finish:    `data: {"messageStop":{"stopReason":"end_turn"}}`,
			terminal:  `data: {"metadata":{"usage":{"inputTokens":35,"outputTokens":7,"totalTokens":42,"cacheReadInputTokens":20,"cacheWriteInputTokens":5}}}`,
			future:    `data: {"futureEvent":{"usage":"opaque"}}`,
			malformed: `data: {"contentBlockDelta":{"delta":{"text":42}}}`,
			failure:   `data: {"modelStreamErrorException":{"message":"private upstream detail"}}`,
			tool: []string{
				`data: {"contentBlockStart":{"contentBlockIndex":1,"start":{"toolUse":{"toolUseId":"call_non_openai","name":"lookup"}}}}`,
				`data: {"contentBlockDelta":{"contentBlockIndex":1,"delta":{"toolUse":{"input":"{\"answer\":"}}}}`,
				`data: {"contentBlockDelta":{"contentBlockIndex":1,"delta":{"toolUse":{"input":"42}"}}}}`,
			},
			toolFinish: `data: {"messageStop":{"stopReason":"tool_use"}}`,
			nativeBody: `{"model":"amazon.nova-micro-v1:0","messages":[{"role":"user","content":[{"text":"hi"}]}],"stream":true,"inferenceConfig":{"maxTokens":64}}`,
		},
		{
			provider: "cohere", model: "command-chat", id: "cohere-chat-id", responseModel: "command-chat",
			start:     `data: {"type":"message-start","id":"cohere-chat-id","delta":{"message":{"role":"assistant","content":[]}}}`,
			text:      `data: {"type":"content-delta","index":0,"delta":{"message":{"content":{"type":"text","text":"hello"}}}}`,
			finish:    `data: {"type":"message-end","delta":{"finish_reason":"COMPLETE","usage":{"billed_units":{"input_tokens":10,"output_tokens":7},"tokens":{"input_tokens":35,"output_tokens":7},"cached_tokens":20}}}`,
			future:    `data: {"type":"future-event","delta":42,"index":"opaque"}`,
			malformed: `data: {"type":"content-delta","delta":{"message":{"content":{"text":42}}}}`,
			failure:   `data: {"type":"message-end","delta":{"finish_reason":"ERROR","error":"private upstream detail"}}`,
			tool: []string{
				`data: {"type":"tool-call-start","index":1,"delta":{"message":{"tool_calls":{"id":"call_non_openai","function":{"name":"lookup","arguments":""}}}}}`,
				`data: {"type":"tool-call-delta","index":1,"delta":{"message":{"tool_calls":{"function":{"arguments":"{\"answer\":"}}}}}`,
				`data: {"type":"tool-call-delta","index":1,"delta":{"message":{"tool_calls":{"function":{"arguments":"42}"}}}}}`,
			},
			toolFinish: `data: {"type":"message-end","delta":{"finish_reason":"TOOL_CALL","usage":{"tokens":{"input_tokens":35,"output_tokens":7},"cached_tokens":20}}}`,
			nativeBody: `{"model":"command-chat","messages":[{"role":"user","content":"hi"}],"stream":true}`,
		},
	}
}

func nonOpenAIChatBody(fixture nonOpenAIChatFixture, options string) []byte {
	return []byte(`{"model":"` + fixture.model + `","messages":[{"role":"user","content":"hi"}],"stream":true,"max_completion_tokens":64` + options + `}`)
}

func (f nonOpenAIChatFixture) lines(content []string, finish string) []string {
	lines := append([]string{f.start, f.future}, content...)
	lines = append(lines, finish, finish)
	if f.terminal != "" {
		lines = append(lines, f.terminal, f.terminal)
	}
	return lines
}

func nonOpenAIChatSequence(lines []string, failure error) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		for _, line := range lines {
			if !yield([]byte(line), nil) {
				return
			}
		}
		if failure != nil {
			yield(nil, failure)
		}
	}
}

func assertNonOpenAIChatCompletion(t *testing.T, fixture nonOpenAIChatFixture, lines []string, includeUsage bool, reason string) {
	t.Helper()
	var frames []string
	for _, line := range lines {
		if payload, ok := strings.CutPrefix(line, "data: "); ok {
			frames = append(frames, payload)
		}
	}
	require.NotEmpty(t, frames)
	assert.Equal(t, "[DONE]", frames[len(frames)-1])
	var identity string
	var finishes, usages, terminals int
	finishIndex, usageIndex := -1, -1
	for i, frame := range frames {
		if frame == "[DONE]" {
			terminals++
			continue
		}
		var chunk anthropicChatChunk
		require.NoError(t, json.Unmarshal([]byte(frame), &chunk))
		require.NotEmpty(t, chunk.ID)
		if identity == "" {
			identity = chunk.ID
		}
		assert.Equal(t, identity, chunk.ID)
		if fixture.id != "" {
			assert.Equal(t, fixture.id, chunk.ID)
		}
		assert.Equal(t, fixture.responseModel, chunk.Model)
		assert.Equal(t, "chat.completion.chunk", chunk.Object)
		for _, choice := range chunk.Choices {
			if choice.FinishReason != nil {
				finishes++
				finishIndex = i
				assert.Equal(t, reason, *choice.FinishReason)
			}
		}
		if chunk.Usage != nil {
			usages++
			usageIndex = i
			assert.Empty(t, chunk.Choices)
			assert.Equal(t, 35, chunk.Usage.PromptTokens)
			assert.Equal(t, 7, chunk.Usage.CompletionTokens)
			assert.Equal(t, 42, chunk.Usage.TotalTokens)
			assert.Equal(t, 20, chunk.Usage.PromptTokensDetails.CachedTokens)
		}
	}
	assert.Equal(t, 1, terminals)
	assert.Equal(t, 1, finishes)
	if includeUsage {
		assert.Equal(t, 1, usages)
		assert.Equal(t, len(frames)-2, usageIndex)
		assert.Equal(t, usageIndex-1, finishIndex)
	} else {
		assert.Zero(t, usages)
		assert.NotContains(t, strings.Join(lines, "\n"), `"usage":`)
		assert.Equal(t, len(frames)-2, finishIndex)
	}
}

func TestInvokeStream_NonOpenAIChatCompletion(t *testing.T) {
	for _, fixture := range nonOpenAIChatFixtures() {
		for _, source := range []string{"openai", "azure"} {
			for _, usage := range []struct {
				name, options string
				include       bool
			}{
				{name: "omitted"},
				{name: "false", options: `,"stream_options":{"include_usage":false}`},
				{name: "true", options: `,"stream_options":{"include_usage":true}`, include: true},
			} {
				for _, tool := range []bool{false, true} {
					name := fixture.provider + "/" + source + "/" + usage.name
					if tool {
						name += "/tool"
					}
					t.Run(name, func(t *testing.T) {
						content, finish, reason := []string{fixture.text}, fixture.finish, "stop"
						if tool {
							content, finish = fixture.tool, fixture.toolFinish
							if fixture.provider != "google" {
								reason = "tool_calls"
							}
						}
						client := providermocks.NewClient(t)
						client.EXPECT().CompletionsStream(mock.Anything, mock.Anything, mock.Anything).Return(nonOpenAIChatSequence(fixture.lines(content, finish), nil), nil).Once()
						request := &infracontext.RequestContext{Body: nonOpenAIChatBody(fixture, usage.options), SourceFormat: source}
						response, err := newStreamInvoker(t, fixture.provider, client).InvokeStream(context.Background(), apiKeyTarget(fixture.provider), request)
						require.NoError(t, err)
						lines := collectStream(t, response.Stream)
						assertNonOpenAIChatCompletion(t, fixture, lines, usage.include, reason)
						var text strings.Builder
						var calls []struct {
							ID       string `json:"id"`
							Function struct {
								Name, Arguments string
							} `json:"function"`
						}
						for _, line := range lines {
							payload, ok := strings.CutPrefix(line, "data: ")
							if !ok || payload == "[DONE]" {
								continue
							}
							var chunk struct {
								Choices []struct {
									Delta struct {
										Content   string          `json:"content"`
										ToolCalls json.RawMessage `json:"tool_calls"`
									} `json:"delta"`
								} `json:"choices"`
							}
							require.NoError(t, json.Unmarshal([]byte(payload), &chunk))
							for _, choice := range chunk.Choices {
								text.WriteString(choice.Delta.Content)
								if choice.Delta.ToolCalls != nil {
									var decoded = calls[:0:0]
									require.NoError(t, json.Unmarshal(choice.Delta.ToolCalls, &decoded))
									calls = append(calls, decoded...)
								}
							}
						}
						if tool {
							assert.Empty(t, text.String())
							require.Len(t, calls, 1)
							expectedID := "call_non_openai"
							if fixture.provider == "google" {
								expectedID = "lookup"
							}
							assert.Equal(t, expectedID, calls[0].ID)
							assert.Equal(t, "lookup", calls[0].Function.Name)
							assert.JSONEq(t, `{"answer":42}`, calls[0].Function.Arguments)
						} else {
							assert.Equal(t, "hello", text.String())
							assert.Empty(t, calls)
						}
						observed, ok := request.Metadata[adapter.MetadataUsageKey].(*adapter.CanonicalUsage)
						require.True(t, ok)
						assert.Equal(t, 35, observed.InputTokens)
						assert.Equal(t, 7, observed.OutputTokens)
						assert.Equal(t, 42, observed.TotalTokens)
					})
				}
			}
		}
	}
}

func TestInvokeStream_NonOpenAIChatFailureHasNoSuccessTerminal(t *testing.T) {
	transportErr := errors.New("upstream reset")
	for _, fixture := range nonOpenAIChatFixtures() {
		cases := []nonOpenAIChatFailure{
			{name: "EOF before finish", lines: []string{fixture.start, fixture.text}},
			{name: "provider error", lines: []string{fixture.start, fixture.text, fixture.failure}},
			{name: "malformed known event", lines: fixture.lines([]string{fixture.text, fixture.malformed}, fixture.finish)},
			{name: "malformed JSON", lines: fixture.lines([]string{`data: {invalid`}, fixture.finish)},
			{name: "null payload", lines: fixture.lines([]string{`data: null`}, fixture.finish)},
			{name: "transport before finish", lines: []string{fixture.start, fixture.text}, err: transportErr},
		}
		if fixture.provider != "cohere" {
			cases = append(cases, nonOpenAIChatFailure{name: "transport after held finish", lines: []string{fixture.start, fixture.text, fixture.finish}, err: transportErr})
			cases = append(cases, nonOpenAIChatFailure{name: "error after held finish", lines: []string{fixture.start, fixture.text, fixture.finish, fixture.failure}})
		}
		if fixture.provider == "bedrock" {
			cases = append(cases, nonOpenAIChatFailure{name: "missing metadata terminal", lines: []string{fixture.start, fixture.text, fixture.finish}})
		}
		for _, source := range []string{"openai", "azure"} {
			for _, tc := range cases {
				t.Run(fixture.provider+"/"+source+"/"+tc.name, func(t *testing.T) {
					client := providermocks.NewClient(t)
					client.EXPECT().CompletionsStream(mock.Anything, mock.Anything, mock.Anything).Return(nonOpenAIChatSequence(tc.lines, tc.err), nil).Once()
					request := &infracontext.RequestContext{Body: nonOpenAIChatBody(fixture, `,"stream_options":{"include_usage":true}`), SourceFormat: source}
					response, err := newStreamInvoker(t, fixture.provider, client).InvokeStream(context.Background(), apiKeyTarget(fixture.provider), request)
					require.NoError(t, err)
					var lines []string
					var streamErr error
					for line, err := range response.Stream {
						if err != nil {
							streamErr = err
						} else {
							lines = append(lines, string(line))
						}
					}
					require.Error(t, streamErr)
					if tc.err != nil {
						assert.ErrorIs(t, streamErr, transportErr)
					}
					joined := strings.Join(lines, "\n")
					assert.Contains(t, joined, `"error"`)
					assert.NotContains(t, joined, "private upstream detail")
					assert.NotContains(t, joined, "[DONE]")
					assert.NotContains(t, joined, `"finish_reason"`)
					assert.NotContains(t, joined, `"usage"`)
				})
			}
		}
	}
}

func TestInvokeStream_NonOpenAINativeStreamUnchanged(t *testing.T) {
	for _, fixture := range nonOpenAIChatFixtures() {
		t.Run(fixture.provider, func(t *testing.T) {
			lines := fixture.lines([]string{fixture.text}, fixture.finish)
			lines = append([]string{"event: provider-event", ""}, lines...)
			client := providermocks.NewClient(t)
			client.EXPECT().CompletionsStream(mock.Anything, mock.Anything, mock.Anything).Return(nonOpenAIChatSequence(lines, nil), nil).Once()
			request := &infracontext.RequestContext{Body: []byte(fixture.nativeBody), SourceFormat: fixture.provider}
			response, err := newStreamInvoker(t, fixture.provider, client).InvokeStream(context.Background(), apiKeyTarget(fixture.provider), request)
			require.NoError(t, err)
			assert.Equal(t, lines, collectStream(t, response.Stream))
		})
	}
}

func TestInvokeStream_CohereChatOptionalNullFields(t *testing.T) {
	fixture := nonOpenAIChatFixtures()[2]
	for _, source := range []string{"openai", "azure"} {
		t.Run(source, func(t *testing.T) {
			upstream := []string{fixture.start, fixture.text, `data: {"type":"message-end","id":null,"delta":{"finish_reason":"COMPLETE","error":null,"usage":null}}`}
			client := providermocks.NewClient(t)
			client.EXPECT().CompletionsStream(mock.Anything, mock.Anything, mock.Anything).Return(nonOpenAIChatSequence(upstream, nil), nil).Once()
			request := &infracontext.RequestContext{Body: nonOpenAIChatBody(fixture, `,"stream_options":{"include_usage":true}`), SourceFormat: source}
			response, err := newStreamInvoker(t, fixture.provider, client).InvokeStream(context.Background(), apiKeyTarget(fixture.provider), request)
			require.NoError(t, err)
			lines := collectStream(t, response.Stream)
			assertNonOpenAIChatCompletion(t, fixture, lines, false, "stop")
		})
	}
}

func TestGeminiMainStreamToolNameMatchesContinuation(t *testing.T) {
	decoder := &adapter.GeminiAdapter{}
	chunk, err := decoder.DecodeStreamChunk([]byte(`{"candidates":[{"content":{"parts":[{"functionCall":{"id":"provider-call-id","name":"lookup","args":{"answer":42}}}]}}]}`))
	require.NoError(t, err)
	require.NotNil(t, chunk)
	require.Len(t, chunk.ToolCallDeltas, 1)
	call := chunk.ToolCallDeltas[0]
	require.Equal(t, "lookup", call.ID)
	body, err := decoder.EncodeRequest(&adapter.CanonicalRequest{Model: "gemini-chat", Messages: []adapter.CanonicalMessage{
		{Role: "assistant", ToolCalls: []adapter.CanonicalToolCall{{ID: call.ID, Name: call.Name, Arguments: call.ArgumentsDelta}}},
		{Role: "tool", ToolCallID: call.ID, Content: `{"answer":42}`},
	}})
	require.NoError(t, err)
	assert.JSONEq(t, `{"model":"gemini-chat","contents":[{"role":"model","parts":[{"functionCall":{"name":"lookup","args":{"answer":42}}}]},{"role":"user","parts":[{"functionResponse":{"name":"lookup","response":{"answer":42}}}]}]}`, string(body))
}

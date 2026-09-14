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

//go:build bedrock_live

// Live tests against real AWS Bedrock. They drive the same adapter + client
// path the proxy uses, for every model in BEDROCK_LIVE_MODELS:
//
//	BEDROCK_LIVE_MODELS  comma-separated model IDs, inference profiles or
//	                     application-inference-profile ARNs (required)
//	AWS_REGION           Bedrock region (default us-east-1)
//
// Credentials come from the SDK's default chain (AWS_* variables, then the
// default profile in ~/.aws/credentials), so nothing secret has to be passed
// on the command line.
//
//	BEDROCK_LIVE_MODELS=eu.amazon.nova-pro-v1:0 AWS_REGION=eu-west-1 \
//	  go test -tags bedrock_live -count=1 -run TestLive -v ./pkg/infra/providers/bedrock/
package bedrock

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func liveModels(t *testing.T) []string {
	t.Helper()
	raw := os.Getenv("BEDROCK_LIVE_MODELS")
	if raw == "" {
		t.Skip("BEDROCK_LIVE_MODELS not set")
	}
	var models []string
	for _, m := range strings.Split(raw, ",") {
		if m = strings.TrimSpace(m); m != "" {
			models = append(models, m)
		}
	}
	return models
}

// liveConfig leaves the keys empty unless AWS_* variables are set, which makes
// the client fall back to the SDK's default credential chain.
func liveConfig(model string) *providers.Config {
	return &providers.Config{
		Model: model,
		Credentials: providers.Credentials{AwsBedrock: &providers.AwsBedrock{
			Region:       os.Getenv("AWS_REGION"),
			AccessKey:    os.Getenv("AWS_ACCESS_KEY_ID"),
			SecretKey:    os.Getenv("AWS_SECRET_ACCESS_KEY"),
			SessionToken: os.Getenv("AWS_SESSION_TOKEN"),
		}},
	}
}

func liveContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	return ctx
}

type openAIResponse struct {
	Choices []struct {
		Message struct {
			Content   string `json:"content"`
			ToolCalls []struct {
				ID       string `json:"id"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

// completeOpenAI runs one OpenAI-shaped request through the exact proxy path:
// OpenAI → Converse (adapter), Converse → Bedrock (client), back to OpenAI.
func completeOpenAI(t *testing.T, model string, body string) (openAIResponse, []byte) {
	t.Helper()
	reg := adapter.NewRegistry()
	wire, err := reg.AdaptRequest([]byte(body), adapter.FormatOpenAI, adapter.FormatBedrock)
	require.NoError(t, err)

	raw, err := NewBedrockClient().Completions(liveContext(t), liveConfig(model), wire)
	require.NoError(t, err, "Bedrock rejected the Converse body: %s", wire)

	out, err := reg.AdaptResponse(raw, adapter.FormatOpenAI, adapter.FormatBedrock)
	require.NoError(t, err)
	var resp openAIResponse
	require.NoError(t, json.Unmarshal(out, &resp))
	require.Len(t, resp.Choices, 1)
	return resp, raw
}

func TestLive_Completions_OpenAIIngress(t *testing.T) {
	for _, model := range liveModels(t) {
		t.Run(model, func(t *testing.T) {
			resp, raw := completeOpenAI(t, model, `{
				"messages": [
					{"role": "system", "content": "Answer in one short sentence."},
					{"role": "user", "content": "Say hello and name the capital of Spain."}
				],
				"max_tokens": 64,
				"temperature": 0.1
			}`)
			t.Logf("converse response: %s", raw)
			t.Logf("answer: %q", resp.Choices[0].Message.Content)

			assert.NotEmpty(t, resp.Choices[0].Message.Content)
			assert.Contains(t, strings.ToLower(resp.Choices[0].Message.Content), "madrid")
			assert.Equal(t, "stop", resp.Choices[0].FinishReason)
			assert.Positive(t, resp.Usage.PromptTokens)
			assert.Positive(t, resp.Usage.CompletionTokens)
		})
	}
}

func TestLive_Completions_MaxTokensTruncates(t *testing.T) {
	for _, model := range liveModels(t) {
		t.Run(model, func(t *testing.T) {
			resp, _ := completeOpenAI(t, model, `{
				"messages": [{"role": "user", "content": "Write a 300 word essay about rivers."}],
				"max_tokens": 5
			}`)
			assert.Equal(t, "length", resp.Choices[0].FinishReason,
				"inferenceConfig.maxTokens must reach the model")
		})
	}
}

func TestLive_Completions_ToolLoop(t *testing.T) {
	const tools = `"tools": [{"type": "function", "function": {
		"name": "get_weather",
		"description": "Current weather for a city",
		"parameters": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}
	}}]`

	for _, model := range liveModels(t) {
		t.Run(model, func(t *testing.T) {
			first, raw := completeOpenAI(t, model, `{
				"messages": [{"role": "user", "content": "What is the weather in Madrid right now? You must call the get_weather tool."}],
				`+tools+`,
				"tool_choice": "required",
				"max_tokens": 256
			}`)
			t.Logf("first turn: %s", raw)
			require.Len(t, first.Choices[0].Message.ToolCalls, 1, "model must call the tool")
			call := first.Choices[0].Message.ToolCalls[0]
			assert.Equal(t, "get_weather", call.Function.Name)
			assert.Equal(t, "tool_calls", first.Choices[0].FinishReason)
			var args map[string]any
			require.NoError(t, json.Unmarshal([]byte(call.Function.Arguments), &args))
			assert.Contains(t, strings.ToLower(args["city"].(string)), "madrid")

			followUp, _ := json.Marshal(map[string]any{
				"messages": []any{
					map[string]any{"role": "user", "content": "What is the weather in Madrid right now? You must call the get_weather tool."},
					map[string]any{"role": "assistant", "content": first.Choices[0].Message.Content, "tool_calls": []any{
						map[string]any{"id": call.ID, "type": "function", "function": map[string]any{
							"name": call.Function.Name, "arguments": call.Function.Arguments,
						}},
					}},
					map[string]any{"role": "tool", "tool_call_id": call.ID, "content": `{"temperature_c": 31, "sky": "sunny"}`},
				},
				"tools":      json.RawMessage(strings.TrimPrefix(tools, `"tools": `)),
				"max_tokens": 128,
			})
			second, raw := completeOpenAI(t, model, string(followUp))
			t.Logf("second turn: %s", raw)
			assert.Empty(t, second.Choices[0].Message.ToolCalls)
			assert.Contains(t, second.Choices[0].Message.Content, "31")
		})
	}
}

func TestLive_CompletionsStream_OpenAIIngress(t *testing.T) {
	for _, model := range liveModels(t) {
		t.Run(model, func(t *testing.T) {
			reg := adapter.NewRegistry()
			wire, err := reg.AdaptRequest([]byte(`{
				"messages": [{"role": "user", "content": "Count from one to five in words, comma separated."}],
				"max_tokens": 64,
				"stream": true
			}`), adapter.FormatOpenAI, adapter.FormatBedrock)
			require.NoError(t, err)

			seq, err := NewBedrockClient().CompletionsStream(liveContext(t), liveConfig(model), wire)
			require.NoError(t, err)

			var (
				content, finish string
				events, chunks  int
				usage           bool
			)
			for line, streamErr := range seq {
				require.NoError(t, streamErr)
				if len(line) == 0 {
					continue
				}
				events++
				payload := bytes.TrimPrefix(line, []byte("data: "))
				out, err := reg.AdaptStreamChunk(payload, adapter.FormatOpenAI, adapter.FormatBedrock)
				require.NoError(t, err, "%s", line)
				for _, l := range out {
					if len(l) == 0 || bytes.Contains(l, []byte("[DONE]")) {
						continue
					}
					chunks++
					var chunk struct {
						Choices []struct {
							Delta struct {
								Content string `json:"content"`
							} `json:"delta"`
							FinishReason *string `json:"finish_reason"`
						} `json:"choices"`
						Usage *struct {
							TotalTokens int `json:"total_tokens"`
						} `json:"usage"`
					}
					require.NoError(t, json.Unmarshal(bytes.TrimPrefix(l, []byte("data: ")), &chunk), "%s", l)
					if chunk.Usage != nil && chunk.Usage.TotalTokens > 0 {
						usage = true
					}
					if len(chunk.Choices) > 0 {
						content += chunk.Choices[0].Delta.Content
						if fr := chunk.Choices[0].FinishReason; fr != nil && *fr != "" {
							finish = *fr
						}
					}
				}
			}
			t.Logf("%d converse events → %d openai chunks: %q", events, chunks, content)

			assert.Contains(t, strings.ToLower(content), "three")
			assert.Contains(t, []string{"stop", "length"}, finish, "chatty models run into maxTokens")
			assert.True(t, usage, "the metadata event must reach the client as usage")
			assert.Greater(t, chunks, 1, "the answer must arrive incrementally")
		})
	}
}

func TestLive_Completions_AnthropicIngress(t *testing.T) {
	for _, model := range liveModels(t) {
		t.Run(model, func(t *testing.T) {
			reg := adapter.NewRegistry()
			wire, err := reg.AdaptRequest([]byte(`{
				"model": "ignored-by-config",
				"system": "Answer in one word.",
				"messages": [{"role": "user", "content": [{"type": "text", "text": "What colour is the sky on a clear day?"}]}],
				"max_tokens": 16
			}`), adapter.FormatAnthropic, adapter.FormatBedrock)
			require.NoError(t, err)

			raw, err := NewBedrockClient().Completions(liveContext(t), liveConfig(model), wire)
			require.NoError(t, err, "Bedrock rejected the Converse body: %s", wire)

			out, err := reg.AdaptResponse(raw, adapter.FormatAnthropic, adapter.FormatBedrock)
			require.NoError(t, err)
			var resp struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
				StopReason string `json:"stop_reason"`
			}
			require.NoError(t, json.Unmarshal(out, &resp))
			require.NotEmpty(t, resp.Content)
			t.Logf("anthropic answer: %q", resp.Content[0].Text)
			assert.Contains(t, strings.ToLower(resp.Content[0].Text), "blue")
			assert.Contains(t, []string{"end_turn", "max_tokens"}, resp.StopReason, "chatty models run into maxTokens")
		})
	}
}

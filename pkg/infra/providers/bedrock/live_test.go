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
//	BEDROCK_LIVE_MODELS        comma-separated model IDs, inference profiles or
//	                           application-inference-profile ARNs (required)
//	AWS_REGION                 Bedrock region (default us-east-1)
//	BEDROCK_LIVE_CACHE_MODELS  comma-separated model IDs that support prompt
//	                           caching, for TestLive_PromptCache_UsageFold
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
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	bedrockTypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func liveModels(t *testing.T) []string {
	t.Helper()
	return liveModelsFrom(t, "BEDROCK_LIVE_MODELS")
}

func liveModelsFrom(t *testing.T, env string) []string {
	t.Helper()
	raw := os.Getenv(env)
	if raw == "" {
		t.Skip(env + " not set")
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

// TestLive_Completions_AnthropicOptions sends the Anthropic options the
// Converse encoder maps (structured output, top_k, a strict tool) to Claude
// models. Set BEDROCK_LIVE_MODELS to Claude models that still take top_k:
// Claude 5 models refuse it as deprecated.
func TestLive_Completions_AnthropicOptions(t *testing.T) {
	for _, model := range liveModels(t) {
		t.Run(model, func(t *testing.T) {
			reg := adapter.NewRegistry()
			wire, err := reg.AdaptRequest([]byte(`{
				"model": "ignored-by-config",
				"max_tokens": 256,
				"top_k": 40,
				"messages": [{"role": "user", "content": "Give the colour of a clear daytime sky."}],
				"tools": [{"name": "lookup", "description": "Unused.", "strict": true,
					"input_schema": {"type": "object", "properties": {"q": {"type": "string"}}, "required": ["q"], "additionalProperties": false}}],
				"output_config": {"format": {"type": "json_schema", "schema": {
					"type": "object", "properties": {"colour": {"type": "string"}}, "required": ["colour"], "additionalProperties": false}}}
			}`), adapter.FormatAnthropic, adapter.FormatBedrock)
			require.NoError(t, err)

			raw, err := NewBedrockClient().Completions(liveContext(t), liveConfig(model), wire)
			require.NoError(t, err, "Bedrock rejected the Converse body: %s", wire)

			out, err := reg.AdaptResponse(raw, adapter.FormatAnthropic, adapter.FormatBedrock)
			require.NoError(t, err)
			var resp struct {
				Content []struct {
					Type  string          `json:"type"`
					Text  string          `json:"text"`
					Input json.RawMessage `json:"input"`
				} `json:"content"`
			}
			require.NoError(t, json.Unmarshal(out, &resp))
			require.NotEmpty(t, resp.Content)
			for _, block := range resp.Content {
				switch block.Type {
				case "text":
					t.Logf("structured answer: %s", block.Text)
					var answer struct {
						Colour string `json:"colour"`
					}
					require.NoError(t, json.Unmarshal([]byte(block.Text), &answer), "the answer follows the schema")
					assert.Contains(t, strings.ToLower(answer.Colour), "blue")
				case "tool_use":
					t.Logf("strict tool call: %s", block.Input)
					var input map[string]any
					require.NoError(t, json.Unmarshal(block.Input, &input))
					assert.Contains(t, input, "q", "a strict call carries its required argument")
				}
			}
		})
	}
}

func cachedPrefix() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Run %d. You are a terse assistant. Reference material follows.\n", time.Now().UnixNano())
	for i := range 600 {
		fmt.Fprintf(&b, "Fact %d: the river number %d flows north for %d kilometres before it meets the sea.\n", i, i, i*7+3)
	}
	return b.String()
}

func cachedConverseInput(model, prefix string) *bedrockruntime.ConverseInput {
	return &bedrockruntime.ConverseInput{
		ModelId: aws.String(model),
		System: []bedrockTypes.SystemContentBlock{
			&bedrockTypes.SystemContentBlockMemberText{Value: prefix},
			&bedrockTypes.SystemContentBlockMemberCachePoint{Value: bedrockTypes.CachePointBlock{Type: bedrockTypes.CachePointTypeDefault}},
		},
		Messages: []bedrockTypes.Message{{
			Role:    bedrockTypes.ConversationRoleUser,
			Content: []bedrockTypes.ContentBlock{&bedrockTypes.ContentBlockMemberText{Value: "Reply with the single word OK."}},
		}},
		InferenceConfig: &bedrockTypes.InferenceConfiguration{MaxTokens: aws.Int32(16)},
	}
}

func assertFolded(t *testing.T, raw *adapter.ConverseUsage, cu *adapter.CanonicalUsage) {
	t.Helper()
	require.NotNil(t, raw)
	require.NotNil(t, cu)
	assert.Equal(t, raw.InputTokens+raw.CacheReadInputTokens+raw.CacheWriteInputTokens+raw.OutputTokens, raw.TotalTokens,
		"raw totalTokens already counts both cache buckets")
	assert.Equal(t, raw.InputTokens+raw.CacheReadInputTokens+raw.CacheWriteInputTokens, cu.InputTokens)
	assert.Equal(t, raw.CacheReadInputTokens, cu.CachedInputTokens)
	assert.Equal(t, raw.CacheWriteInputTokens, cu.CacheWriteInputTokens)
	assert.GreaterOrEqual(t, cu.TotalTokens, cu.InputTokens+cu.OutputTokens)
}

func TestLive_PromptCache_UsageFold(t *testing.T) {
	for _, model := range liveModelsFrom(t, "BEDROCK_LIVE_CACHE_MODELS") {
		t.Run(model, func(t *testing.T) {
			ctx := liveContext(t)
			c := NewBedrockClient().(*client)
			sdk, err := c.getOrCreateClient(ctx, liveConfig(model).Credentials)
			require.NoError(t, err)
			prefix := cachedPrefix()

			buffered := func(call string) (*adapter.ConverseUsage, *adapter.CanonicalUsage, []byte) {
				out, err := sdk.Converse(ctx, cachedConverseInput(model, prefix))
				require.NoError(t, err)
				raw, err := converseResponseJSON(out)
				require.NoError(t, err)
				var wire adapter.ConverseResponse
				require.NoError(t, json.Unmarshal(raw, &wire))
				cr, err := (&adapter.BedrockAdapter{}).DecodeResponse(raw)
				require.NoError(t, err)
				usage, err := json.Marshal(wire.Usage)
				require.NoError(t, err)
				t.Logf("%s raw usage: %s canonical: %+v", call, usage, *cr.Usage)
				return wire.Usage, cr.Usage, raw
			}

			firstRaw, firstCU, _ := buffered("first")
			assertFolded(t, firstRaw, firstCU)
			require.Positive(t, firstRaw.CacheReadInputTokens+firstRaw.CacheWriteInputTokens, "the prefix must be written to or read from the cache")

			var (
				secondRaw *adapter.ConverseUsage
				secondCU  *adapter.CanonicalUsage
				body      []byte
			)
			for attempt := range 4 {
				if attempt > 0 {
					time.Sleep(time.Duration(attempt+1) * time.Second)
				}
				secondRaw, secondCU, body = buffered(fmt.Sprintf("read attempt %d", attempt+1))
				assertFolded(t, secondRaw, secondCU)
				if secondRaw.CacheReadInputTokens > 0 {
					break
				}
			}
			require.Positive(t, secondRaw.CacheReadInputTokens, "a later call must read the cached prefix; cross-region profiles cache per region")
			assert.Less(t, secondRaw.InputTokens, secondRaw.CacheReadInputTokens, "raw inputTokens excludes the cache read")

			decoded, err := (&adapter.BedrockAdapter{}).DecodeResponse(body)
			require.NoError(t, err)
			reencoded, err := (&adapter.BedrockAdapter{}).EncodeResponse(decoded)
			require.NoError(t, err)
			var roundTrip adapter.ConverseResponse
			require.NoError(t, json.Unmarshal(reencoded, &roundTrip))
			require.NotNil(t, roundTrip.Usage)
			assert.Equal(t, secondRaw.InputTokens, roundTrip.Usage.InputTokens, "round-trip inputTokens")
			assert.Equal(t, secondRaw.CacheReadInputTokens, roundTrip.Usage.CacheReadInputTokens, "round-trip cacheReadInputTokens")
			assert.Equal(t, secondRaw.CacheWriteInputTokens, roundTrip.Usage.CacheWriteInputTokens, "round-trip cacheWriteInputTokens")
			assert.Equal(t, secondRaw.TotalTokens, roundTrip.Usage.TotalTokens, "round-trip totalTokens")
			if len(secondRaw.CacheDetails) > 0 {
				assert.ElementsMatch(t, secondRaw.CacheDetails, roundTrip.Usage.CacheDetails, "round-trip cacheDetails")
			}

			out, err := adapter.NewRegistry().AdaptResponse(body, adapter.FormatOpenAI, adapter.FormatBedrock)
			require.NoError(t, err)
			var resp openAIResponse
			require.NoError(t, json.Unmarshal(out, &resp))
			assert.Equal(t, secondCU.InputTokens, resp.Usage.PromptTokens)

			streamed := func(call string) (*adapter.ConverseUsage, *adapter.CanonicalUsage) {
				in := cachedConverseInput(model, prefix)
				stream, err := sdk.ConverseStream(ctx, &bedrockruntime.ConverseStreamInput{
					ModelId:         in.ModelId,
					System:          in.System,
					Messages:        in.Messages,
					InferenceConfig: in.InferenceConfig,
				})
				require.NoError(t, err)
				var (
					raw    *adapter.ConverseUsage
					merged *adapter.CanonicalUsage
				)
				for line, streamErr := range converseStreamLines(ctx, stream.GetStream()) {
					require.NoError(t, streamErr)
					if len(line) == 0 {
						continue
					}
					payload := bytes.TrimPrefix(line, []byte("data: "))
					var event adapter.ConverseStreamEvent
					require.NoError(t, json.Unmarshal(payload, &event))
					if event.Metadata != nil && event.Metadata.Usage != nil {
						raw = event.Metadata.Usage
					}
					chunk, err := (&adapter.BedrockAdapter{}).DecodeStreamChunk(payload)
					require.NoError(t, err)
					if chunk != nil && chunk.Usage != nil {
						merged = adapter.MergeUsage(merged, chunk.Usage)
					}
				}
				require.NotNil(t, raw, "the metadata event must carry usage")
				require.NotNil(t, merged, "decoded metadata must yield canonical usage")
				usage, err := json.Marshal(raw)
				require.NoError(t, err)
				t.Logf("%s stream raw usage: %s canonical: %+v", call, usage, *merged)
				return raw, merged
			}

			var (
				streamRaw *adapter.ConverseUsage
				streamCU  *adapter.CanonicalUsage
			)
			for attempt := range 4 {
				if attempt > 0 {
					time.Sleep(time.Duration(attempt+1) * time.Second)
				}
				streamRaw, streamCU = streamed(fmt.Sprintf("stream attempt %d", attempt+1))
				assertFolded(t, streamRaw, streamCU)
				if streamRaw.CacheReadInputTokens > 0 {
					break
				}
			}
			require.Positive(t, streamRaw.CacheReadInputTokens, "a streamed call must read the cached prefix; cross-region profiles cache per region")
			assert.Equal(t, streamRaw.CacheReadInputTokens, streamCU.CachedInputTokens)
		})
	}
}

// liveThinking is the thinking option for BEDROCK_LIVE_THINKING_MODELS:
// BEDROCK_LIVE_THINKING=adaptive for models that only take adaptive thinking
// (Claude 5), with the highest effort so the model does think, and enabled
// with a budget otherwise.
func liveThinking() string {
	if os.Getenv("BEDROCK_LIVE_THINKING") == "adaptive" {
		return `{"type": "adaptive"}, "output_config": {"effort": "max"}`
	}
	return `{"type": "enabled", "budget_tokens": 1024}`
}

const liveWeatherTool = `{"name": "get_weather", "description": "Current weather for a city.",
	"input_schema": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}}`

type anthropicLiveBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	Thinking  *string         `json:"thinking,omitempty"`
	Signature string          `json:"signature,omitempty"`
	Data      string          `json:"data,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
}

// anthropicTurn runs one Anthropic Messages request through the proxy path
// with thinking on, buffered or streamed, and returns the assistant content
// as the client would hold it.
func anthropicTurn(t *testing.T, model, messages string, stream bool) []anthropicLiveBlock {
	t.Helper()
	reg := adapter.NewRegistry()
	wire, err := reg.AdaptRequest([]byte(`{"model": "ignored-by-config", "max_tokens": 4096,
		"thinking": `+liveThinking()+`, "tools": [`+liveWeatherTool+`], "messages": `+messages+`}`),
		adapter.FormatAnthropic, adapter.FormatBedrock)
	require.NoError(t, err)

	if !stream {
		raw, err := NewBedrockClient().Completions(liveContext(t), liveConfig(model), wire)
		require.NoError(t, err, "Bedrock rejected the Converse body: %s", wire)
		out, err := reg.AdaptResponse(raw, adapter.FormatAnthropic, adapter.FormatBedrock)
		require.NoError(t, err)
		var resp struct {
			Content []anthropicLiveBlock `json:"content"`
		}
		require.NoError(t, json.Unmarshal(out, &resp))
		return resp.Content
	}

	seq, err := NewBedrockClient().CompletionsStream(liveContext(t), liveConfig(model), wire)
	require.NoError(t, err, "Bedrock rejected the Converse body: %s", wire)
	enc := adapter.NewAnthropicStreamEncoder(adapter.FormatBedrock).EmitSignedReasoning()
	var sse [][]byte
	var finish *adapter.CanonicalStreamChunk
	for line, streamErr := range seq {
		require.NoError(t, streamErr)
		payload := bytes.TrimPrefix(bytes.TrimSpace(line), []byte("data: "))
		if len(payload) == 0 {
			continue
		}
		chunk, err := reg.DecodeStreamChunkFor(payload, adapter.FormatBedrock)
		require.NoError(t, err)
		if chunk == nil {
			continue
		}
		if chunk.FinishReason != "" {
			finish = chunk
			continue
		}
		sse = append(sse, enc.Content(chunk)...)
	}
	require.NotNil(t, finish)
	sse = append(sse, enc.Finish(finish)...)
	return anthropicBlocksFromSSE(t, sse)
}

func anthropicBlocksFromSSE(t *testing.T, lines [][]byte) []anthropicLiveBlock {
	t.Helper()
	var blocks []anthropicLiveBlock
	var inputs []strings.Builder
	for _, line := range lines {
		payload, ok := bytes.CutPrefix(bytes.TrimSpace(line), []byte("data: "))
		if !ok {
			continue
		}
		var ev struct {
			Type         string             `json:"type"`
			Index        int                `json:"index"`
			ContentBlock anthropicLiveBlock `json:"content_block"`
			Delta        struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				Thinking    string `json:"thinking"`
				Signature   string `json:"signature"`
				PartialJSON string `json:"partial_json"`
			} `json:"delta"`
		}
		require.NoError(t, json.Unmarshal(payload, &ev), "%s", payload)
		switch ev.Type {
		case "content_block_start":
			require.Equal(t, len(blocks), ev.Index)
			blocks = append(blocks, ev.ContentBlock)
			inputs = append(inputs, strings.Builder{})
		case "content_block_delta":
			b := &blocks[ev.Index]
			switch ev.Delta.Type {
			case "text_delta":
				b.Text += ev.Delta.Text
			case "thinking_delta":
				thinking := *b.Thinking + ev.Delta.Thinking
				b.Thinking = &thinking
			case "signature_delta":
				b.Signature = ev.Delta.Signature
			case "input_json_delta":
				inputs[ev.Index].WriteString(ev.Delta.PartialJSON)
			}
		}
	}
	for i := range blocks {
		if blocks[i].Type == "tool_use" && inputs[i].Len() > 0 {
			blocks[i].Input = json.RawMessage(inputs[i].String())
		}
	}
	return blocks
}

// TestLive_AnthropicThinking_ToolLoop runs a tool loop with thinking and sends
// turn 1's content back exactly as the client got it, signatures included.
func TestLive_AnthropicThinking_ToolLoop(t *testing.T) {
	for _, model := range liveModelsFrom(t, "BEDROCK_LIVE_THINKING_MODELS") {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%v", model, stream), func(t *testing.T) {
				first := `[{"role": "user", "content": "What is the weather in Madrid? Use the tool."}]`
				turn1 := anthropicTurn(t, model, first, stream)

				var toolID string
				for _, b := range turn1 {
					switch b.Type {
					case "thinking":
						require.NotNil(t, b.Thinking, "a thinking block always carries its text field")
						assert.NotEmpty(t, b.Signature, "a thinking block comes back signed")
					case "tool_use":
						toolID = b.ID
					}
				}
				t.Logf("turn 1 blocks: %s", liveBlockTypes(turn1))
				require.NotEmpty(t, toolID, "the model called the tool")

				assistant, err := json.Marshal(turn1)
				require.NoError(t, err)
				second := `[{"role": "user", "content": "What is the weather in Madrid? Use the tool."},
					{"role": "assistant", "content": ` + string(assistant) + `},
					{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "` + toolID + `", "content": "22C, sunny"}]}]`
				turn2 := anthropicTurn(t, model, second, stream)
				t.Logf("turn 2 blocks: %s", liveBlockTypes(turn2))
				var answer string
				for _, b := range turn2 {
					answer += b.Text
				}
				assert.Contains(t, answer, "22")
			})
		}
	}
}

// TestLive_AnthropicThinking_RedactedRoundTrip asks for a redacted thinking
// block with the test string Anthropic documents and sends the turn back. A
// model that ignores the string still returns a signed block, sent back the
// same way.
func TestLive_AnthropicThinking_RedactedRoundTrip(t *testing.T) {
	const trigger = "ANTHROPIC_MAGIC_STRING_TRIGGER_REDACTED_THINKING_46C9A13E193C177646C7398A98432ECCCE4C1253D5E2D82641AC0E52CC2876CB"
	for _, model := range liveModelsFrom(t, "BEDROCK_LIVE_THINKING_MODELS") {
		t.Run(model, func(t *testing.T) {
			turn1 := anthropicTurn(t, model, `[{"role": "user", "content": "`+trigger+` Is 17 prime?"}]`, false)
			t.Logf("turn 1 blocks: %s", liveBlockTypes(turn1))
			reasoning := false
			for _, b := range turn1 {
				reasoning = reasoning || b.Type == "redacted_thinking" || b.Type == "thinking"
			}
			if !reasoning {
				t.Skip("the model returned no reasoning block")
			}
			assistant, err := json.Marshal(turn1)
			require.NoError(t, err)
			turn2 := anthropicTurn(t, model, `[{"role": "user", "content": "`+trigger+` Is 17 prime?"},
				{"role": "assistant", "content": `+string(assistant)+`},
				{"role": "user", "content": "And 21?"}]`, false)
			t.Logf("turn 2 blocks: %s", liveBlockTypes(turn2))
		})
	}
}

func liveBlockTypes(blocks []anthropicLiveBlock) string {
	types := make([]string, 0, len(blocks))
	for _, b := range blocks {
		types = append(types, b.Type)
	}
	return strings.Join(types, ",")
}

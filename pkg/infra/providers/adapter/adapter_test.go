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

package adapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testRegistry() *Registry { return NewRegistry() }

// usageDecoder is the minimal slice of ProviderAdapter the usage-extraction
// table tests exercise. Pulling it out lets us reuse one runner across all
// adapters.
type usageDecoder interface {
	DecodeResponse([]byte) (*CanonicalResponse, error)
	DecodeStreamChunk([]byte) (*CanonicalStreamChunk, error)
}

// usageCase is one row of a provider × {response,stream} × {with-usage,no-usage}
// table. wantUsage == nil asserts Requirement "Graceful Absence of Usage"
// (adapter returns nil, not a zero struct).
type usageCase struct {
	name      string
	body      []byte
	path      string
	wantUsage *CanonicalUsage
}

func runUsageCases(t *testing.T, dec usageDecoder, cases []usageCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got *CanonicalUsage
			switch tc.path {
			case "response":
				cr, err := dec.DecodeResponse(tc.body)
				require.NoError(t, err)
				require.NotNil(t, cr)
				got = cr.Usage
			case "stream":
				sc, err := dec.DecodeStreamChunk(tc.body)
				require.NoError(t, err)
				if sc != nil {
					got = sc.Usage
				}
			default:
				t.Fatalf("unknown path %q", tc.path)
			}
			if tc.wantUsage == nil {
				assert.Nil(t, got, "Usage must be nil when provider emits no usage fields")
				return
			}
			assert.Equal(t, tc.wantUsage, got)
		})
	}
}

// ---------------------------------------------------------------------------
// DetectFormat
// ---------------------------------------------------------------------------

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		expect Format
	}{
		{
			name:   "openai chat completion",
			body:   `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`,
			expect: FormatOpenAI,
		},
		{
			name:   "anthropic with anthropic_version",
			body:   `{"model":"claude-3","messages":[{"role":"user","content":"hi"}],"anthropic_version":"2023-06-01","max_tokens":1024}`,
			expect: FormatAnthropic,
		},
		{
			name:   "anthropic with system string",
			body:   `{"model":"claude-3","messages":[{"role":"user","content":"hi"}],"system":"you are helpful","max_tokens":1024}`,
			expect: FormatAnthropic,
		},
		{
			name:   "anthropic with system array (cache_control)",
			body:   `{"model":"claude-3","messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}],"system":[{"type":"text","text":"you are helpful","cache_control":{"type":"ephemeral"}}],"max_tokens":4096}`,
			expect: FormatAnthropic,
		},
		{
			name:   "gemini with contents",
			body:   `{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`,
			expect: FormatGemini,
		},
		{
			name:   "bedrock-native body with modelId is never detected as a source format",
			body:   `{"modelId":"eu.amazon.nova-micro-v1:0","messages":[{"role":"user","content":[{"text":"hi"}]}]}`,
			expect: FormatOpenAI,
		},
		{
			name:   "bedrock titan inputText body falls back to openai",
			body:   `{"inputText":"hello world"}`,
			expect: FormatOpenAI,
		},
		{
			name:   "invalid json defaults to openai",
			body:   `not json`,
			expect: FormatOpenAI,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectFormat([]byte(tt.body))
			assert.Equal(t, tt.expect, got)
		})
	}
}

// ---------------------------------------------------------------------------
// ResolveAgentFormat
// ---------------------------------------------------------------------------

func TestResolveAgentFormat_SourceFormatOverrides(t *testing.T) {
	got, err := ResolveAgentFormat("ignored", "openai_responses", nil)
	require.NoError(t, err)
	assert.Equal(t, FormatOpenAIResponses, got)
}

func TestResolveAgentFormat_OpenAIResponsesViaOptions(t *testing.T) {
	opts := map[string]any{"api": "responses"}
	got, err := ResolveAgentFormat("openai", "", opts)
	require.NoError(t, err)
	assert.Equal(t, FormatOpenAIResponses, got)

	gotAzure, err := ResolveAgentFormat("azure", "", opts)
	require.NoError(t, err)
	assert.Equal(t, FormatOpenAIResponses, gotAzure)
}

func TestResolveAgentFormat_KnownProviders(t *testing.T) {
	tests := []struct {
		provider string
		want     Format
	}{
		{"openai", FormatOpenAI},
		{"openai_compatible", FormatOpenAI},
		{"azure", FormatAzure},
		{"anthropic", FormatAnthropic},
		{"google", FormatGemini},
		{"bedrock", FormatBedrock},
		{"mistral", FormatMistral},
		{"vertex", FormatVertex},
		{"groq", FormatGroq},
		{"deepseek", FormatDeepSeek},
		{"cerebras", FormatOpenAI},
	}
	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			got, err := ResolveAgentFormat(tt.provider, "", nil)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestResolveAgentFormat_UnknownProvider(t *testing.T) {
	_, err := ResolveAgentFormat("unknown-provider", "", nil)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// IsSameWireFormat
// ---------------------------------------------------------------------------

func TestIsSameWireFormat(t *testing.T) {
	assert.True(t, IsSameWireFormat(FormatOpenAI, FormatAzure))
	assert.True(t, IsSameWireFormat(FormatAzure, FormatOpenAI))
	assert.True(t, IsSameWireFormat(FormatOpenAI, FormatOpenAI))
	assert.False(t, IsSameWireFormat(FormatOpenAI, FormatAnthropic))
	assert.False(t, IsSameWireFormat(FormatGemini, FormatAnthropic))
	assert.True(t, IsSameWireFormat("vertex", FormatGemini), "vertex should be wire-compatible with google/gemini")
	assert.True(t, IsSameWireFormat(FormatGemini, "vertex"), "google/gemini should be wire-compatible with vertex")
}

func TestResolveTargetFormat_Vertex(t *testing.T) {
	f := ResolveTargetFormat("vertex", nil)
	assert.Equal(t, Format("vertex"), f, "ResolveTargetFormat returns the raw format string")
	assert.True(t, IsSameWireFormat(f, FormatGemini), "vertex normalizes to gemini for adapter lookup")
}

func TestResolveTargetFormat_Groq(t *testing.T) {
	got := ResolveTargetFormat("groq", nil)

	assert.Equal(t, FormatGroq, got)
	assert.True(t, IsSameWireFormat(got, FormatOpenAI))
}

func TestResolveTargetFormat_OpenAIResponsesUnchanged(t *testing.T) {
	opts := map[string]any{"api": "responses"}

	assert.Equal(t, FormatOpenAIResponses, ResolveTargetFormat("openai", opts))
	assert.Equal(t, FormatOpenAIResponses, ResolveTargetFormat("azure", opts))
	assert.Equal(t, FormatGroq, ResolveTargetFormat("groq", opts))
}

func TestResolveTargetFormat_OpenAICompatible(t *testing.T) {
	// Generic OpenAI-compatible targets use the OpenAI Chat Completions wire
	// format. They are Chat Completions only, so the Responses API opt-in does
	// NOT apply even if an "api" option leaks into provider_options.
	got := ResolveTargetFormat("openai_compatible", map[string]any{"base_url": "https://host/v1"})
	assert.Equal(t, FormatOpenAI, got)
	assert.True(t, IsSameWireFormat(got, FormatOpenAI))

	assert.Equal(t, FormatOpenAI, ResolveTargetFormat("openai_compatible", map[string]any{"api": "responses"}),
		"openai_compatible must stay Chat Completions regardless of the api option")
}

// A client picks an OpenAI chat surface by calling either /v1/chat/completions
// or /v1/responses, and the gateway must serve the one it asked for instead of
// downgrading a Responses request to Chat Completions.
func TestResolveTargetFormatForCapability_MirrorsInboundRoute(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		source   Format
		options  map[string]any
		want     Format
	}{
		{
			name:     "responses route reaches the responses surface",
			provider: "openai",
			source:   FormatOpenAIResponses,
			want:     FormatOpenAIResponses,
		},
		{
			name:     "completions route reaches the completions surface",
			provider: "openai",
			source:   FormatOpenAI,
			want:     FormatOpenAI,
		},
		{
			// The Azure client only builds chat/completions URLs, so mirroring
			// there would produce a body its endpoint cannot accept.
			name:     "azure does not mirror the route",
			provider: "azure",
			source:   FormatOpenAIResponses,
			want:     FormatAzure,
		},
		{
			name:     "azure still honours an explicit api option",
			provider: "azure",
			source:   FormatOpenAI,
			options:  map[string]any{"api": "responses"},
			want:     FormatOpenAIResponses,
		},
		{
			name:     "an explicit api option overrides the route",
			provider: "openai",
			source:   FormatOpenAI,
			options:  map[string]any{"api": "responses"},
			want:     FormatOpenAIResponses,
		},
		{
			name:     "an explicit completions option overrides the route",
			provider: "openai",
			source:   FormatOpenAIResponses,
			options:  map[string]any{"api": "completions"},
			want:     FormatOpenAI,
		},
		{
			name:     "providers with a single chat surface ignore the route",
			provider: "anthropic",
			source:   FormatOpenAIResponses,
			want:     FormatAnthropic,
		},
		{
			name:     "openai_compatible stays chat completions",
			provider: "openai_compatible",
			source:   FormatOpenAIResponses,
			want:     FormatOpenAI,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ResolveTargetFormatForCapability(tc.provider, "chat", tc.source, tc.options)
			assert.Equal(t, tc.want, got)
		})
	}
}

// The provider client picks its endpoint from provider_options.api, so the
// resolved surface has to be restated there or the two decisions can disagree.
func TestOpenAIProviderOptionsForTarget(t *testing.T) {
	t.Run("responses target sets the api option", func(t *testing.T) {
		in := map[string]any{"base_url": "https://host/v1"}
		got := OpenAIProviderOptionsForTarget("openai", FormatOpenAIResponses, in)

		assert.Equal(t, "responses", got["api"])
		assert.Equal(t, "https://host/v1", got["base_url"])
		assert.NotContains(t, in, "api", "the registry options must not be mutated")
	})

	t.Run("completions target pins the api option", func(t *testing.T) {
		got := OpenAIProviderOptionsForTarget("openai", FormatOpenAI, nil)
		assert.Equal(t, "completions", got["api"])
	})

	t.Run("other providers are left alone", func(t *testing.T) {
		in := map[string]any{"project": "p"}
		assert.Equal(t, in, OpenAIProviderOptionsForTarget("vertex", FormatOpenAIResponses, in))
	})
}

// Embeddings and rerank have a single surface, so the chat route must not leak
// into them.
func TestResolveTargetFormatForCapability_NonChatCapabilitiesIgnoreRoute(t *testing.T) {
	assert.Equal(t, FormatOpenAIEmbeddings,
		ResolveTargetFormatForCapability("openai", "embeddings", FormatOpenAIResponses, nil))
	assert.Equal(t, FormatCohereEmbed,
		ResolveTargetFormatForCapability("cohere", "embeddings", FormatOpenAIResponses, nil))
	assert.Equal(t, FormatVertexEmbed,
		ResolveTargetFormatForCapability("vertex", "embeddings", FormatOpenAIEmbeddings, nil))
	assert.Equal(t, FormatBedrockTitanEmbed,
		ResolveTargetFormatForCapability("bedrock", "embeddings", FormatOpenAIEmbeddings, nil))
	assert.Equal(t, FormatCohereRerank,
		ResolveTargetFormatForCapability("cohere", "rerank", FormatOpenAIResponses, nil))
	assert.Equal(t, FormatOpenAIFiles,
		ResolveTargetFormatForCapability("openai", "files", FormatOpenAIResponses, nil))
	assert.Equal(t, FormatOpenAIFiles,
		ResolveTargetFormatForCapability("azure", "files", FormatOpenAI, nil))
	assert.Equal(t, FormatOpenAIImages,
		ResolveTargetFormatForCapability("openai", "images", FormatOpenAIResponses, nil))
	assert.Equal(t, FormatOpenAIImages,
		ResolveTargetFormatForCapability("azure", "images", FormatOpenAI, nil))
	assert.Equal(t, FormatOpenAIAudio,
		ResolveTargetFormatForCapability("openai", "audio_speech", FormatOpenAIResponses, nil))
	assert.Equal(t, FormatOpenAIAudio,
		ResolveTargetFormatForCapability("mistral", "audio_transcription", FormatOpenAI, nil))
}

// ---------------------------------------------------------------------------
// Cross-provider: OpenAI → Anthropic
// ---------------------------------------------------------------------------

func TestAdaptRequest_OpenAIToAnthropic(t *testing.T) {
	input := `{
		"model": "gpt-4",
		"messages": [
			{"role": "system", "content": "You are helpful."},
			{"role": "user", "content": "Hello"}
		],
		"max_tokens": 100,
		"temperature": 0.7,
		"tools": [
			{
				"type": "function",
				"function": {
					"name": "get_weather",
					"description": "Get weather info",
					"parameters": {"type": "object", "properties": {"city": {"type": "string"}}}
				}
			}
		],
		"tool_choice": "auto"
	}`

	out, err := testRegistry().AdaptRequest([]byte(input), FormatOpenAI, FormatAnthropic)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	// System extracted.
	assert.Equal(t, "You are helpful.", result["system"])

	// Messages should only contain user message.
	msgs, ok := result["messages"].([]interface{})
	require.True(t, ok)
	assert.Len(t, msgs, 1)

	// max_tokens present.
	assert.Equal(t, float64(100), result["max_tokens"])

	// temperature preserved.
	assert.Equal(t, 0.7, result["temperature"])

	// Tools adapted to Anthropic flat format (name, input_schema, description at top level).
	tools, ok := result["tools"].([]interface{})
	require.True(t, ok)
	assert.Len(t, tools, 1)
	tool := tools[0].(map[string]interface{})
	assert.Equal(t, "get_weather", tool["name"])
	assert.NotNil(t, tool["input_schema"])

	// tool_choice adapted.
	tc, ok := result["tool_choice"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "auto", tc["type"])
}

// ---------------------------------------------------------------------------
// Cross-provider: Anthropic → OpenAI
// ---------------------------------------------------------------------------

func TestAdaptRequest_AnthropicToOpenAI(t *testing.T) {
	input := `{
		"model": "claude-3-sonnet",
		"system": "You are helpful.",
		"messages": [
			{"role": "user", "content": "Hello"}
		],
		"max_tokens": 100,
		"temperature": 0.7
	}`

	out, err := testRegistry().AdaptRequest([]byte(input), FormatAnthropic, FormatOpenAI)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	msgs, ok := result["messages"].([]interface{})
	require.True(t, ok)
	assert.Len(t, msgs, 2) // system + user

	first := msgs[0].(map[string]interface{})
	assert.Equal(t, "system", first["role"])
	assert.Equal(t, "You are helpful.", first["content"])
}

func TestAdaptRequest_AnthropicServerToolBlockToOpenAI(t *testing.T) {
	input := `{
		"model": "gpt-5",
		"max_tokens": 100,
		"messages": [{"role": "user", "content": "Hello"}],
		"tools": [
			{"name": "Read", "description": "read", "input_schema": {"type": "object", "properties": {}}},
			{"type": "web_search_20250305"}
		]
	}`

	out, err := testRegistry().AdaptRequest([]byte(input), FormatAnthropic, FormatOpenAI)
	require.NoError(t, err)

	var result struct {
		Tools []struct {
			Function struct{ Name string } `json:"function"`
		} `json:"tools"`
	}
	require.NoError(t, json.Unmarshal(out, &result))
	require.Len(t, result.Tools, 1)
	assert.Equal(t, "Read", result.Tools[0].Function.Name)
	assert.NotContains(t, string(out), `"name":""`)
}

// ---------------------------------------------------------------------------
// Cross-provider: OpenAI → Gemini
// ---------------------------------------------------------------------------

func TestAdaptRequest_OpenAIToGemini(t *testing.T) {
	input := `{
		"model": "gpt-4",
		"messages": [
			{"role": "system", "content": "Be concise."},
			{"role": "user", "content": "Hello"},
			{"role": "assistant", "content": "Hi there!"},
			{"role": "user", "content": "How are you?"}
		],
		"max_tokens": 50,
		"temperature": 0.5
	}`

	out, err := testRegistry().AdaptRequest([]byte(input), FormatOpenAI, FormatGemini)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	// System → systemInstruction.
	si, ok := result["systemInstruction"].(map[string]interface{})
	require.True(t, ok)
	assert.NotNil(t, si["parts"])

	// contents should have 3 entries (user, model, user).
	contents, ok := result["contents"].([]interface{})
	require.True(t, ok)
	assert.Len(t, contents, 3)

	// Second entry should have role "model".
	second := contents[1].(map[string]interface{})
	assert.Equal(t, "model", second["role"])

	// generationConfig.
	gc, ok := result["generationConfig"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, float64(50), gc["maxOutputTokens"])
	assert.Equal(t, 0.5, gc["temperature"])
}

// ---------------------------------------------------------------------------
// Cross-provider: OpenAI → Bedrock (Converse wire format)
// ---------------------------------------------------------------------------

func TestAdaptRequest_OpenAIToBedrock(t *testing.T) {
	input := `{
		"model": "anthropic.claude-3-sonnet",
		"messages": [
			{"role": "system", "content": "Be helpful."},
			{"role": "user", "content": "Hello"}
		],
		"max_tokens": 100
	}`

	out, err := testRegistry().AdaptRequest([]byte(input), FormatOpenAI, FormatBedrock)
	require.NoError(t, err)

	var result ConverseRequest
	require.NoError(t, json.Unmarshal(out, &result))

	require.Len(t, result.System, 1)
	assert.Equal(t, "Be helpful.", result.System[0].Text)
	require.Len(t, result.Messages, 1)
	assert.Equal(t, "Hello", result.Messages[0].Content[0].Text)
	require.NotNil(t, result.InferenceConfig)
	assert.Equal(t, 100, result.InferenceConfig.MaxTokens)
}

// ---------------------------------------------------------------------------
// Same format passthrough
// ---------------------------------------------------------------------------

func TestAdaptRequest_SameFormat(t *testing.T) {
	input := `{"model":"gpt-4","messages":[]}`
	out, err := testRegistry().AdaptRequest([]byte(input), FormatOpenAI, FormatOpenAI)
	require.NoError(t, err)
	assert.JSONEq(t, input, string(out))
}

func TestAdaptRequest_AzureToOpenAI(t *testing.T) {
	input := `{"model":"gpt-4","messages":[]}`
	out, err := testRegistry().AdaptRequest([]byte(input), FormatAzure, FormatOpenAI)
	require.NoError(t, err)
	assert.JSONEq(t, input, string(out))
}

// ---------------------------------------------------------------------------
// Response: Anthropic → OpenAI
// ---------------------------------------------------------------------------

func TestAdaptResponse_AnthropicToOpenAI(t *testing.T) {
	input := `{
		"id": "msg_123",
		"type": "message",
		"role": "assistant",
		"model": "claude-3-sonnet",
		"content": [
			{"type": "text", "text": "Hello world"}
		],
		"stop_reason": "end_turn",
		"usage": {
			"input_tokens": 10,
			"output_tokens": 5
		}
	}`

	// target=anthropic produced this response, source=openai wants it.
	out, err := testRegistry().AdaptResponse([]byte(input), FormatOpenAI, FormatAnthropic)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	assert.Equal(t, "chat.completion", result["object"])
	assert.Equal(t, "msg_123", result["id"])

	choices, ok := result["choices"].([]interface{})
	require.True(t, ok)
	assert.Len(t, choices, 1)

	choice := choices[0].(map[string]interface{})
	msg := choice["message"].(map[string]interface{})
	assert.Equal(t, "Hello world", msg["content"])
	assert.Equal(t, "stop", choice["finish_reason"])

	usage := result["usage"].(map[string]interface{})
	assert.Equal(t, float64(10), usage["prompt_tokens"])
	assert.Equal(t, float64(5), usage["completion_tokens"])
	assert.Equal(t, float64(15), usage["total_tokens"])
}

// ---------------------------------------------------------------------------
// Stream: Anthropic → OpenAI
// ---------------------------------------------------------------------------

func TestAdaptStreamChunk_AnthropicContentDelta(t *testing.T) {
	input := `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}`
	lines, err := testRegistry().AdaptStreamChunk([]byte(input), FormatOpenAI, FormatAnthropic)
	require.NoError(t, err)
	require.NotEmpty(t, lines)

	// Find the "data: " line and parse its payload.
	var payload []byte
	for _, line := range lines {
		if bytes.HasPrefix(line, []byte("data: ")) {
			payload = bytes.TrimPrefix(line, []byte("data: "))
			break
		}
	}
	require.NotNil(t, payload, "expected a data: line in adapted output")

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(payload, &result))

	assert.Equal(t, "chat.completion.chunk", result["object"])
	choices := result["choices"].([]interface{})
	delta := choices[0].(map[string]interface{})["delta"].(map[string]interface{})
	assert.Equal(t, "Hello", delta["content"])
}

func TestAdaptStreamChunk_AnthropicNonContentSkipped(t *testing.T) {
	input := `{"type":"message_stop"}`
	out, err := testRegistry().AdaptStreamChunk([]byte(input), FormatOpenAI, FormatAnthropic)
	require.NoError(t, err)
	assert.Empty(t, out, "non-content events should be skipped")
}

// TestAdaptStreamChunk_OpenAIToolCallsToAnthropic ensures OpenAI stream chunks
// with tool_calls are converted to Anthropic content_block_start(tool_use) and
// content_block_delta(input_json_delta) so the agent receives a valid stream.
func TestAdaptStreamChunk_OpenAIToolCallsToAnthropic(t *testing.T) {
	// First chunk: role + tool_calls with id, name, empty arguments
	input := `{"id":"chatcmpl-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_abc","type":"function","function":{"name":"database_agent","arguments":""}}]}}]}`
	lines, err := testRegistry().AdaptStreamChunk([]byte(input), FormatAnthropic, FormatOpenAI)
	require.NoError(t, err)
	require.NotEmpty(t, lines)
	// Expect message_start and content_block_start(tool_use)
	var seenMessageStart, seenBlockStart bool
	for _, line := range lines {
		if bytes.Contains(line, []byte("message_start")) {
			seenMessageStart = true
		}
		if bytes.Contains(line, []byte("tool_use")) && bytes.Contains(line, []byte("database_agent")) {
			seenBlockStart = true
		}
	}
	assert.True(t, seenMessageStart, "expected message_start event")
	assert.True(t, seenBlockStart, "expected content_block_start with tool_use and name")

	// Chunk with only arguments delta
	input2 := `{"id":"chatcmpl-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"query\":\"test\"}"}}]}}]}`
	lines2, err := testRegistry().AdaptStreamChunk([]byte(input2), FormatAnthropic, FormatOpenAI)
	require.NoError(t, err)
	require.NotEmpty(t, lines2)
	var seenInputDelta bool
	for _, line := range lines2 {
		if bytes.Contains(line, []byte("input_json_delta")) && bytes.Contains(line, []byte("partial_json")) {
			seenInputDelta = true
			break
		}
	}
	assert.True(t, seenInputDelta, "expected content_block_delta with input_json_delta")
}

// ---------------------------------------------------------------------------
// Cross-format: Gemini → Anthropic (via canonical, no two-hop hack)
// ---------------------------------------------------------------------------

func TestAdaptRequest_GeminiToAnthropic(t *testing.T) {
	input := `{
		"contents": [
			{"role": "user", "parts": [{"text": "Hello"}]}
		],
		"systemInstruction": {"parts": [{"text": "Be brief."}]},
		"generationConfig": {"maxOutputTokens": 100}
	}`

	out, err := testRegistry().AdaptRequest([]byte(input), FormatGemini, FormatAnthropic)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	assert.Equal(t, "Be brief.", result["system"])
	msgs := result["messages"].([]interface{})
	assert.Len(t, msgs, 1)
	assert.Equal(t, float64(100), result["max_tokens"])
}

// ---------------------------------------------------------------------------
// OpenAI Completions vs Responses dispatcher (OpenAIAdapter handles both)
// ---------------------------------------------------------------------------

func TestCanonical_OpenAI_CompletionsVsResponsesDispatch(t *testing.T) {
	adapter := &OpenAIAdapter{}

	t.Run("completions request dispatched correctly", func(t *testing.T) {
		body := `{"model":"gpt-4","messages":[{"role":"user","content":"Hi"}]}`
		cr, err := adapter.DecodeRequest([]byte(body))
		require.NoError(t, err)
		assert.Len(t, cr.Messages, 1)
		assert.Equal(t, "Hi", cr.Messages[0].Content)
	})

	t.Run("responses request dispatched correctly", func(t *testing.T) {
		body := `{"model":"gpt-4o","input":"Hello"}`
		cr, err := adapter.DecodeRequest([]byte(body))
		require.NoError(t, err)
		assert.Len(t, cr.Messages, 1)
		assert.Equal(t, "Hello", cr.Messages[0].Content)
	})

	t.Run("completions response dispatched correctly", func(t *testing.T) {
		body := `{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4","choices":[{"index":0,"message":{"role":"assistant","content":"Hi!"},"finish_reason":"stop"}]}`
		cr, err := adapter.DecodeResponse([]byte(body))
		require.NoError(t, err)
		assert.Equal(t, "Hi!", cr.Content)
		assert.Equal(t, "stop", cr.FinishReason)
	})

	t.Run("responses response dispatched correctly", func(t *testing.T) {
		body := `{"id":"resp_1","object":"response","model":"gpt-4o","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Hey!"}]}]}`
		cr, err := adapter.DecodeResponse([]byte(body))
		require.NoError(t, err)
		assert.Equal(t, "Hey!", cr.Content)
		assert.Equal(t, "stop", cr.FinishReason)
	})

	t.Run("completions stream chunk dispatched correctly", func(t *testing.T) {
		chunk := `{"id":"chatcmpl-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"Hi"}}]}`
		sc, err := adapter.DecodeStreamChunk([]byte(chunk))
		require.NoError(t, err)
		require.NotNil(t, sc)
		assert.Equal(t, "Hi", sc.Delta)
	})

	t.Run("responses stream chunk dispatched correctly", func(t *testing.T) {
		chunk := `{"type":"response.output_text.delta","delta":"Hey"}`
		sc, err := adapter.DecodeStreamChunk([]byte(chunk))
		require.NoError(t, err)
		require.NotNil(t, sc)
		assert.Equal(t, "Hey", sc.Delta)
	})
}

// ---------------------------------------------------------------------------
// DetectFormat: Responses API distinction
// ---------------------------------------------------------------------------

func TestDetectFormat_ResponsesAPIInput(t *testing.T) {
	body := `{"model":"gpt-4o","input":"Hello"}`
	got := DetectFormat([]byte(body))
	assert.Equal(t, FormatOpenAIResponses, got)
}

func TestDetectFormat_ResponsesAPIInputArray(t *testing.T) {
	body := `{"model":"gpt-4o","input":[{"role":"user","content":"Hi"}]}`
	got := DetectFormat([]byte(body))
	assert.Equal(t, FormatOpenAIResponses, got)
}

func TestDetectFormat_CompletionsStillDetected(t *testing.T) {
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`
	got := DetectFormat([]byte(body))
	assert.Equal(t, FormatOpenAI, got)
}

// ---------------------------------------------------------------------------
// Cross-provider: Responses API request → Anthropic (via canonical)
// ---------------------------------------------------------------------------

func TestAdaptRequest_ResponsesAPIToAnthropic(t *testing.T) {
	input := `{
		"model": "gpt-4o",
		"instructions": "You are helpful.",
		"input": [
			{"role": "user", "content": "Hello"}
		],
		"max_output_tokens": 100,
		"temperature": 0.7
	}`

	out, err := testRegistry().AdaptRequest([]byte(input), FormatOpenAIResponses, FormatAnthropic)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	assert.Equal(t, "You are helpful.", result["system"])
	msgs := result["messages"].([]interface{})
	assert.Len(t, msgs, 1)
	assert.Equal(t, float64(100), result["max_tokens"])
}

// ---------------------------------------------------------------------------
// FormatOpenAIResponses: wire format isolation
// ---------------------------------------------------------------------------

func TestIsSameWireFormat_ResponsesVsCompletions(t *testing.T) {
	assert.False(t, IsSameWireFormat(FormatOpenAIResponses, FormatOpenAI),
		"Responses API and Completions are NOT wire-compatible")
	assert.True(t, IsSameWireFormat(FormatOpenAIResponses, FormatOpenAIResponses),
		"Same format should be wire-compatible")
	assert.False(t, IsSameWireFormat(FormatOpenAIResponses, FormatAnthropic),
		"Responses API and Anthropic are NOT wire-compatible")
}

// ---------------------------------------------------------------------------
// Cross-provider full roundtrip: Responses API client → Completions upstream
// ---------------------------------------------------------------------------

func TestAdaptResponse_CompletionsToResponsesAPI(t *testing.T) {
	completionsResp := `{
		"id": "chatcmpl-1",
		"object": "chat.completion",
		"model": "gpt-4",
		"choices": [{
			"index": 0,
			"message": {"role": "assistant", "content": "Hello from Completions!"},
			"finish_reason": "stop"
		}],
		"usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
	}`

	out, err := testRegistry().AdaptResponse([]byte(completionsResp), FormatOpenAIResponses, FormatOpenAI)
	require.NoError(t, err)

	var resp openaiResponsesResponse
	require.NoError(t, json.Unmarshal(out, &resp))

	assert.Equal(t, "response", resp.Object)
	assert.Equal(t, "completed", resp.Status)
	require.Len(t, resp.Output, 1)
	assert.Equal(t, "message", resp.Output[0].Type)
	assert.Equal(t, "Hello from Completions!", resp.Output[0].Content[0].Text)
	require.NotNil(t, resp.Usage)
	assert.Equal(t, 10, resp.Usage.InputTokens)
}

func TestAdaptRequest_ResponsesAPIToCompletions(t *testing.T) {
	responsesReq := `{
		"model": "gpt-4o",
		"instructions": "Be helpful.",
		"input": [{"role": "user", "content": "Hi"}],
		"max_output_tokens": 100
	}`

	out, err := testRegistry().AdaptRequest([]byte(responsesReq), FormatOpenAIResponses, FormatOpenAI)
	require.NoError(t, err)

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &raw))

	assert.NotNil(t, raw["messages"], "should be Completions format with 'messages'")
	assert.Nil(t, raw["input"], "should NOT have 'input' in Completions format")

	var msgs []map[string]interface{}
	require.NoError(t, json.Unmarshal(raw["messages"], &msgs))
	require.Len(t, msgs, 2) // system + user
	assert.Equal(t, "system", msgs[0]["role"])
	assert.Equal(t, "Be helpful.", msgs[0]["content"])
	assert.Equal(t, "user", msgs[1]["role"])
}

func TestAdaptStreamChunk_CompletionsToResponsesAPI(t *testing.T) {
	completionsChunk := `{"id":"chatcmpl-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"Hi"}}]}`

	lines, err := testRegistry().AdaptStreamChunk([]byte(completionsChunk), FormatOpenAIResponses, FormatOpenAI)
	require.NoError(t, err)
	require.NotEmpty(t, lines)

	joined := bytes.Join(lines, []byte("\n"))
	assert.Contains(t, string(joined), "response.output_text.delta")
	assert.Contains(t, string(joined), `"delta":"Hi"`)
}

func TestAdaptResponse_AnthropicToResponsesAPI(t *testing.T) {
	anthropicResp := `{
		"id": "msg_123",
		"type": "message",
		"role": "assistant",
		"content": [{"type": "text", "text": "Hello from Claude!"}],
		"model": "claude-3-sonnet",
		"stop_reason": "end_turn",
		"usage": {"input_tokens": 15, "output_tokens": 8}
	}`

	out, err := testRegistry().AdaptResponse([]byte(anthropicResp), FormatOpenAIResponses, FormatAnthropic)
	require.NoError(t, err)

	var resp openaiResponsesResponse
	require.NoError(t, json.Unmarshal(out, &resp))

	assert.Equal(t, "response", resp.Object)
	assert.Equal(t, "completed", resp.Status)
	require.Len(t, resp.Output, 1)
	assert.Equal(t, "message", resp.Output[0].Type)
	assert.Equal(t, "Hello from Claude!", resp.Output[0].Content[0].Text)
}

func TestAdaptRequest_Images(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		source      Format
		target      Format
		input       string
		wantContent string
		wantErr     error
	}{
		{
			name:        "openai data uri to anthropic",
			source:      FormatOpenAI,
			target:      FormatAnthropic,
			input:       `{"model":"gpt-4","messages":[{"role":"user","content":[{"type":"text","text":"what is this?"},{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA","detail":"high"}}]}]}`,
			wantContent: `[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AAAA"}},{"type":"text","text":"what is this?"}]`,
		},
		{
			name:        "openai url to anthropic",
			source:      FormatOpenAI,
			target:      FormatAnthropic,
			input:       `{"model":"gpt-4","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/cat.jpg"}},{"type":"text","text":"cat?"}]}]}`,
			wantContent: `[{"type":"image","source":{"type":"url","url":"https://example.com/cat.jpg"}},{"type":"text","text":"cat?"}]`,
		},
		{
			name:        "openai interleaved parts to anthropic",
			source:      FormatOpenAI,
			target:      FormatAnthropic,
			input:       `{"model":"gpt-4","messages":[{"role":"user","content":[{"type":"text","text":"A"},{"type":"image_url","image_url":{"url":"https://example.com/x.png"}},{"type":"text","text":"B"},{"type":"image_url","image_url":{"url":"https://example.com/y.png"}}]}]}`,
			wantContent: `[{"type":"image","source":{"type":"url","url":"https://example.com/x.png"}},{"type":"image","source":{"type":"url","url":"https://example.com/y.png"}},{"type":"text","text":"A\nB"}]`,
		},
		{
			name:    "openai ftp url to anthropic",
			source:  FormatOpenAI,
			target:  FormatAnthropic,
			input:   `{"model":"gpt-4","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"ftp://example.com/a.png"}}]}]}`,
			wantErr: ErrUnsupportedContent,
		},
		{
			name:        "anthropic webp to openai",
			source:      FormatAnthropic,
			target:      FormatOpenAI,
			input:       `{"model":"claude","max_tokens":10,"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/webp","data":"UklGR"}},{"type":"text","text":"describe"}]}]}`,
			wantContent: `[{"type":"image_url","image_url":{"url":"data:image/webp;base64,UklGR"}},{"type":"text","text":"describe"}]`,
		},
		{
			name:        "openai data uri to bedrock",
			source:      FormatOpenAI,
			target:      FormatBedrock,
			input:       `{"model":"gpt-4","messages":[{"role":"user","content":[{"type":"text","text":"what is this?"},{"type":"image_url","image_url":{"url":"data:image/jpeg;base64,/9j/4AAQ","detail":"low"}}]}]}`,
			wantContent: `[{"image":{"format":"jpeg","source":{"bytes":"/9j/4AAQ"}}},{"text":"what is this?"}]`,
		},
		{
			name:    "openai url to bedrock",
			source:  FormatOpenAI,
			target:  FormatBedrock,
			input:   `{"model":"gpt-4","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/cat.jpg"}},{"type":"text","text":"cat?"}]}]}`,
			wantErr: ErrUnsupportedContent,
		},
		{
			name:        "openai to openrouter passes parts through in client order",
			source:      FormatOpenAI,
			target:      FormatOpenRouter,
			input:       `{"model":"gpt-4","messages":[{"role":"user","content":[{"type":"text","text":"cat?"},{"type":"image_url","image_url":{"url":"https://example.com/cat.jpg","detail":"high"}}]}]}`,
			wantContent: `[{"type":"text","text":"cat?"},{"type":"image_url","image_url":{"url":"https://example.com/cat.jpg","detail":"high"}}]`,
		},
		{
			name:        "anthropic to bedrock",
			source:      FormatAnthropic,
			target:      FormatBedrock,
			input:       `{"model":"claude","max_tokens":10,"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0KGgo="}},{"type":"text","text":"describe"}]}]}`,
			wantContent: `[{"image":{"format":"png","source":{"bytes":"iVBORw0KGgo="}}},{"text":"describe"}]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out, err := testRegistry().AdaptRequest([]byte(tt.input), tt.source, tt.target)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			var got struct {
				Messages []struct {
					Role    string          `json:"role"`
					Content json.RawMessage `json:"content"`
				} `json:"messages"`
			}
			require.NoError(t, json.Unmarshal(out, &got))
			require.Len(t, got.Messages, 1)
			assert.Equal(t, "user", got.Messages[0].Role)
			assert.JSONEq(t, tt.wantContent, string(got.Messages[0].Content))
		})
	}
}

func TestAdaptRequest_ImageRegression(t *testing.T) {
	t.Parallel()

	const (
		textPart  = `{"type":"text","text":"what do you see?"}`
		imagePart = `{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgo="}}`
		request   = `{"model":"gpt-4","max_tokens":64,` +
			`"tools":[{"type":"function","function":{"name":"lookup","description":"Look up","parameters":{"type":"object","properties":{}}}}],` +
			`"messages":[{"role":"system","content":"be brief"},{"role":"user","content":[%s]}]}`
	)

	tests := []struct {
		name          string
		target        Format
		isImage       func(block map[string]json.RawMessage) bool
		textOnly      func(blocks []map[string]json.RawMessage) any
		wantPlainText string
	}{
		{
			name:          "anthropic",
			target:        FormatAnthropic,
			isImage:       func(b map[string]json.RawMessage) bool { return string(b["type"]) == `"image"` },
			textOnly:      func(b []map[string]json.RawMessage) any { return b[1]["text"] },
			wantPlainText: `"what do you see?"`,
		},
		{
			name:          "bedrock",
			target:        FormatBedrock,
			isImage:       func(b map[string]json.RawMessage) bool { _, ok := b["image"]; return ok },
			textOnly:      func(b []map[string]json.RawMessage) any { return b[1:] },
			wantPlainText: `[{"text":"what do you see?"}]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			plain, err := testRegistry().AdaptRequest([]byte(fmt.Sprintf(request, textPart)), FormatOpenAI, tt.target)
			require.NoError(t, err)
			withImage, err := testRegistry().AdaptRequest([]byte(fmt.Sprintf(request, textPart+","+imagePart)), FormatOpenAI, tt.target)
			require.NoError(t, err)

			var plainBody map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(plain, &plainBody))
			var plainMessages []map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(plainBody["messages"], &plainMessages))
			require.Len(t, plainMessages, 1)
			assert.JSONEq(t, tt.wantPlainText, string(plainMessages[0]["content"]))

			var body map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(withImage, &body))
			var messages []map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(body["messages"], &messages))
			require.Len(t, messages, 1)
			var blocks []map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(messages[0]["content"], &blocks))
			require.Len(t, blocks, 2)
			require.True(t, tt.isImage(blocks[0]), "the image block leads the user turn")
			require.False(t, tt.isImage(blocks[1]))

			messages[0]["content"], err = json.Marshal(tt.textOnly(blocks))
			require.NoError(t, err)
			body["messages"], err = json.Marshal(messages)
			require.NoError(t, err)
			stripped, err := json.Marshal(body)
			require.NoError(t, err)

			assert.JSONEq(t, string(plain), string(stripped))
		})
	}
}

func decodeUsageFromSSE(t *testing.T, a ProviderAdapter, lines [][]byte) *CanonicalUsage {
	t.Helper()
	var merged *CanonicalUsage
	for _, line := range lines {
		payload, ok := bytes.CutPrefix(line, []byte("data: "))
		if !ok {
			continue
		}
		chunk, err := a.DecodeStreamChunk(payload)
		require.NoError(t, err)
		if chunk != nil {
			merged = MergeUsage(merged, chunk.Usage)
		}
	}
	return merged
}

func TestUsageRoundTrip_ClientEncoders(t *testing.T) {
	chat := &CanonicalUsage{
		InputTokens: 2000, OutputTokens: 10, TotalTokens: 2010,
		CachedInputTokens: 1000, CacheWriteInputTokens: 500, ReasoningOutputTokens: 4,
	}
	withTTL := &CanonicalUsage{
		InputTokens: 2000, OutputTokens: 10, TotalTokens: 2010,
		CachedInputTokens: 1000, CacheWriteInputTokens: 300, CacheWrite1hInputTokens: 200, cacheTTLKnown: true,
	}
	fiveMinuteOnly := &CanonicalUsage{
		InputTokens: 2000, OutputTokens: 10, TotalTokens: 2010,
		CachedInputTokens: 1000, CacheWriteInputTokens: 300, cacheTTLKnown: true,
	}
	ttlUnknown := &CanonicalUsage{
		InputTokens: 2000, OutputTokens: 10, TotalTokens: 2010,
		CachedInputTokens: 1000, CacheWriteInputTokens: 300,
	}
	noCache := &CanonicalUsage{InputTokens: 20, OutputTokens: 10, TotalTokens: 30}

	tests := []struct {
		name   string
		format Format
		usage  *CanonicalUsage
	}{
		{name: "openai chat", format: FormatOpenAI, usage: chat},
		{name: "openai chat without cache", format: FormatOpenAI, usage: noCache},
		{name: "openai responses", format: FormatOpenAIResponses, usage: chat},
		{name: "openai responses without cache", format: FormatOpenAIResponses, usage: noCache},
		{name: "cohere", format: FormatCohere, usage: &CanonicalUsage{InputTokens: 2000, OutputTokens: 10, TotalTokens: 2010, CachedInputTokens: 1000}},
		{name: "cohere without cache", format: FormatCohere, usage: noCache},
		{name: "anthropic with a 1h share", format: FormatAnthropic, usage: withTTL},
		{name: "anthropic five-minute only", format: FormatAnthropic, usage: fiveMinuteOnly},
		{name: "anthropic ttl unknown", format: FormatAnthropic, usage: ttlUnknown},
		{name: "anthropic without cache", format: FormatAnthropic, usage: noCache},
		{name: "bedrock with a 1h share", format: FormatBedrock, usage: withTTL},
		{name: "bedrock five-minute only", format: FormatBedrock, usage: fiveMinuteOnly},
		{name: "bedrock ttl unknown", format: FormatBedrock, usage: ttlUnknown},
		{name: "bedrock without cache", format: FormatBedrock, usage: noCache},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := testRegistry().GetAdapter(tt.format)
			require.NoError(t, err)

			body, err := a.EncodeResponse(&CanonicalResponse{Role: "assistant", Content: "ok", FinishReason: "stop", Usage: tt.usage})
			require.NoError(t, err)
			back, err := a.DecodeResponse(body)
			require.NoError(t, err)
			assert.Equal(t, tt.usage, back.Usage, "buffered")

			var lines [][]byte
			for _, chunk := range []*CanonicalStreamChunk{
				{Role: "assistant"},
				{Delta: "ok"},
				{FinishReason: "stop", Usage: tt.usage},
			} {
				out, err := a.EncodeStreamChunk(chunk)
				require.NoError(t, err)
				lines = append(lines, out...)
			}
			assert.Equal(t, tt.usage, decodeUsageFromSSE(t, a, lines), "stream")
		})
	}
}

func TestAnthropicSSEUsage_CacheCreationBreakdown(t *testing.T) {
	usage := &CanonicalUsage{InputTokens: 400, OutputTokens: 1, TotalTokens: 401, CacheWriteInputTokens: 300, CacheWrite1hInputTokens: 200}

	lines, err := (&AnthropicAdapter{}).EncodeStreamChunk(&CanonicalStreamChunk{Role: "assistant", Usage: usage})
	require.NoError(t, err)

	var start struct {
		Message struct {
			Usage map[string]json.RawMessage `json:"usage"`
		} `json:"message"`
	}
	for _, line := range lines {
		if payload, ok := bytes.CutPrefix(line, []byte("data: ")); ok {
			require.NoError(t, json.Unmarshal(payload, &start))
			break
		}
	}
	assert.JSONEq(t, `{"ephemeral_5m_input_tokens":100,"ephemeral_1h_input_tokens":200}`, string(start.Message.Usage["cache_creation"]))
	assert.JSONEq(t, `100`, string(start.Message.Usage["input_tokens"]))
}

func TestAnthropicUsage_CacheCreationWireCarriesBothKeys(t *testing.T) {
	tests := []struct {
		name  string
		usage *CanonicalUsage
		want  string
	}{
		{
			name:  "five-minute-only write",
			usage: &CanonicalUsage{InputTokens: 400, OutputTokens: 1, TotalTokens: 401, CacheWriteInputTokens: 300, cacheTTLKnown: true},
			want:  `{"ephemeral_5m_input_tokens":300,"ephemeral_1h_input_tokens":0}`,
		},
		{
			name:  "ttl known without a write",
			usage: &CanonicalUsage{InputTokens: 400, OutputTokens: 1, TotalTokens: 401, CachedInputTokens: 100, cacheTTLKnown: true},
			want:  `{"ephemeral_5m_input_tokens":0,"ephemeral_1h_input_tokens":0}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &AnthropicAdapter{}

			body, err := a.EncodeResponse(&CanonicalResponse{Role: "assistant", Content: "ok", FinishReason: "stop", Usage: tt.usage})
			require.NoError(t, err)
			var buffered struct {
				Usage map[string]json.RawMessage `json:"usage"`
			}
			require.NoError(t, json.Unmarshal(body, &buffered))
			assert.JSONEq(t, tt.want, string(buffered.Usage["cache_creation"]), "buffered")

			lines, err := a.EncodeStreamChunk(&CanonicalStreamChunk{Role: "assistant", Usage: tt.usage})
			require.NoError(t, err)
			var start struct {
				Message struct {
					Usage map[string]json.RawMessage `json:"usage"`
				} `json:"message"`
			}
			for _, line := range lines {
				if payload, ok := bytes.CutPrefix(line, []byte("data: ")); ok {
					require.NoError(t, json.Unmarshal(payload, &start))
					break
				}
			}
			assert.JSONEq(t, tt.want, string(start.Message.Usage["cache_creation"]), "stream")
		})
	}
}

func TestAnthropicUsage_OneHourShareClampedToWrite(t *testing.T) {
	body := []byte(`{"id":"m","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn",
		"usage":{"input_tokens":10,"output_tokens":1,"cache_creation_input_tokens":50,"cache_creation":{"ephemeral_1h_input_tokens":200}}}`)

	cr, err := (&AnthropicAdapter{}).DecodeResponse(body)
	require.NoError(t, err)

	assert.Equal(t, 50, cr.Usage.CacheWriteInputTokens)
	assert.Equal(t, 50, cr.Usage.CacheWrite1hInputTokens)
}

func TestUsageUnfold_CacheAboveInput(t *testing.T) {
	usage := &CanonicalUsage{InputTokens: 10, OutputTokens: 2, TotalTokens: 12, CachedInputTokens: 8, CacheWriteInputTokens: 5}
	require.Equal(t, 0, usage.PlainInputTokens())

	anthropicBody, err := (&AnthropicAdapter{}).EncodeResponse(&CanonicalResponse{Role: "assistant", Content: "ok", FinishReason: "stop", Usage: usage})
	require.NoError(t, err)
	var anthropicWire anthropicResponse
	require.NoError(t, json.Unmarshal(anthropicBody, &anthropicWire))
	assert.Equal(t, 0, anthropicWire.Usage.InputTokens)

	bedrockBody, err := (&BedrockAdapter{}).EncodeResponse(&CanonicalResponse{Role: "assistant", Content: "ok", FinishReason: "stop", Usage: usage})
	require.NoError(t, err)
	var bedrockWire ConverseResponse
	require.NoError(t, json.Unmarshal(bedrockBody, &bedrockWire))
	assert.Equal(t, 0, bedrockWire.Usage.InputTokens)
}

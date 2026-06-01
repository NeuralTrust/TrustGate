package adapter

import (
	"bytes"
	"encoding/json"
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
			name:   "bedrock titan with inputText",
			body:   `{"inputText":"hello world"}`,
			expect: FormatBedrock,
		},
		{
			name:   "bedrock legacy claude with prompt",
			body:   `{"prompt":"Human: hi\n\nAssistant:","max_tokens_to_sample":200}`,
			expect: FormatBedrock,
		},
		{
			name: "bedrock native with modelId and messages",
			body: `{
				"modelId": "eu.amazon.nova-micro-v1:0",
				"messages": [{"role":"user","content":[{"text":"hi"}]}]
			}`,
			expect: FormatBedrock,
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
		{"azure", FormatAzure},
		{"anthropic", FormatAnthropic},
		{"google", FormatGemini},
		{"bedrock", FormatBedrock},
		{"mistral", FormatMistral},
		{"vertex", FormatVertex},
		{"groq", FormatGroq},
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

// ---------------------------------------------------------------------------
// ValidateModel
// ---------------------------------------------------------------------------

func TestValidateModel(t *testing.T) {
	t.Run("allowed model passes through", func(t *testing.T) {
		body := []byte(`{"model":"gpt-4","messages":[]}`)
		out, model, err := ValidateModel(body, []string{"gpt-4", "gpt-3.5-turbo"}, "gpt-3.5-turbo")
		require.NoError(t, err)
		assert.Equal(t, "gpt-4", model)
		assert.Contains(t, string(out), `"gpt-4"`)
	})

	t.Run("disallowed model replaced", func(t *testing.T) {
		body := []byte(`{"model":"gpt-4","messages":[]}`)
		out, model, err := ValidateModel(body, []string{"gpt-3.5-turbo"}, "gpt-3.5-turbo")
		require.NoError(t, err)
		assert.Equal(t, "gpt-3.5-turbo", model)
		assert.Contains(t, string(out), `"gpt-3.5-turbo"`)
	})

	t.Run("empty allowedModels accepts all", func(t *testing.T) {
		body := []byte(`{"model":"anything","messages":[]}`)
		_, model, err := ValidateModel(body, nil, "default")
		require.NoError(t, err)
		assert.Equal(t, "anything", model)
	})

	t.Run("modelId passes through", func(t *testing.T) {
		body := []byte(`{"modelId":"eu.amazon.nova-micro-v1:0","messages":[]}`)
		out, model, err := ValidateModel(body, []string{"eu.amazon.nova-micro-v1:0"}, "anthropic.claude-sonnet-4-20250514-v1:0")
		require.NoError(t, err)
		assert.Equal(t, "eu.amazon.nova-micro-v1:0", model)
		assert.Contains(t, string(out), `"modelId":"eu.amazon.nova-micro-v1:0"`)
		assert.NotContains(t, string(out), `"model":"anthropic.claude-sonnet-4-20250514-v1:0"`)
	})

	t.Run("modelId is not silently replaced", func(t *testing.T) {
		body := []byte(`{"modelId":"eu.amazon.nova-micro-v1:0","messages":[]}`)
		out, model, err := ValidateModel(body, []string{"amazon.nova-pro-v1:0"}, "amazon.nova-pro-v1:0")
		require.NoError(t, err)
		assert.Equal(t, "eu.amazon.nova-micro-v1:0", model)
		assert.Contains(t, string(out), `"modelId":"eu.amazon.nova-micro-v1:0"`)
		assert.NotContains(t, string(out), `"amazon.nova-pro-v1:0"`)
	})

	t.Run("no model field in body injects default", func(t *testing.T) {
		body := []byte(`{"messages":[]}`)
		out, model, err := ValidateModel(body, []string{"gpt-4"}, "gpt-4")
		require.NoError(t, err)
		assert.Equal(t, "gpt-4", model)
		assert.Contains(t, string(out), `"model"`)
		assert.Contains(t, string(out), `"gpt-4"`)
	})

	t.Run("no model field no default returns unchanged", func(t *testing.T) {
		body := []byte(`{"messages":[]}`)
		out, model, err := ValidateModel(body, nil, "")
		require.NoError(t, err)
		assert.Equal(t, "", model)
		assert.NotContains(t, string(out), `"model"`)
	})
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
// Cross-provider: OpenAI → Bedrock (should get anthropic_version)
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

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	assert.Equal(t, "bedrock-2023-05-31", result["anthropic_version"])
	assert.Equal(t, "Be helpful.", result["system"])
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

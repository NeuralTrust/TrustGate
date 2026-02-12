package adapter

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
// IsSameWireFormat
// ---------------------------------------------------------------------------

func TestIsSameWireFormat(t *testing.T) {
	assert.True(t, IsSameWireFormat(FormatOpenAI, FormatAzure))
	assert.True(t, IsSameWireFormat(FormatAzure, FormatOpenAI))
	assert.True(t, IsSameWireFormat(FormatOpenAI, FormatOpenAI))
	assert.False(t, IsSameWireFormat(FormatOpenAI, FormatAnthropic))
	assert.False(t, IsSameWireFormat(FormatGemini, FormatAnthropic))
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
// Canonical roundtrip: OpenAI → Canonical → OpenAI
// ---------------------------------------------------------------------------

func TestCanonical_OpenAI_Roundtrip(t *testing.T) {
	input := `{
		"model": "gpt-4",
		"messages": [
			{"role": "system", "content": "You are helpful."},
			{"role": "user", "content": "Hello"}
		],
		"max_tokens": 100,
		"temperature": 0.7
	}`

	adapter := &OpenAIAdapter{}

	canonical, err := adapter.DecodeRequest([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, "gpt-4", canonical.Model)
	assert.Equal(t, "You are helpful.", canonical.System)
	assert.Len(t, canonical.Messages, 1) // system extracted
	assert.Equal(t, "user", canonical.Messages[0].Role)
	assert.Equal(t, 100, canonical.MaxTokens)
	assert.Equal(t, 0.7, *canonical.Temperature)

	encoded, err := adapter.EncodeRequest(canonical)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(encoded, &result))
	msgs := result["messages"].([]interface{})
	assert.Len(t, msgs, 2) // system re-injected + user
	assert.Equal(t, "system", msgs[0].(map[string]interface{})["role"])
}

// ---------------------------------------------------------------------------
// Canonical roundtrip: Anthropic → Canonical → Anthropic
// ---------------------------------------------------------------------------

func TestCanonical_Anthropic_Roundtrip(t *testing.T) {
	input := `{
		"model": "claude-3-sonnet",
		"system": "You are helpful.",
		"messages": [
			{"role": "user", "content": "Hello"}
		],
		"max_tokens": 100,
		"temperature": 0.7
	}`

	adapter := &AnthropicAdapter{}

	canonical, err := adapter.DecodeRequest([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, "claude-3-sonnet", canonical.Model)
	assert.Equal(t, "You are helpful.", canonical.System)
	assert.Len(t, canonical.Messages, 1)
	assert.Equal(t, 100, canonical.MaxTokens)

	encoded, err := adapter.EncodeRequest(canonical)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(encoded, &result))
	assert.Equal(t, "You are helpful.", result["system"])
	msgs := result["messages"].([]interface{})
	assert.Len(t, msgs, 1)
}

// ---------------------------------------------------------------------------
// Canonical roundtrip: Gemini → Canonical → Gemini
// ---------------------------------------------------------------------------

func TestCanonical_Gemini_Roundtrip(t *testing.T) {
	input := `{
		"contents": [
			{"role": "user", "parts": [{"text": "Hello"}]},
			{"role": "model", "parts": [{"text": "Hi!"}]}
		],
		"systemInstruction": {"parts": [{"text": "Be concise."}]},
		"generationConfig": {
			"maxOutputTokens": 50,
			"temperature": 0.5
		}
	}`

	adapter := &GeminiAdapter{}

	canonical, err := adapter.DecodeRequest([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, "Be concise.", canonical.System)
	assert.Len(t, canonical.Messages, 2)
	assert.Equal(t, "user", canonical.Messages[0].Role)
	assert.Equal(t, "assistant", canonical.Messages[1].Role) // model → assistant
	assert.Equal(t, 50, canonical.MaxTokens)

	encoded, err := adapter.EncodeRequest(canonical)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(encoded, &result))
	contents := result["contents"].([]interface{})
	assert.Len(t, contents, 2)
	second := contents[1].(map[string]interface{})
	assert.Equal(t, "model", second["role"]) // assistant → model
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

	out, err := AdaptRequest([]byte(input), FormatOpenAI, FormatAnthropic)
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

	// Tools adapted to Anthropic format.
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

	out, err := AdaptRequest([]byte(input), FormatAnthropic, FormatOpenAI)
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

	out, err := AdaptRequest([]byte(input), FormatOpenAI, FormatGemini)
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

	out, err := AdaptRequest([]byte(input), FormatOpenAI, FormatBedrock)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	assert.Equal(t, "bedrock-2023-05-31", result["anthropic_version"])
	assert.Equal(t, "Be helpful.", result["system"])
}

// ---------------------------------------------------------------------------
// Bedrock Titan: OpenAI → Bedrock (Titan model)
// ---------------------------------------------------------------------------

func TestAdaptRequest_OpenAIToBedrockTitan(t *testing.T) {
	input := `{
		"model": "amazon.titan-text-express-v1",
		"messages": [
			{"role": "system", "content": "You are helpful."},
			{"role": "user", "content": "Hello, Titan!"}
		],
		"max_tokens": 200,
		"temperature": 0.8
	}`

	adapter := &BedrockAdapter{}

	// Step 1: Decode from OpenAI to canonical (via OpenAI adapter).
	oa := &OpenAIAdapter{}
	canonical, err := oa.DecodeRequest([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, "amazon.titan-text-express-v1", canonical.Model)
	assert.Equal(t, "You are helpful.", canonical.System)

	// Step 2: Encode canonical to Bedrock (dispatches to Titan).
	out, err := adapter.EncodeRequest(canonical)
	require.NoError(t, err)

	var result titanRequest
	require.NoError(t, json.Unmarshal(out, &result))

	assert.Contains(t, result.InputText, "You are helpful.")
	assert.Contains(t, result.InputText, "Hello, Titan!")
	require.NotNil(t, result.TextGenerationConfig)
	assert.Equal(t, 200, result.TextGenerationConfig.MaxTokenCount)
	assert.InDelta(t, 0.8, *result.TextGenerationConfig.Temperature, 0.001)
}

func TestBedrock_Titan_ResponseDecode(t *testing.T) {
	body := `{
		"inputTextTokenCount": 15,
		"results": [{
			"tokenCount": 42,
			"outputText": "Hello! I am Titan.",
			"completionReason": "FINISH"
		}]
	}`

	adapter := &BedrockAdapter{}
	cr, err := adapter.DecodeResponse([]byte(body))
	require.NoError(t, err)
	assert.Equal(t, "Hello! I am Titan.", cr.Content)
	assert.Equal(t, "stop", cr.FinishReason)
	require.NotNil(t, cr.Usage)
	assert.Equal(t, 15, cr.Usage.PromptTokens)
	assert.Equal(t, 42, cr.Usage.CompletionTokens)
}

func TestBedrock_Titan_StreamChunkDecode(t *testing.T) {
	chunk := `{"outputText": "Hello from Titan"}`
	adapter := &BedrockAdapter{}
	sc, err := adapter.DecodeStreamChunk([]byte(chunk))
	require.NoError(t, err)
	require.NotNil(t, sc)
	assert.Equal(t, "Hello from Titan", sc.Delta)
}

// ---------------------------------------------------------------------------
// Bedrock Llama: OpenAI → Bedrock (Llama model)
// ---------------------------------------------------------------------------

func TestAdaptRequest_OpenAIToBedrockLlama(t *testing.T) {
	input := `{
		"model": "meta.llama3-70b-instruct-v1:0",
		"messages": [
			{"role": "system", "content": "You are a helpful assistant."},
			{"role": "user", "content": "What is Go?"}
		],
		"max_tokens": 512,
		"temperature": 0.6
	}`

	oa := &OpenAIAdapter{}
	canonical, err := oa.DecodeRequest([]byte(input))
	require.NoError(t, err)

	adapter := &BedrockAdapter{}
	out, err := adapter.EncodeRequest(canonical)
	require.NoError(t, err)

	var result llamaRequest
	require.NoError(t, json.Unmarshal(out, &result))

	assert.Contains(t, result.Prompt, "<|begin_of_text|>")
	assert.Contains(t, result.Prompt, "system")
	assert.Contains(t, result.Prompt, "You are a helpful assistant.")
	assert.Contains(t, result.Prompt, "What is Go?")
	assert.Contains(t, result.Prompt, "assistant") // assistant turn open
	assert.Equal(t, 512, result.MaxGenLen)
	assert.InDelta(t, 0.6, *result.Temperature, 0.001)
}

func TestBedrock_Llama_ResponseDecode(t *testing.T) {
	body := `{
		"generation": "Go is a programming language by Google.",
		"prompt_token_count": 25,
		"generation_token_count": 8,
		"stop_reason": "stop"
	}`

	adapter := &BedrockAdapter{}
	cr, err := adapter.DecodeResponse([]byte(body))
	require.NoError(t, err)
	assert.Equal(t, "Go is a programming language by Google.", cr.Content)
	assert.Equal(t, "stop", cr.FinishReason)
	require.NotNil(t, cr.Usage)
	assert.Equal(t, 25, cr.Usage.PromptTokens)
	assert.Equal(t, 8, cr.Usage.CompletionTokens)
}

func TestBedrock_Llama_StreamChunkDecode(t *testing.T) {
	chunk := `{"generation": "Hello from Llama", "stop_reason": null}`
	adapter := &BedrockAdapter{}
	sc, err := adapter.DecodeStreamChunk([]byte(chunk))
	require.NoError(t, err)
	require.NotNil(t, sc)
	assert.Equal(t, "Hello from Llama", sc.Delta)
}

// ---------------------------------------------------------------------------
// Bedrock Mistral: OpenAI → Bedrock (Mistral model)
// ---------------------------------------------------------------------------

func TestAdaptRequest_OpenAIToBedrockMistral(t *testing.T) {
	input := `{
		"model": "mistral.mistral-large-2407-v1:0",
		"messages": [
			{"role": "user", "content": "Explain AI"}
		],
		"max_tokens": 300
	}`

	oa := &OpenAIAdapter{}
	canonical, err := oa.DecodeRequest([]byte(input))
	require.NoError(t, err)

	adapter := &BedrockAdapter{}
	out, err := adapter.EncodeRequest(canonical)
	require.NoError(t, err)

	var result mistralRequest
	require.NoError(t, json.Unmarshal(out, &result))

	assert.Contains(t, result.Prompt, "<s>")
	assert.Contains(t, result.Prompt, "[INST]")
	assert.Contains(t, result.Prompt, "Explain AI")
	assert.Contains(t, result.Prompt, "[/INST]")
	assert.Equal(t, 300, result.MaxTokens)
}

func TestBedrock_Mistral_ResponseDecode(t *testing.T) {
	body := `{"outputs": [{"text": "AI is artificial intelligence.", "stop_reason": "stop"}]}`

	adapter := &BedrockAdapter{}
	cr, err := adapter.DecodeResponse([]byte(body))
	require.NoError(t, err)
	assert.Equal(t, "AI is artificial intelligence.", cr.Content)
	assert.Equal(t, "stop", cr.FinishReason)
}

func TestBedrock_Mistral_StreamChunkDecode(t *testing.T) {
	chunk := `{"outputs": [{"text": "Hello from Mistral", "stop_reason": ""}]}`
	adapter := &BedrockAdapter{}
	sc, err := adapter.DecodeStreamChunk([]byte(chunk))
	require.NoError(t, err)
	require.NotNil(t, sc)
	assert.Equal(t, "Hello from Mistral", sc.Delta)
}

// ---------------------------------------------------------------------------
// Bedrock: Decode incoming model-specific requests
// ---------------------------------------------------------------------------

func TestBedrock_DecodeTitanRequest(t *testing.T) {
	body := `{
		"inputText": "Hello Titan",
		"textGenerationConfig": {"maxTokenCount": 100, "temperature": 0.5}
	}`
	adapter := &BedrockAdapter{}
	cr, err := adapter.DecodeRequest([]byte(body))
	require.NoError(t, err)
	require.Len(t, cr.Messages, 1)
	assert.Equal(t, "Hello Titan", cr.Messages[0].Content)
	assert.Equal(t, 100, cr.MaxTokens)
	assert.InDelta(t, 0.5, *cr.Temperature, 0.001)
}

func TestBedrock_DecodeLlamaRequest(t *testing.T) {
	body := `{"prompt": "Hello Llama", "max_gen_len": 256, "temperature": 0.7}`
	adapter := &BedrockAdapter{}
	cr, err := adapter.DecodeRequest([]byte(body))
	require.NoError(t, err)
	require.Len(t, cr.Messages, 1)
	assert.Equal(t, "Hello Llama", cr.Messages[0].Content)
	assert.Equal(t, 256, cr.MaxTokens)
}

func TestBedrock_DecodeMistralRequest(t *testing.T) {
	body := `{"prompt": "<s>[INST] Hello Mistral [/INST]", "max_tokens": 128}`
	adapter := &BedrockAdapter{}
	cr, err := adapter.DecodeRequest([]byte(body))
	require.NoError(t, err)
	require.Len(t, cr.Messages, 1)
	assert.Contains(t, cr.Messages[0].Content, "Hello Mistral")
	assert.Equal(t, 128, cr.MaxTokens)
}

// ---------------------------------------------------------------------------
// Same format passthrough
// ---------------------------------------------------------------------------

func TestAdaptRequest_SameFormat(t *testing.T) {
	input := `{"model":"gpt-4","messages":[]}`
	out, err := AdaptRequest([]byte(input), FormatOpenAI, FormatOpenAI)
	require.NoError(t, err)
	assert.JSONEq(t, input, string(out))
}

func TestAdaptRequest_AzureToOpenAI(t *testing.T) {
	input := `{"model":"gpt-4","messages":[]}`
	out, err := AdaptRequest([]byte(input), FormatAzure, FormatOpenAI)
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
	out, err := AdaptResponse([]byte(input), FormatOpenAI, FormatAnthropic)
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
	out, err := AdaptStreamChunk([]byte(input), FormatOpenAI, FormatAnthropic)
	require.NoError(t, err)
	require.NotNil(t, out)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	assert.Equal(t, "chat.completion.chunk", result["object"])
	choices := result["choices"].([]interface{})
	delta := choices[0].(map[string]interface{})["delta"].(map[string]interface{})
	assert.Equal(t, "Hello", delta["content"])
}

func TestAdaptStreamChunk_AnthropicNonContentSkipped(t *testing.T) {
	input := `{"type":"message_stop"}`
	out, err := AdaptStreamChunk([]byte(input), FormatOpenAI, FormatAnthropic)
	require.NoError(t, err)
	assert.Nil(t, out, "non-content events should be skipped")
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

	out, err := AdaptRequest([]byte(input), FormatGemini, FormatAnthropic)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	assert.Equal(t, "Be brief.", result["system"])
	msgs := result["messages"].([]interface{})
	assert.Len(t, msgs, 1)
	assert.Equal(t, float64(100), result["max_tokens"])
}

// ---------------------------------------------------------------------------
// Real Anthropic request with stream + tools
// ---------------------------------------------------------------------------

func TestCanonical_Anthropic_RealRequest_WithStreamAndTools(t *testing.T) {
	input := `{
		"max_tokens": 64000,
		"messages": [{"role": "user", "content": "buscame en la base de datos el cliente Juan"}],
		"model": "claude-sonnet-4-20250514",
		"stream": true,
		"system": "You are an orchestrator.",
		"tools": [
			{
				"name": "database_agent",
				"input_schema": {
					"properties": {"query": {"type": "string"}},
					"required": ["query"],
					"type": "object"
				},
				"description": "Query the Postgres database."
			}
		]
	}`

	adapter := &AnthropicAdapter{}

	canonical, err := adapter.DecodeRequest([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, "claude-sonnet-4-20250514", canonical.Model)
	assert.Equal(t, "You are an orchestrator.", canonical.System)
	assert.True(t, canonical.Stream, "stream should be true")
	assert.Equal(t, 64000, canonical.MaxTokens)
	assert.Len(t, canonical.Messages, 1)
	assert.Equal(t, "buscame en la base de datos el cliente Juan", canonical.Messages[0].Content)
	assert.Len(t, canonical.Tools, 1)
	assert.Equal(t, "database_agent", canonical.Tools[0].Name)

	// Roundtrip: encode back to Anthropic
	encoded, err := adapter.EncodeRequest(canonical)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(encoded, &result))

	assert.Equal(t, "claude-sonnet-4-20250514", result["model"])
	assert.Equal(t, "You are an orchestrator.", result["system"])
	assert.Equal(t, true, result["stream"])
	assert.Equal(t, float64(64000), result["max_tokens"])

	// Cross-provider: Anthropic → OpenAI (should preserve stream)
	openaiBody, err := AdaptRequest([]byte(input), FormatAnthropic, FormatOpenAI)
	require.NoError(t, err)

	var openaiResult map[string]interface{}
	require.NoError(t, json.Unmarshal(openaiBody, &openaiResult))

	assert.Equal(t, true, openaiResult["stream"])
	msgs := openaiResult["messages"].([]interface{})
	assert.Len(t, msgs, 2) // system re-injected + user
	tools := openaiResult["tools"].([]interface{})
	assert.Len(t, tools, 1)
	tool := tools[0].(map[string]interface{})
	assert.Equal(t, "function", tool["type"])
}

// ---------------------------------------------------------------------------
// Response roundtrip: OpenAI → Canonical → OpenAI
// ---------------------------------------------------------------------------

func TestCanonical_OpenAI_ResponseRoundtrip(t *testing.T) {
	input := `{
		"id": "chatcmpl-123",
		"object": "chat.completion",
		"model": "gpt-4",
		"choices": [
			{
				"index": 0,
				"message": {"role": "assistant", "content": "Hello!"},
				"finish_reason": "stop"
			}
		],
		"usage": {
			"prompt_tokens": 5,
			"completion_tokens": 3,
			"total_tokens": 8
		}
	}`

	adapter := &OpenAIAdapter{}
	canonical, err := adapter.DecodeResponse([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, "chatcmpl-123", canonical.ID)
	assert.Equal(t, "Hello!", canonical.Content)
	assert.Equal(t, "stop", canonical.FinishReason)
	assert.Equal(t, 8, canonical.Usage.TotalTokens)

	encoded, err := adapter.EncodeResponse(canonical)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(encoded, &result))
	assert.Equal(t, "chat.completion", result["object"])
}

// ---------------------------------------------------------------------------
// Bedrock OpenAI-compat (DeepSeek): OpenAI → Bedrock (OpenAI model)
// ---------------------------------------------------------------------------

func TestAdaptRequest_OpenAIToBedrockDeepSeek(t *testing.T) {
	input := `{
		"model": "us.deepseek.deepseek-r1-v1:0",
		"messages": [
			{"role": "system", "content": "You are a reasoning engine."},
			{"role": "user", "content": "Solve: 2+2"}
		],
		"max_tokens": 1024,
		"temperature": 0.0
	}`

	oa := &OpenAIAdapter{}
	canonical, err := oa.DecodeRequest([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, "us.deepseek.deepseek-r1-v1:0", canonical.Model)
	assert.Equal(t, "You are a reasoning engine.", canonical.System)

	adapter := &BedrockAdapter{}
	out, err := adapter.EncodeRequest(canonical)
	require.NoError(t, err)

	// Should produce OpenAI-format body (delegated to OpenAIAdapter).
	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))
	assert.Equal(t, "us.deepseek.deepseek-r1-v1:0", result["model"])
	msgs := result["messages"].([]interface{})
	assert.Len(t, msgs, 2) // system + user
	assert.Equal(t, float64(1024), result["max_tokens"])
}

func TestBedrock_DeepSeek_ResponseDecode(t *testing.T) {
	body := `{
		"id": "chatcmpl-deepseek-123",
		"object": "chat.completion",
		"model": "us.deepseek.deepseek-r1-v1:0",
		"choices": [{
			"index": 0,
			"message": {"role": "assistant", "content": "2+2=4"},
			"finish_reason": "stop"
		}],
		"usage": {
			"prompt_tokens": 10,
			"completion_tokens": 5,
			"total_tokens": 15
		}
	}`

	adapter := &BedrockAdapter{}
	cr, err := adapter.DecodeResponse([]byte(body))
	require.NoError(t, err)
	assert.Equal(t, "chatcmpl-deepseek-123", cr.ID)
	assert.Equal(t, "2+2=4", cr.Content)
	assert.Equal(t, "stop", cr.FinishReason)
	require.NotNil(t, cr.Usage)
	assert.Equal(t, 10, cr.Usage.PromptTokens)
	assert.Equal(t, 5, cr.Usage.CompletionTokens)
	assert.Equal(t, 15, cr.Usage.TotalTokens)
}

func TestBedrock_DeepSeek_StreamChunkDecode(t *testing.T) {
	chunk := `{
		"id": "chatcmpl-deepseek-456",
		"choices": [{
			"index": 0,
			"delta": {"content": "The answer"},
			"finish_reason": null
		}]
	}`
	adapter := &BedrockAdapter{}
	sc, err := adapter.DecodeStreamChunk([]byte(chunk))
	require.NoError(t, err)
	require.NotNil(t, sc)
	assert.Equal(t, "The answer", sc.Delta)
}

func TestBedrock_DecodeDeepSeekRequest(t *testing.T) {
	// An OpenAI-format body arriving as a Bedrock request (no system/anthropic_version).
	body := `{
		"model": "us.deepseek.deepseek-r1-v1:0",
		"messages": [
			{"role": "user", "content": "Hello DeepSeek!"}
		],
		"max_tokens": 256
	}`

	adapter := &BedrockAdapter{}
	cr, err := adapter.DecodeRequest([]byte(body))
	require.NoError(t, err)
	assert.Equal(t, "us.deepseek.deepseek-r1-v1:0", cr.Model)
	require.Len(t, cr.Messages, 1)
	assert.Equal(t, "user", cr.Messages[0].Role)
	assert.Equal(t, "Hello DeepSeek!", cr.Messages[0].Content)
}

func TestDetectFamilyByModel_OpenAICompat(t *testing.T) {
	tests := []struct {
		model  string
		family string
	}{
		{"us.deepseek.deepseek-r1-v1:0", bfOpenAI},
		{"deepseek.deepseek-r1-v1:0", bfOpenAI},
		{"ai21.jamba-1.5-large-v1:0", bfOpenAI},
		{"ai21.jamba-instruct-v1:0", bfOpenAI},
		{"anthropic.claude-3-5-sonnet-20241022-v2:0", bfClaude},
		{"meta.llama3-70b-instruct-v1:0", bfLlama},
		{"amazon.titan-text-express-v1", bfTitan},
		{"mistral.mistral-7b-instruct-v0:2", bfMistral},
	}
	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			assert.Equal(t, tt.family, detectFamilyByModel(tt.model))
		})
	}
}

func TestDetectFamilyFromRequestBody_OpenAICompat(t *testing.T) {
	// OpenAI-compat body: has "messages" but no "system" / "anthropic_version".
	body := `{"model":"deepseek-r1","messages":[{"role":"user","content":"hi"}],"max_tokens":100}`
	assert.Equal(t, bfOpenAI, detectFamilyFromRequestBody([]byte(body)))

	// Claude body: has "messages" + "system" string.
	claudeBody := `{"model":"claude-3","messages":[{"role":"user","content":"hi"}],"system":"be helpful","max_tokens":100}`
	assert.Equal(t, bfClaude, detectFamilyFromRequestBody([]byte(claudeBody)))

	// Claude body: has "anthropic_version".
	claudeBody2 := `{"messages":[{"role":"user","content":"hi"}],"anthropic_version":"bedrock-2023-05-31","max_tokens":100}`
	assert.Equal(t, bfClaude, detectFamilyFromRequestBody([]byte(claudeBody2)))
}

// ---------------------------------------------------------------------------
// Anthropic tool_use response: real-world payload
// ---------------------------------------------------------------------------

func TestAnthropic_DecodeResponse_ToolUse_RealPayload(t *testing.T) {
	// Exact payload from Anthropic Claude.
	body := `{
		"model": "claude-sonnet-4-20250514",
		"id": "msg_015uW5QLWaDeLdqegC29faCw",
		"type": "message",
		"role": "assistant",
		"content": [{
			"type": "tool_use",
			"id": "toolu_016u41qZE8fBygCBmSxapu7x",
			"name": "database_agent",
			"input": {
				"query": "Buscar cliente con nombre Juan"
			}
		}],
		"stop_reason": "tool_use",
		"stop_sequence": null,
		"usage": {
			"input_tokens": 1030,
			"cache_creation_input_tokens": 0,
			"cache_read_input_tokens": 0,
			"cache_creation": {
				"ephemeral_5m_input_tokens": 0,
				"ephemeral_1h_input_tokens": 0
			},
			"output_tokens": 86,
			"service_tier": "standard",
			"inference_geo": "not_available"
		}
	}`

	adapter := &AnthropicAdapter{}

	// Decode to canonical
	cr, err := adapter.DecodeResponse([]byte(body))
	require.NoError(t, err)

	// ID, Model, Role
	assert.Equal(t, "msg_015uW5QLWaDeLdqegC29faCw", cr.ID)
	assert.Equal(t, "claude-sonnet-4-20250514", cr.Model)
	assert.Equal(t, "assistant", cr.Role)

	// Content should be empty (no text blocks)
	assert.Equal(t, "", cr.Content)

	// Tool calls
	require.Len(t, cr.ToolCalls, 1)
	assert.Equal(t, "toolu_016u41qZE8fBygCBmSxapu7x", cr.ToolCalls[0].ID)
	assert.Equal(t, "database_agent", cr.ToolCalls[0].Name)
	assert.Contains(t, cr.ToolCalls[0].Arguments, "Buscar cliente con nombre Juan")

	// FinishReason: tool_use → tool_calls
	assert.Equal(t, "tool_calls", cr.FinishReason)

	// Usage — core tokens
	require.NotNil(t, cr.Usage)
	assert.Equal(t, 1030, cr.Usage.PromptTokens)
	assert.Equal(t, 86, cr.Usage.CompletionTokens)
	assert.Equal(t, 1116, cr.Usage.TotalTokens)

	// Usage — cache/billing pass-through
	assert.Equal(t, 0, cr.Usage.CacheCreationInputTokens)
	assert.Equal(t, 0, cr.Usage.CacheReadInputTokens)
	assert.Equal(t, "standard", cr.Usage.ServiceTier)

	// Roundtrip: canonical → Anthropic → canonical
	encoded, err := adapter.EncodeResponse(cr)
	require.NoError(t, err)

	cr2, err := adapter.DecodeResponse(encoded)
	require.NoError(t, err)

	assert.Equal(t, cr.ID, cr2.ID)
	assert.Equal(t, cr.Model, cr2.Model)
	assert.Equal(t, cr.FinishReason, cr2.FinishReason)
	require.Len(t, cr2.ToolCalls, 1)
	assert.Equal(t, cr.ToolCalls[0].ID, cr2.ToolCalls[0].ID)
	assert.Equal(t, cr.ToolCalls[0].Name, cr2.ToolCalls[0].Name)
	assert.Equal(t, cr.Usage.ServiceTier, cr2.Usage.ServiceTier)
	assert.Equal(t, cr.Usage.CacheCreationInputTokens, cr2.Usage.CacheCreationInputTokens)
	assert.Equal(t, cr.Usage.CacheReadInputTokens, cr2.Usage.CacheReadInputTokens)

	// Cross-format: canonical → OpenAI
	openaiAdapter := &OpenAIAdapter{}
	openaiBody, err := openaiAdapter.EncodeResponse(cr)
	require.NoError(t, err)

	var openaiResult map[string]interface{}
	require.NoError(t, json.Unmarshal(openaiBody, &openaiResult))

	assert.Equal(t, "chat.completion", openaiResult["object"])
	choices := openaiResult["choices"].([]interface{})
	require.Len(t, choices, 1)
	choice := choices[0].(map[string]interface{})
	assert.Equal(t, "tool_calls", choice["finish_reason"])
	msg := choice["message"].(map[string]interface{})
	toolCalls := msg["tool_calls"].([]interface{})
	require.Len(t, toolCalls, 1)
	tc := toolCalls[0].(map[string]interface{})
	assert.Equal(t, "function", tc["type"])
	fn := tc["function"].(map[string]interface{})
	assert.Equal(t, "database_agent", fn["name"])
}

// ---------------------------------------------------------------------------
// Gemini functionCall response: real-world payload
// ---------------------------------------------------------------------------

func TestGemini_DecodeResponse_FunctionCall_RealPayload(t *testing.T) {
	body := `{
		"candidates": [{
			"content": {
				"parts": [{
					"functionCall": {
						"name": "database_agent",
						"args": {
							"query": "cliente Juan"
						}
					},
					"thoughtSignature": "CqACAb4+9vud..."
				}],
				"role": "model"
			},
			"finishReason": "STOP",
			"index": 0,
			"finishMessage": "Model generated function call(s)."
		}],
		"usageMetadata": {
			"promptTokenCount": 640,
			"candidatesTokenCount": 16,
			"totalTokenCount": 712,
			"promptTokensDetails": [{
				"modality": "TEXT",
				"tokenCount": 640
			}],
			"thoughtsTokenCount": 56
		},
		"modelVersion": "gemini-2.5-flash",
		"responseId": "5QKOaf_DL97ensEPo5OwkQg"
	}`

	adapter := &GeminiAdapter{}

	// Decode to canonical
	cr, err := adapter.DecodeResponse([]byte(body))
	require.NoError(t, err)

	// ID, Model, Role
	assert.Equal(t, "5QKOaf_DL97ensEPo5OwkQg", cr.ID)
	assert.Equal(t, "gemini-2.5-flash", cr.Model)
	assert.Equal(t, "assistant", cr.Role)

	// Content should be empty (only functionCall, no text)
	assert.Equal(t, "", cr.Content)

	// Tool calls
	require.Len(t, cr.ToolCalls, 1)
	assert.Equal(t, "database_agent", cr.ToolCalls[0].Name)
	assert.Contains(t, cr.ToolCalls[0].Arguments, "cliente Juan")

	// FinishReason: functionCall → tool_calls
	assert.Equal(t, "tool_calls", cr.FinishReason)

	// Usage
	require.NotNil(t, cr.Usage)
	assert.Equal(t, 640, cr.Usage.PromptTokens)
	assert.Equal(t, 16, cr.Usage.CompletionTokens)
	assert.Equal(t, 712, cr.Usage.TotalTokens)

	// Cross-format: Gemini → Canonical → OpenAI
	openaiAdapter := &OpenAIAdapter{}
	openaiBody, err := openaiAdapter.EncodeResponse(cr)
	require.NoError(t, err)

	var openaiResult map[string]interface{}
	require.NoError(t, json.Unmarshal(openaiBody, &openaiResult))

	assert.Equal(t, "chat.completion", openaiResult["object"])
	choices := openaiResult["choices"].([]interface{})
	require.Len(t, choices, 1)
	choice := choices[0].(map[string]interface{})
	assert.Equal(t, "tool_calls", choice["finish_reason"])
	msg := choice["message"].(map[string]interface{})
	toolCalls := msg["tool_calls"].([]interface{})
	require.Len(t, toolCalls, 1)
	tcObj := toolCalls[0].(map[string]interface{})
	assert.Equal(t, "function", tcObj["type"])
	fnObj := tcObj["function"].(map[string]interface{})
	assert.Equal(t, "database_agent", fnObj["name"])
	assert.Contains(t, fnObj["arguments"], "cliente Juan")

	// Roundtrip: Canonical → Gemini → Canonical
	geminiBody, err := adapter.EncodeResponse(cr)
	require.NoError(t, err)

	cr2, err := adapter.DecodeResponse(geminiBody)
	require.NoError(t, err)
	assert.Equal(t, cr.ID, cr2.ID)
	assert.Equal(t, cr.Model, cr2.Model)
	assert.Equal(t, "tool_calls", cr2.FinishReason)
	require.Len(t, cr2.ToolCalls, 1)
	assert.Equal(t, "database_agent", cr2.ToolCalls[0].Name)
}

// ---------------------------------------------------------------------------
// Gemini → OpenAI: tool schema type conversion (STRING → string)
// ---------------------------------------------------------------------------

func TestGemini_ToolSchemaTypes_ConvertedToOpenAI(t *testing.T) {
	// Gemini-format request with UPPER_CASE types
	input := `{
		"contents": [{"role": "user", "parts": [{"text": "busca Juan"}]}],
		"tools": [{
			"functionDeclarations": [{
				"name": "database_agent",
				"description": "Query the database",
				"parameters": {
					"type": "OBJECT",
					"properties": {
						"query": {"type": "STRING"},
						"limit": {"type": "INTEGER"}
					},
					"required": ["query"]
				}
			}]
		}]
	}`

	// Decode Gemini → Canonical
	gemini := &GeminiAdapter{}
	canonical, err := gemini.DecodeRequest([]byte(input))
	require.NoError(t, err)
	require.Len(t, canonical.Tools, 1)

	// Schema should have lowercase types now
	schema := canonical.Tools[0].Schema
	assert.Equal(t, "object", schema["type"])
	props := schema["properties"].(map[string]interface{})
	assert.Equal(t, "string", props["query"].(map[string]interface{})["type"])
	assert.Equal(t, "integer", props["limit"].(map[string]interface{})["type"])

	// Encode Canonical → OpenAI
	openai := &OpenAIAdapter{}
	openaiBody, err := openai.EncodeRequest(canonical)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(openaiBody, &result))

	tools := result["tools"].([]interface{})
	require.Len(t, tools, 1)
	fn := tools[0].(map[string]interface{})["function"].(map[string]interface{})
	params := fn["parameters"].(map[string]interface{})

	// OpenAI gets lowercase types — no more "STRING is not valid" errors
	assert.Equal(t, "object", params["type"])
	openaiProps := params["properties"].(map[string]interface{})
	assert.Equal(t, "string", openaiProps["query"].(map[string]interface{})["type"])
	assert.Equal(t, "integer", openaiProps["limit"].(map[string]interface{})["type"])
}

func TestOpenAI_ToolSchemaTypes_ConvertedToGemini(t *testing.T) {
	// OpenAI-format request with lowercase types
	input := `{
		"model": "gemini-2.5-flash",
		"messages": [{"role": "user", "content": "busca Juan"}],
		"tools": [{
			"type": "function",
			"function": {
				"name": "db_agent",
				"parameters": {
					"type": "object",
					"properties": {
						"q": {"type": "string"}
					}
				}
			}
		}]
	}`

	// Decode OpenAI → Canonical
	oa := &OpenAIAdapter{}
	canonical, err := oa.DecodeRequest([]byte(input))
	require.NoError(t, err)

	// Encode Canonical → Gemini
	gemini := &GeminiAdapter{}
	geminiBody, err := gemini.EncodeRequest(canonical)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(geminiBody, &result))

	tools := result["tools"].([]interface{})
	require.Len(t, tools, 1)
	decls := tools[0].(map[string]interface{})["functionDeclarations"].([]interface{})
	params := decls[0].(map[string]interface{})["parameters"].(map[string]interface{})

	// Gemini gets UPPER_CASE types
	assert.Equal(t, "OBJECT", params["type"])
	geminiProps := params["properties"].(map[string]interface{})
	assert.Equal(t, "STRING", geminiProps["q"].(map[string]interface{})["type"])
}

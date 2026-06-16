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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	assert.Equal(t, 15, cr.Usage.InputTokens)
	assert.Equal(t, 42, cr.Usage.OutputTokens)
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
	assert.Equal(t, 25, cr.Usage.InputTokens)
	assert.Equal(t, 8, cr.Usage.OutputTokens)
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
	assert.Equal(t, 10, cr.Usage.InputTokens)
	assert.Equal(t, 5, cr.Usage.OutputTokens)
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

func TestUsageExtraction_BedrockTitan(t *testing.T) {
	runUsageCases(t, &bedrockTitanAdapter{}, []usageCase{
		{
			name:      "response with usage",
			body:      []byte(`{"inputTextTokenCount":11,"results":[{"tokenCount":4,"outputText":"hi","completionReason":"FINISH"}]}`),
			path:      "response",
			wantUsage: &CanonicalUsage{InputTokens: 11, OutputTokens: 4, TotalTokens: 15},
		},
		{
			name:      "response no usage",
			body:      []byte(`{"results":[{"outputText":"hi","completionReason":"FINISH"}]}`),
			path:      "response",
			wantUsage: nil,
		},
		{
			name:      "stream final chunk with usage",
			body:      []byte(`{"outputText":"final","inputTextTokenCount":11,"totalOutputTextTokenCount":4}`),
			path:      "stream",
			wantUsage: &CanonicalUsage{InputTokens: 11, OutputTokens: 4, TotalTokens: 15},
		},
		{
			name:      "stream no usage",
			body:      []byte(`{"outputText":"hi"}`),
			path:      "stream",
			wantUsage: nil,
		},
	})
}

func TestUsageExtraction_BedrockLlama(t *testing.T) {
	runUsageCases(t, &bedrockLlamaAdapter{}, []usageCase{
		{
			name:      "response with usage",
			body:      []byte(`{"generation":"hi","prompt_token_count":11,"generation_token_count":4,"stop_reason":"stop"}`),
			path:      "response",
			wantUsage: &CanonicalUsage{InputTokens: 11, OutputTokens: 4, TotalTokens: 15},
		},
		{
			name:      "response no usage",
			body:      []byte(`{"generation":"hi","stop_reason":"stop"}`),
			path:      "response",
			wantUsage: nil,
		},
		{
			name:      "stream final chunk with usage",
			body:      []byte(`{"generation":"","prompt_token_count":11,"generation_token_count":4,"stop_reason":"stop"}`),
			path:      "stream",
			wantUsage: &CanonicalUsage{InputTokens: 11, OutputTokens: 4, TotalTokens: 15},
		},
		{
			name:      "stream no usage",
			body:      []byte(`{"generation":"hi"}`),
			path:      "stream",
			wantUsage: nil,
		},
	})
}

func TestBedrock_InvocationMetricsFallback_Mistral(t *testing.T) {
	body := []byte(`{"outputs":[{"text":"hi","stop_reason":"stop"}],"amazon-bedrock-invocationMetrics":{"inputTokenCount":14,"outputTokenCount":6}}`)
	cr, err := (&bedrockMistralAdapter{}).DecodeResponse(body)
	require.NoError(t, err)
	require.NotNil(t, cr.Usage)
	assert.Equal(t, 14, cr.Usage.InputTokens)
	assert.Equal(t, 6, cr.Usage.OutputTokens)
	assert.Equal(t, 20, cr.Usage.TotalTokens)
}

func TestBedrock_InvocationMetricsFallback_FamilyFieldsWin(t *testing.T) {
	body := []byte(`{"inputTextTokenCount":11,"results":[{"tokenCount":4,"outputText":"hi","completionReason":"FINISH"}],"amazon-bedrock-invocationMetrics":{"inputTokenCount":99,"outputTokenCount":99}}`)
	cr, err := (&bedrockTitanAdapter{}).DecodeResponse(body)
	require.NoError(t, err)
	require.NotNil(t, cr.Usage)
	assert.Equal(t, 11, cr.Usage.InputTokens, "Titan native inputTextTokenCount must win over invocation metrics")
	assert.Equal(t, 4, cr.Usage.OutputTokens, "Titan native results[].tokenCount must win over invocation metrics")
	assert.Equal(t, 15, cr.Usage.TotalTokens)
}

func TestBedrock_InvocationMetricsFallback_MetricsAbsent(t *testing.T) {
	body := []byte(`{"outputs":[{"text":"hi","stop_reason":"stop"}]}`)
	cr, err := (&bedrockMistralAdapter{}).DecodeResponse(body)
	require.NoError(t, err)
	assert.Nil(t, cr.Usage, "Mistral with no metrics and no native counters must return nil")
}

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

func TestUsageExtraction_OpenAICompletions(t *testing.T) {
	runUsageCases(t, &OpenAIAdapter{}, []usageCase{
		{
			name:      "response with usage",
			body:      []byte(`{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":8,"total_tokens":20}}`),
			path:      "response",
			wantUsage: &CanonicalUsage{InputTokens: 12, OutputTokens: 8, TotalTokens: 20},
		},
		{
			name:      "response no usage",
			body:      []byte(`{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}]}`),
			path:      "response",
			wantUsage: nil,
		},
		{
			name:      "stream final chunk with usage",
			body:      []byte(`{"id":"chatcmpl-1","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":12,"completion_tokens":8,"total_tokens":20}}`),
			path:      "stream",
			wantUsage: &CanonicalUsage{InputTokens: 12, OutputTokens: 8, TotalTokens: 20},
		},
		{
			name:      "stream no usage",
			body:      []byte(`{"id":"chatcmpl-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"hi"}}]}`),
			path:      "stream",
			wantUsage: nil,
		},
	})
}

func TestUsageSubCounts_OpenAIChat_CachedInput(t *testing.T) {
	body := []byte(`{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":8,"total_tokens":20,"prompt_tokens_details":{"cached_tokens":7}}}`)
	cr, err := (&OpenAIAdapter{}).DecodeResponse(body)
	require.NoError(t, err)
	require.NotNil(t, cr.Usage)
	assert.Equal(t, 7, cr.Usage.CachedInputTokens)
	assert.Equal(t, 12, cr.Usage.InputTokens, "CachedInputTokens is a sub-count; InputTokens must not be reduced")
}

func TestUsageSubCounts_OpenAIChat_ReasoningOutput(t *testing.T) {
	body := []byte(`{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":20,"total_tokens":25,"completion_tokens_details":{"reasoning_tokens":12}}}`)
	cr, err := (&OpenAIAdapter{}).DecodeResponse(body)
	require.NoError(t, err)
	require.NotNil(t, cr.Usage)
	assert.Equal(t, 12, cr.Usage.ReasoningOutputTokens)
	assert.Equal(t, 20, cr.Usage.OutputTokens, "ReasoningOutputTokens is a sub-count; OutputTokens must not be reduced")
}

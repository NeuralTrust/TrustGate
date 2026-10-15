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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fixtures below are the request and response examples of the AWS Bedrock
// user guide for each model family, not output of this package's own types.

func lastUserText(cr *CanonicalRequest) string {
	for i := len(cr.Messages) - 1; i >= 0; i-- {
		if cr.Messages[i].Role == "user" {
			return cr.Messages[i].Content
		}
	}
	return ""
}

func TestBedrockNativeAdapter_DecodeRequest_InvokeShapes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		body      string
		wantText  string
		wantSys   string
		wantMax   int
		wantTurns int
	}{
		{
			name:      "anthropic messages",
			body:      `{"anthropic_version":"bedrock-2023-05-31","max_tokens":1024,"system":"You are terse.","messages":[{"role":"user","content":[{"type":"text","text":"Hello there"}]}]}`,
			wantText:  "Hello there",
			wantSys:   "You are terse.",
			wantMax:   1024,
			wantTurns: 1,
		},
		{
			name:      "titan text",
			body:      `{"inputText":"Tell me a story","textGenerationConfig":{"maxTokenCount":512,"stopSequences":[],"temperature":0.7,"topP":0.9}}`,
			wantText:  "Tell me a story",
			wantMax:   512,
			wantTurns: 1,
		},
		{
			name:      "llama prompt",
			body:      `{"prompt":"<|begin_of_text|>hello llama","max_gen_len":256,"temperature":0.5,"top_p":0.9}`,
			wantText:  "<|begin_of_text|>hello llama",
			wantMax:   256,
			wantTurns: 1,
		},
		{
			name:      "mistral prompt",
			body:      `{"prompt":"<s>[INST] hi [/INST]","max_tokens":200,"temperature":0.5,"top_p":0.9,"top_k":50}`,
			wantText:  "<s>[INST] hi [/INST]",
			wantMax:   200,
			wantTurns: 1,
		},
		{
			name:      "mistral large chat messages",
			body:      `{"messages":[{"role":"user","content":"hi mistral"}],"max_tokens":100}`,
			wantText:  "hi mistral",
			wantMax:   100,
			wantTurns: 1,
		},
		{
			name:      "chat messages with typed content blocks",
			body:      `{"messages":[{"role":"user","content":[{"type":"text","text":"typed blocks"}]}]}`,
			wantText:  "typed blocks",
			wantTurns: 1,
		},
		{
			name:      "cohere command r",
			body:      `{"message":"What is up?","chat_history":[{"role":"USER","message":"hi"},{"role":"CHATBOT","message":"hello"}],"preamble":"Be nice","max_tokens":100,"temperature":0.3,"p":0.75}`,
			wantText:  "What is up?",
			wantSys:   "Be nice",
			wantMax:   100,
			wantTurns: 3,
		},
		{
			name:      "nova messages-v1 reads as converse",
			body:      `{"schemaVersion":"messages-v1","messages":[{"role":"user","content":[{"text":"hi nova"}]}],"system":[{"text":"sys"}],"inferenceConfig":{"maxTokens":100}}`,
			wantText:  "hi nova",
			wantSys:   "sys",
			wantMax:   100,
			wantTurns: 1,
		},
		{
			name:      "converse body",
			body:      `{"messages":[{"role":"user","content":[{"text":"hi converse"}]}],"system":[{"text":"be brief"}],"inferenceConfig":{"maxTokens":50}}`,
			wantText:  "hi converse",
			wantSys:   "be brief",
			wantMax:   50,
			wantTurns: 1,
		},
		{
			name:      "unknown shape falls back to its text-bearing strings",
			body:      `{"weird":{"Prompt":"secret stuff"},"n":1,"extras":[{"text":"more"}]}`,
			wantText:  "more\nsecret stuff",
			wantTurns: 1,
		},
	}
	adapter := &BedrockNativeAdapter{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cr, err := adapter.DecodeRequest([]byte(tc.body))
			require.NoError(t, err)
			require.NotNil(t, cr)
			assert.Equal(t, tc.wantText, lastUserText(cr))
			assert.Equal(t, tc.wantSys, cr.System)
			assert.Equal(t, tc.wantMax, cr.MaxTokens)
			assert.Len(t, cr.Messages, tc.wantTurns)
		})
	}
}

func TestBedrockNativeAdapter_DecodeRequest_Roles(t *testing.T) {
	t.Parallel()
	cr, err := (&BedrockNativeAdapter{}).DecodeRequest([]byte(
		`{"message":"now","chat_history":[{"role":"USER","message":"a"},{"role":"CHATBOT","message":"b"}]}`))
	require.NoError(t, err)
	require.Len(t, cr.Messages, 3)
	assert.Equal(t, []string{"user", "assistant", "user"},
		[]string{cr.Messages[0].Role, cr.Messages[1].Role, cr.Messages[2].Role})
}

func TestBedrockNativeAdapter_DecodeRequest_InvalidJSONStillFails(t *testing.T) {
	t.Parallel()
	for _, body := range []string{`not json`, `[1,2]`, `"text"`} {
		_, err := (&BedrockNativeAdapter{}).DecodeRequest([]byte(body))
		assert.Error(t, err, body)
	}
}

func TestBedrockNativeAdapter_DecodeResponse_InvokeShapes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		body       string
		wantText   string
		wantFinish string
		wantIn     int
		wantOut    int
	}{
		{
			name:       "anthropic",
			body:       `{"id":"msg_01","type":"message","role":"assistant","model":"claude-3-haiku-20240307","content":[{"type":"text","text":"Hi!"}],"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":5}}`,
			wantText:   "Hi!",
			wantFinish: "stop",
			wantIn:     10,
			wantOut:    5,
		},
		{
			name:       "titan",
			body:       `{"inputTextTokenCount":3,"results":[{"tokenCount":20,"outputText":"Once upon","completionReason":"FINISH"}]}`,
			wantText:   "Once upon",
			wantFinish: "stop",
			wantIn:     3,
			wantOut:    20,
		},
		{
			name:       "titan cut by length",
			body:       `{"inputTextTokenCount":3,"results":[{"tokenCount":20,"outputText":"abc","completionReason":"LENGTH"}]}`,
			wantText:   "abc",
			wantFinish: "length",
			wantIn:     3,
			wantOut:    20,
		},
		{
			name:       "llama",
			body:       `{"generation":"Hello","prompt_token_count":5,"generation_token_count":8,"stop_reason":"stop"}`,
			wantText:   "Hello",
			wantFinish: "stop",
			wantIn:     5,
			wantOut:    8,
		},
		{
			name:       "mistral prompt",
			body:       `{"outputs":[{"text":"Bonjour","stop_reason":"length"}]}`,
			wantText:   "Bonjour",
			wantFinish: "length",
		},
		{
			name:       "mistral large chat",
			body:       `{"id":"c","object":"chat.completion","model":"mistral-large","choices":[{"index":0,"message":{"role":"assistant","content":"Yo"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}`,
			wantText:   "Yo",
			wantFinish: "stop",
			wantIn:     4,
			wantOut:    2,
		},
		{
			name:       "cohere command r",
			body:       `{"response_id":"x","text":"Hi there","generation_id":"y","chat_history":[],"finish_reason":"COMPLETE"}`,
			wantText:   "Hi there",
			wantFinish: "stop",
		},
		{
			name:       "cohere command generations",
			body:       `{"generations":[{"id":"1","text":"Hello","finish_reason":"MAX_TOKENS"}]}`,
			wantText:   "Hello",
			wantFinish: "length",
		},
		{
			name:       "converse",
			body:       `{"output":{"message":{"role":"assistant","content":[{"text":"From converse"}]}},"stopReason":"end_turn","usage":{"inputTokens":7,"outputTokens":3,"totalTokens":10}}`,
			wantText:   "From converse",
			wantFinish: "stop",
			wantIn:     7,
			wantOut:    3,
		},
		{
			name:     "unknown shape",
			body:     `{"foo":{"text":"leaked words"}}`,
			wantText: "leaked words",
		},
	}
	adapter := &BedrockNativeAdapter{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cr, err := adapter.DecodeResponse([]byte(tc.body))
			require.NoError(t, err)
			require.NotNil(t, cr)
			assert.Equal(t, tc.wantText, cr.Content)
			assert.Equal(t, tc.wantFinish, cr.FinishReason)
			if tc.wantIn == 0 && tc.wantOut == 0 {
				return
			}
			require.NotNil(t, cr.Usage)
			assert.Equal(t, tc.wantIn, cr.Usage.InputTokens)
			assert.Equal(t, tc.wantOut, cr.Usage.OutputTokens)
		})
	}
}

func TestBedrockNativeAdapter_DecodeStreamChunk_InvokeShapes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		chunk      string
		wantDelta  string
		wantFinish string
		wantIn     int
		wantOut    int
	}{
		{
			name:      "anthropic delta",
			chunk:     `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hel"}}`,
			wantDelta: "Hel",
		},
		{
			name:    "anthropic closing chunk carries the invocation metrics",
			chunk:   `{"type":"message_stop","amazon-bedrock-invocationMetrics":{"inputTokenCount":9,"outputTokenCount":12,"invocationLatency":1000,"firstByteLatency":300}}`,
			wantIn:  9,
			wantOut: 12,
		},
		{
			name:      "titan delta",
			chunk:     `{"outputText":"abc","index":0,"totalOutputTextTokenCount":null,"completionReason":null,"inputTextTokenCount":null}`,
			wantDelta: "abc",
		},
		{
			name:       "titan closing chunk",
			chunk:      `{"outputText":"","index":0,"totalOutputTextTokenCount":12,"completionReason":"FINISH","inputTextTokenCount":4,"amazon-bedrock-invocationMetrics":{"inputTokenCount":4,"outputTokenCount":12}}`,
			wantFinish: "stop",
			wantIn:     4,
			wantOut:    12,
		},
		{
			name:      "llama delta",
			chunk:     `{"generation":"Hel","prompt_token_count":null,"generation_token_count":1,"stop_reason":null}`,
			wantDelta: "Hel",
			wantOut:   1,
		},
		{
			name:       "llama closing chunk",
			chunk:      `{"generation":"","prompt_token_count":null,"generation_token_count":9,"stop_reason":"stop","amazon-bedrock-invocationMetrics":{"inputTokenCount":7,"outputTokenCount":9}}`,
			wantFinish: "stop",
			wantIn:     7,
			wantOut:    9,
		},
		{
			name:      "mistral delta",
			chunk:     `{"outputs":[{"text":"Bon","stop_reason":null}]}`,
			wantDelta: "Bon",
		},
		{
			name:      "cohere delta",
			chunk:     `{"text":"Hi","is_finished":false,"event_type":"text-generation"}`,
			wantDelta: "Hi",
		},
		{
			name:       "cohere end",
			chunk:      `{"is_finished":true,"event_type":"stream-end","finish_reason":"COMPLETE"}`,
			wantFinish: "stop",
		},
		{
			name:      "converse event is left to the converse decoder",
			chunk:     `{"contentBlockDelta":{"contentBlockIndex":0,"delta":{"text":"conv"}}}`,
			wantDelta: "conv",
		},
		{
			name:       "converse metadata is left to the converse decoder",
			chunk:      `{"metadata":{"usage":{"inputTokens":9,"outputTokens":4,"totalTokens":13}}}`,
			wantIn:     9,
			wantOut:    4,
			wantFinish: "",
		},
		{
			name:      "unknown shape",
			chunk:     `{"mystery":{"text":"words"}}`,
			wantDelta: "\nwords\n",
		},
	}
	adapter := &BedrockNativeAdapter{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := adapter.DecodeStreamChunk([]byte(tc.chunk))
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, tc.wantDelta, got.Delta)
			assert.Equal(t, tc.wantFinish, got.FinishReason)
			if tc.wantIn == 0 && tc.wantOut == 0 {
				assert.Nil(t, got.Usage)
				return
			}
			require.NotNil(t, got.Usage)
			assert.Equal(t, tc.wantIn, got.Usage.InputTokens)
			assert.Equal(t, tc.wantOut, got.Usage.OutputTokens)
		})
	}
}

func TestBedrockNativeAdapter_DecodeStreamChunk_NothingToReport(t *testing.T) {
	t.Parallel()
	for _, chunk := range []string{`{}`, `not json`, `[1]`, `{"index":0}`} {
		got, err := (&BedrockNativeAdapter{}).DecodeStreamChunk([]byte(chunk))
		assert.NoError(t, err, chunk)
		assert.Nil(t, got, chunk)
	}
}

func TestInvocationMetricsUsage_FoldsCacheBucketsIntoTheInput(t *testing.T) {
	t.Parallel()
	got, err := (&BedrockNativeAdapter{}).DecodeStreamChunk([]byte(
		`{"type":"message_stop","amazon-bedrock-invocationMetrics":{"inputTokenCount":10,"outputTokenCount":5,"cacheReadInputTokenCount":100,"cacheWriteInputTokenCount":20}}`))
	require.NoError(t, err)
	require.NotNil(t, got.Usage)
	assert.Equal(t, 130, got.Usage.InputTokens)
	assert.Equal(t, 100, got.Usage.CachedInputTokens)
	assert.Equal(t, 20, got.Usage.CacheWriteInputTokens)
	assert.Equal(t, 5, got.Usage.OutputTokens)
}

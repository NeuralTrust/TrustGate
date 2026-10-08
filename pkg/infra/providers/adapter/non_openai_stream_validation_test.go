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

func TestNonOpenAIStreamDecodersRejectMalformedKnownEvents(t *testing.T) {
	for _, provider := range []struct {
		name    string
		decoder StreamAdapter
		invalid []string
		future  string
	}{
		{
			name: "Gemini", decoder: &GeminiAdapter{}, future: `{"futureEvent":{"usage":"opaque"}}`,
			invalid: []string{
				`{"candidates":42}`, `{"candidates":[null]}`, `{"candidates":[{"content":null}]}`,
				`{"candidates":[{"content":{"parts":[null]}}]}`,
				`{"candidates":[{"content":{"parts":[{"text":42}]}}]}`,
				`{"candidates":[{"content":{"parts":[{"functionCall":null}]}}]}`,
				`{"candidates":[{"finishReason":42}]}`, `{"usageMetadata":{"promptTokenCount":"bad"}}`,
				`{"usageMetadata":null}`, `{"responseId":42}`, `{"modelVersion":null}`,
			},
		},
		{
			name: "Bedrock", decoder: &BedrockAdapter{}, future: `{"futureEvent":{"usage":"opaque"}}`,
			invalid: []string{
				`{"messageStart":null}`, `{"messageStart":{"role":42}}`, `{"messageStart":{}}`,
				`{"contentBlockStart":{"start":null}}`, `{"contentBlockDelta":{"delta":42}}`,
				`{"contentBlockDelta":{"delta":{"text":42}}}`,
				`{"contentBlockDelta":{"delta":{"toolUse":null}}}`,
				`{"messageStop":{}}`, `{"messageStop":{"stopReason":42}}`, `{"metadata":null}`,
				`{"metadata":{"usage":{"inputTokens":"bad"}}}`,
				`{"messageStop":{"stopReason":"end_turn"},"metadata":{}}`,
			},
		},
		{
			name: "Cohere", decoder: &CohereAdapter{}, future: `{"type":"future-event","delta":42,"index":"opaque"}`,
			invalid: []string{
				`{"type":42}`, `{"type":"content-delta","delta":42}`,
				`{"type":"content-delta","delta":{"message":{"content":null}}}`,
				`{"type":"content-delta","delta":{"message":{"content":{"text":42}}}}`,
				`{"type":"tool-call-delta","delta":{"message":{"tool_calls":null}}}`,
				`{"type":"tool-call-delta","delta":{"message":{"tool_calls":{"function":{"arguments":42}}}}}`,
				`{"type":"message-end","delta":{"finish_reason":42}}`,
				`{"type":"message-end","delta":{"finish_reason":"COMPLETE","usage":{"tokens":{"input_tokens":"bad"}}}}`,
			},
		},
	} {
		t.Run(provider.name, func(t *testing.T) {
			for _, raw := range append([]string{`null`, `{}`, `[]`, `{invalid`}, provider.invalid...) {
				t.Run(raw, func(t *testing.T) {
					chunk, err := provider.decoder.DecodeStreamChunk([]byte(raw))
					require.NoError(t, err)
					require.NotNil(t, chunk)
					require.NotNil(t, chunk.UpstreamError)
					assert.Equal(t, "invalid_stream_event", chunk.UpstreamError.Type)
					assert.Empty(t, chunk.FinishReason)
				})
			}
			chunk, err := provider.decoder.DecodeStreamChunk([]byte(provider.future))
			require.NoError(t, err)
			assert.Nil(t, chunk)
		})
	}
}

func TestNonOpenAIStreamDecodersPreserveTerminalEvidenceAndIdentity(t *testing.T) {
	gemini, err := (&GeminiAdapter{}).DecodeStreamChunk([]byte(`{"responseId":"gemini-id","modelVersion":"gemini-version","candidates":[{"finishReason":"STOP"}]}`))
	require.NoError(t, err)
	require.NotNil(t, gemini)
	assert.Equal(t, "gemini-id", gemini.ID)
	assert.Equal(t, "gemini-version", gemini.Model)
	assert.Equal(t, "stop", gemini.FinishReason)
	assert.False(t, gemini.StreamEnd)
	for _, raw := range []string{`{"metadata":{}}`, `{"metadata":{"usage":{"inputTokens":5,"outputTokens":7,"totalTokens":12}}}`} {
		chunk, err := (&BedrockAdapter{}).DecodeStreamChunk([]byte(raw))
		require.NoError(t, err)
		require.NotNil(t, chunk)
		assert.True(t, chunk.StreamEnd)
		assert.Empty(t, chunk.ID)
		assert.Empty(t, chunk.Model)
	}
	cohere, err := (&CohereAdapter{}).DecodeStreamChunk([]byte(`{"type":"message-end","delta":{"finish_reason":"COMPLETE"}}`))
	require.NoError(t, err)
	require.NotNil(t, cohere)
	assert.True(t, cohere.StreamEnd)
	assert.Equal(t, "stop", cohere.FinishReason)
	for _, raw := range []string{
		`{"type":"message-end","id":null,"delta":{"finish_reason":"COMPLETE","error":null,"usage":null}}`,
		`{"type":"message-end","delta":{"finish_reason":"COMPLETE","usage":{"tokens":null,"billed_units":null,"cached_tokens":null}}}`,
	} {
		chunk, err := (&CohereAdapter{}).DecodeStreamChunk([]byte(raw))
		require.NoError(t, err)
		require.NotNil(t, chunk)
		assert.Equal(t, "stop", chunk.FinishReason)
		assert.True(t, chunk.StreamEnd)
		assert.Nil(t, chunk.UpstreamError)
		assert.Nil(t, chunk.Usage)
	}
}

func TestNonOpenAIStreamDecodersSurfaceProviderErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		decoder StreamAdapter
		body    string
	}{
		{"gemini", &GeminiAdapter{}, `{"error":{"code":503,"message":"private upstream detail","status":"UNAVAILABLE"}}`},
		{"bedrock", &BedrockAdapter{}, `{"modelStreamErrorException":{"message":"private upstream detail"}}`},
		{"cohere ERROR", &CohereAdapter{}, `{"type":"message-end","delta":{"finish_reason":"ERROR","usage":{"tokens":{"input_tokens":5,"output_tokens":2}}}}`},
		{"cohere error detail", &CohereAdapter{}, `{"type":"message-end","delta":{"finish_reason":"COMPLETE","error":"private upstream detail"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chunk, err := tc.decoder.DecodeStreamChunk([]byte(tc.body))
			require.NoError(t, err)
			require.NotNil(t, chunk)
			require.NotNil(t, chunk.UpstreamError)
			assert.NotContains(t, chunk.UpstreamError.Error(), "private upstream detail")
			if tc.name == "cohere ERROR" {
				require.NotNil(t, chunk.Usage)
				assert.Equal(t, 7, chunk.Usage.TotalTokens)
			}
		})
	}
}

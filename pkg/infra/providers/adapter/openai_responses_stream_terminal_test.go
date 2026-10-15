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

func TestResponsesStreamTerminalEvidence(t *testing.T) {
	for _, event := range []string{"response.completed", "response.incomplete"} {
		t.Run(event, func(t *testing.T) {
			chunk, err := decodeResponsesStreamChunk([]byte(`{"type":"` + event + `","response":{"id":"resp_1","model":"model_1"}}`))
			require.NoError(t, err)
			require.NotNil(t, chunk)
			assert.True(t, chunk.StreamEnd)
			assert.NotEmpty(t, chunk.FinishReason)
			assert.Equal(t, "resp_1", chunk.ID)
			assert.Equal(t, "model_1", chunk.Model)
		})
	}
	for _, event := range []string{"error", "response.failed"} {
		t.Run(event, func(t *testing.T) {
			chunk, err := decodeResponsesStreamChunk([]byte(`{"type":"` + event + `"}`))
			require.NoError(t, err)
			require.NotNil(t, chunk)
			assert.NotNil(t, chunk.UpstreamError)
			assert.False(t, chunk.StreamEnd)
		})
	}
	chunk, err := decodeResponsesStreamChunk([]byte(`{"type":"response.created","response":{"id":"resp_1","model":"model_1"}}`))
	require.NoError(t, err)
	require.NotNil(t, chunk)
	assert.Equal(t, "resp_1", chunk.ID)
	assert.Equal(t, "model_1", chunk.Model)
	assert.False(t, chunk.StreamEnd)
}

func TestResponsesStreamMalformedTerminalFails(t *testing.T) {
	for _, event := range []string{"response.completed", "response.incomplete"} {
		for _, response := range []string{`null`, `42`, `{"usage":{"input_tokens":"bad"}}`} {
			t.Run(event+"/"+response, func(t *testing.T) {
				chunk, err := decodeResponsesStreamChunk([]byte(`{"type":"` + event + `","response":` + response + `}`))
				require.NoError(t, err)
				require.NotNil(t, chunk)
				assert.NotNil(t, chunk.UpstreamError)
				assert.False(t, chunk.StreamEnd)
				assert.Empty(t, chunk.FinishReason)
			})
		}
		chunk, err := decodeResponsesStreamChunk([]byte(`{"type":"` + event + `","response":{"usage":null}}`))
		require.NoError(t, err)
		require.NotNil(t, chunk)
		assert.True(t, chunk.StreamEnd)
		assert.Nil(t, chunk.UpstreamError)
	}
	for _, raw := range []string{`null`, `{}`, `{invalid`} {
		chunk, err := decodeResponsesStreamChunk([]byte(raw))
		require.NoError(t, err)
		require.NotNil(t, chunk)
		assert.NotNil(t, chunk.UpstreamError)
	}
	chunk, err := decodeResponsesStreamChunk([]byte(`{"type":"future_event","delta":42}`))
	require.NoError(t, err)
	assert.Nil(t, chunk)
}

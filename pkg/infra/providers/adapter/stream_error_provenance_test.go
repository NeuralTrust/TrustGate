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

func TestUpstreamStreamErrorDecoderFailure(t *testing.T) {
	t.Parallel()
	assert.False(t, (*UpstreamStreamError)(nil).DecoderFailure())
	assert.False(t, failedStreamEvent("Anthropic").UpstreamError.DecoderFailure())
	failure := invalidStreamEvent("Anthropic").UpstreamError
	assert.True(t, failure.DecoderFailure())
	assert.Equal(t, InvalidStreamEventType, failure.Type)
	encoded, err := json.Marshal(failure)
	require.NoError(t, err)
	assert.JSONEq(t, `{"Type":"invalid_stream_event","Code":"","Message":"invalid upstream Anthropic stream event"}`, string(encoded))
}

func TestOpenAIStreamErrorTypeCannotImpersonateDecoderFailure(t *testing.T) {
	t.Parallel()
	const payload = `{"error":{"type":"invalid_stream_event","code":"provider_failure","message":"upstream failed","decoderFailure":true}}`
	for _, format := range []Format{FormatOpenAI, FormatOpenRouter} {
		t.Run(string(format), func(t *testing.T) {
			t.Parallel()
			chunk, err := NewRegistry().DecodeStreamChunkFor([]byte(payload), format)
			require.NoError(t, err)
			require.NotNil(t, chunk)
			require.NotNil(t, chunk.UpstreamError)
			failure := chunk.UpstreamError
			assert.False(t, failure.DecoderFailure())
			assert.Equal(t, InvalidStreamEventType, failure.Type)
			assert.Equal(t, "provider_failure", failure.Code)
			assert.Equal(t, "upstream failed", failure.Message)
			encoded, err := json.Marshal(failure)
			require.NoError(t, err)
			assert.JSONEq(t, `{"Type":"invalid_stream_event","Code":"provider_failure","Message":"upstream failed"}`, string(encoded))
		})
	}
}

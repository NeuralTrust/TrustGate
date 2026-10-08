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

func TestAnthropicDecodeStreamRejectsMalformedKnownEvents(t *testing.T) {
	for _, body := range []string{
		`not json`, `null`, `{}`, `{"type":7}`,
		`{"type":"message_start","message":null}`,
		`{"type":"message_start","message":{}}`,
		`{"type":"message_start","message":{"id":"msg_1"}}`,
		`{"type":"message_start","message":{"model":"claude"}}`,
		`{"type":"message_start","message":{"id":" ","model":"claude"}}`,
		`{"type":"message_start","message":{"id":"msg_1","model":" "}}`,
		`{"type":"message_start","message":{"id":"msg_1","model":"claude","usage":{"input_tokens":"bad"}}}`,
		`{"type":"content_block_delta","delta":null}`,
		`{"type":"content_block_delta","delta":{}}`,
		`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":1}}`,
		`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":null}}`,
		`{"type":"content_block_delta","index":null,"delta":{"type":"text_delta","text":"hi"}}`,
		`{"type":"content_block_start","content_block":[]}`,
		`{"type":"content_block_start","content_block":{}}`,
		`{"type":"message_delta","delta":null}`,
		`{"type":"message_delta","delta":{"stop_reason":9}}`,
		`{"type":"message_stop","index":"bad"}`,
	} {
		t.Run(body, func(t *testing.T) {
			chunk, err := (&AnthropicAdapter{}).DecodeStreamChunk([]byte(body))
			require.NoError(t, err)
			require.NotNil(t, chunk)
			require.NotNil(t, chunk.UpstreamError)
			assert.Equal(t, "invalid upstream Anthropic stream event", chunk.UpstreamError.Message)
			assert.False(t, chunk.StreamEnd)
		})
	}
}

func TestAnthropicDecodeStreamReportsExplicitTerminalOnly(t *testing.T) {
	a := &AnthropicAdapter{}
	finish, err := a.DecodeStreamChunk([]byte(`{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":1}}`))
	require.NoError(t, err)
	require.NotNil(t, finish)
	assert.Equal(t, "stop", finish.FinishReason)
	assert.False(t, finish.StreamEnd)
	terminal, err := a.DecodeStreamChunk([]byte(`{"type":"message_stop"}`))
	require.NoError(t, err)
	require.NotNil(t, terminal)
	assert.True(t, terminal.StreamEnd)
	assert.Empty(t, terminal.FinishReason)
	data, err := json.Marshal(terminal)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "stream_end")
}

func TestAnthropicDecodeStreamErrorsNeverDisappear(t *testing.T) {
	for _, body := range []string{
		`{"type":"error"}`, `{"type":"error","error":null}`,
		`{"type":"error","error":{}}`,
		`{"type":"error","error":{"type":"overloaded_error","message":"private provider detail"}}`,
	} {
		chunk, err := (&AnthropicAdapter{}).DecodeStreamChunk([]byte(body))
		require.NoError(t, err)
		require.NotNil(t, chunk)
		require.NotNil(t, chunk.UpstreamError)
		assert.Equal(t, "upstream Anthropic stream failed", chunk.UpstreamError.Message)
		assert.False(t, chunk.StreamEnd)
	}
}

func TestAnthropicDecodeStreamSkipsUnknownFutureEvents(t *testing.T) {
	for _, body := range []string{`{"type":"future_event"}`, `{"type":"future_event","index":"future","usage":[]}`} {
		chunk, err := (&AnthropicAdapter{}).DecodeStreamChunk([]byte(body))
		require.NoError(t, err)
		assert.Nil(t, chunk)
		assert.NoError(t, ValidateAnthropicStreamEvent([]byte(body)))
	}
}

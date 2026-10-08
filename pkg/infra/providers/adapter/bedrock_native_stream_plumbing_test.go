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

func TestNativeStreamChunk_UsageAndMetricsAreNotText(t *testing.T) {
	t.Parallel()
	a := &BedrockNativeAdapter{}
	for name, chunk := range map[string]string{
		"message_start usage":  `{"type":"message_start","message":{"model":"claude-haiku-4-5-20251001","id":"msg_bdrk_01X","type":"message","role":"assistant","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":20,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":1,"service_tier":"standard"}}}`,
		"message_stop metrics": `{"type":"message_stop","amazon-bedrock-invocationMetrics":{"inputTokenCount":20,"outputTokenCount":12,"invocationLatency":900,"firstByteLatency":400,"region":"eu-west-1"}}`,
		"nested usage label":   `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":12,"tier":"standard"}}`,
	} {
		got, err := a.DecodeStreamChunk([]byte(chunk))
		require.NoError(t, err, name)
		if got != nil {
			assert.Empty(t, got.Delta, name)
		}
	}
}

func TestNativeStreamChunk_UnmodelledTextStaysInTheViewButNotInTheModelledText(t *testing.T) {
	t.Parallel()
	chunk := []byte(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"},"note":"standard"}`)
	view, err := (&BedrockNativeAdapter{}).decodeStreamChunk(chunk, true)
	require.NoError(t, err)
	assert.Equal(t, "hello\nstandard\n", view.Delta)
	modelled, err := (&BedrockNativeAdapter{}).decodeStreamChunk(chunk, false)
	require.NoError(t, err)
	assert.Equal(t, "hello", modelled.Delta)
}

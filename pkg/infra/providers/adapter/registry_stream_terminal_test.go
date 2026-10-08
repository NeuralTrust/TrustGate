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
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistryPreservesDecodedTerminalWithoutStatelessOutput(t *testing.T) {
	r := NewRegistry()
	body := []byte(`{"type":"message_stop"}`)
	chunk, err := r.DecodeStreamChunkFor(body, FormatAnthropic)
	require.NoError(t, err)
	require.NotNil(t, chunk)
	assert.True(t, chunk.StreamEnd)
	assert.True(t, chunk.StreamEndOnly())
	lines, err := r.AdaptStreamChunk(body, FormatOpenAI, FormatAnthropic)
	require.NoError(t, err)
	assert.Empty(t, lines)
	passthrough, err := r.AdaptStreamChunk(body, FormatAnthropic, FormatAnthropic)
	require.NoError(t, err)
	assert.Contains(t, string(bytes.Join(passthrough, nil)), string(body))
}

func TestCanonicalStreamEndOnlyDoesNotDiscardPayload(t *testing.T) {
	assert.False(t, (*CanonicalStreamChunk)(nil).StreamEndOnly())
	assert.False(t, (&CanonicalStreamChunk{}).StreamEndOnly())
	assert.True(t, (&CanonicalStreamChunk{StreamEnd: true}).StreamEndOnly())
	for _, chunk := range []CanonicalStreamChunk{
		{ID: "msg"}, {Model: "model"}, {Role: "assistant"}, {Delta: "text"},
		{ReasoningDelta: "thinking"}, {FinishReason: "stop"},
		{ToolCallDeltas: []StreamToolCallDelta{{Index: 0}}},
		{Usage: &CanonicalUsage{}}, {UpstreamError: &UpstreamStreamError{}},
		{ProviderExtensions: map[string]json.RawMessage{"future": json.RawMessage(`{}`)}},
		{OpenItem: &StreamOpenItem{}},
	} {
		chunk.StreamEnd = true
		assert.False(t, chunk.StreamEndOnly())
	}
}

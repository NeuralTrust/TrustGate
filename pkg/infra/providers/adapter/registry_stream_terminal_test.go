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
	assert.True(t, chunk.SignalOnly())
	lines, err := r.AdaptStreamChunk(body, FormatOpenAI, FormatAnthropic)
	require.NoError(t, err)
	assert.Empty(t, lines)
	passthrough, err := r.AdaptStreamChunk(body, FormatAnthropic, FormatAnthropic)
	require.NoError(t, err)
	assert.Contains(t, string(bytes.Join(passthrough, nil)), string(body))
}

func TestCanonicalSignalOnlyDoesNotDiscardPayload(t *testing.T) {
	assert.False(t, (*CanonicalStreamChunk)(nil).SignalOnly())
	assert.False(t, (&CanonicalStreamChunk{}).SignalOnly())
	assert.True(t, (&CanonicalStreamChunk{StreamEnd: true}).SignalOnly())
	assert.True(t, (&CanonicalStreamChunk{ID: "msg"}).SignalOnly())
	assert.True(t, (&CanonicalStreamChunk{Model: "model"}).SignalOnly())
	for _, chunk := range []CanonicalStreamChunk{
		{Role: "assistant"}, {Delta: "text"},
		{ReasoningDelta: "thinking"}, {FinishReason: "stop"},
		{ToolCallDeltas: []StreamToolCallDelta{{Index: 0}}},
		{Usage: &CanonicalUsage{}}, {UpstreamError: &UpstreamStreamError{}},
		{ProviderExtensions: map[string]json.RawMessage{"future": json.RawMessage(`{}`)}},
		{OpenItem: &StreamOpenItem{}},
	} {
		chunk.StreamEnd, chunk.ID, chunk.Model = true, "msg", "model"
		assert.False(t, chunk.SignalOnly())
	}
}

func TestRegistryAdaptStreamChunkSkipsIdentityOnlyEvents(t *testing.T) {
	r := NewRegistry()
	for _, tc := range []struct {
		target  Format
		payload string
	}{
		{FormatOpenAIResponses, `{"type":"response.created","response":{"id":"resp_1","model":"gpt-x"}}`},
		{FormatOpenAIResponses, `{"type":"response.in_progress","response":{"id":"resp_1","model":"gpt-x"}}`},
		{FormatGemini, `{"responseId":"g1","modelVersion":"gemini-x"}`},
	} {
		for _, source := range []Format{FormatGroq, FormatMistral, FormatOpenRouter} {
			lines, err := r.AdaptStreamChunk([]byte(tc.payload), source, tc.target)
			require.NoError(t, err)
			assert.Empty(t, lines, "%s client of %s: %s", source, tc.target, tc.payload)
		}
	}
}

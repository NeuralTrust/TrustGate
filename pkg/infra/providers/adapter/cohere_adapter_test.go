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

func TestCohereAdapter_RoundtripRequest(t *testing.T) {
	input := `{
		"model": "command-r-plus",
		"messages": [{"role": "user", "content": "Hello"}],
		"max_tokens": 100,
		"temperature": 0.7
	}`

	a := &CohereAdapter{}
	canonical, err := a.DecodeRequest([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, "command-r-plus", canonical.Model)
	assert.Len(t, canonical.Messages, 1)

	encoded, err := a.EncodeRequest(canonical)
	require.NoError(t, err)

	var result map[string]any
	require.NoError(t, json.Unmarshal(encoded, &result))
	assert.Equal(t, "command-r-plus", result["model"])
}

func TestCohereAdapter_OpenAIToCohereCrossFormat(t *testing.T) {
	reg := NewRegistry()
	openaiReq := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`

	out, err := reg.AdaptRequest([]byte(openaiReq), FormatOpenAI, FormatCohere)
	require.NoError(t, err)

	var cohereReq map[string]any
	require.NoError(t, json.Unmarshal(out, &cohereReq))
	assert.Equal(t, "gpt-4", cohereReq["model"])
	msgs := cohereReq["messages"].([]any)
	assert.Len(t, msgs, 1)
}

func TestCohereAdapter_StreamChunkContentDelta(t *testing.T) {
	a := &CohereAdapter{}
	chunk := []byte(`{"type":"content-delta","delta":{"message":{"content":{"type":"text","text":"hi"}}}}`)

	got, err := a.DecodeStreamChunk(chunk)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "hi", got.Delta)
}

func TestUsageCache_Cohere_CachedTokens(t *testing.T) {
	const usage = `{"billed_units":{"input_tokens":1480,"output_tokens":12},"tokens":{"input_tokens":1500,"output_tokens":12},"cached_tokens":600}`
	want := &CanonicalUsage{InputTokens: 1500, OutputTokens: 12, TotalTokens: 1512, CachedInputTokens: 600}
	runUsageCases(t, &CohereAdapter{}, []usageCase{
		{
			name:      "buffered",
			body:      []byte(`{"id":"co-1","finish_reason":"COMPLETE","message":{"role":"assistant","content":[{"type":"text","text":"hi"}]},"usage":` + usage + `}`),
			path:      "response",
			wantUsage: want,
		},
		{
			name:      "stream message-end",
			body:      []byte(`{"type":"message-end","delta":{"finish_reason":"COMPLETE","usage":` + usage + `}}`),
			path:      "stream",
			wantUsage: want,
		},
		{
			name:      "no cached tokens",
			body:      []byte(`{"id":"co-1","finish_reason":"COMPLETE","message":{"role":"assistant","content":[{"type":"text","text":"hi"}]},"usage":{"tokens":{"input_tokens":10,"output_tokens":2}}}`),
			path:      "response",
			wantUsage: &CanonicalUsage{InputTokens: 10, OutputTokens: 2, TotalTokens: 12},
		},
	})
}

func TestCohereEmbedAdapter_OpenAIToCohere(t *testing.T) {
	reg := NewRegistry()
	openaiReq := `{"model":"embed-english-v3.0","input":["hello","world"]}`

	out, err := AdaptEmbeddingRequest(reg, []byte(openaiReq), FormatOpenAIEmbeddings, FormatCohereEmbed)
	require.NoError(t, err)

	var cohereReq map[string]any
	require.NoError(t, json.Unmarshal(out, &cohereReq))
	assert.Equal(t, "embed-english-v3.0", cohereReq["model"])
	assert.Equal(t, []any{"hello", "world"}, cohereReq["texts"])
}

func TestCohereRerankAdapter_DecodeRequest_Model(t *testing.T) {
	a := &CohereRerankAdapter{}
	body := []byte(`{"model":"rerank-english-v3.0","query":"q","documents":["a"]}`)

	got, err := a.DecodeRequest(body)
	require.NoError(t, err)
	assert.Equal(t, "rerank-english-v3.0", got.Model)
}

func TestCohere_DecodeStreamChunk_SkipsThinking(t *testing.T) {
	a := &CohereAdapter{}
	thinking := []byte(`{"type":"content-delta","delta":{"message":{"content":{"type":"thinking","thinking":"private"}}}}`)
	chunk, err := a.DecodeStreamChunk(thinking)
	require.NoError(t, err)
	assert.Nil(t, chunk)

	text := []byte(`{"type":"content-delta","delta":{"message":{"content":{"type":"text","text":"hello"}}}}`)
	chunk, err = a.DecodeStreamChunk(text)
	require.NoError(t, err)
	require.NotNil(t, chunk)
	assert.Equal(t, "hello", chunk.Delta)
}

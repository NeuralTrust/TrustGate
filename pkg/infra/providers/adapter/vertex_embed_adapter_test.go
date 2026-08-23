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

func TestVertexEmbedAdapter_OpenAIToVertexSingle(t *testing.T) {
	reg := NewRegistry()
	out, err := AdaptEmbeddingRequest(reg, []byte(`{"model":"text-embedding-004","input":"hello"}`), FormatOpenAIEmbeddings, FormatVertexEmbed)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))
	assert.NotContains(t, got, "requests")
	content := got["content"].(map[string]any)
	parts := content["parts"].([]any)
	assert.Equal(t, "hello", parts[0].(map[string]any)["text"])
}

func TestVertexEmbedAdapter_OpenAIToVertexBatch(t *testing.T) {
	reg := NewRegistry()
	out, err := AdaptEmbeddingRequest(reg, []byte(`{"model":"text-embedding-004","input":["a","b"]}`), FormatOpenAIEmbeddings, FormatVertexEmbed)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))
	reqs := got["requests"].([]any)
	require.Len(t, reqs, 2)
}

func TestVertexEmbedAdapter_VertexToOpenAIResponse(t *testing.T) {
	reg := NewRegistry()
	out, err := AdaptEmbeddingResponse(reg, []byte(`{"embedding":{"values":[0.1,0.2]}}`), FormatOpenAIEmbeddings, FormatVertexEmbed)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))
	data := got["data"].([]any)
	require.Len(t, data, 1)
	emb := data[0].(map[string]any)["embedding"].([]any)
	assert.Equal(t, []any{0.1, 0.2}, emb)
}

func TestVertexEmbedAdapter_BatchResponseToOpenAI(t *testing.T) {
	reg := NewRegistry()
	body := `{"embeddings":[{"values":[0.1]},{"values":[0.2]}]}`
	out, err := AdaptEmbeddingResponse(reg, []byte(body), FormatOpenAIEmbeddings, FormatVertexEmbed)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))
	assert.Len(t, got["data"].([]any), 2)
}

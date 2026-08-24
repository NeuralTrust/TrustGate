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

func TestBedrockTitanEmbedAdapter_OpenAIToTitanSingle(t *testing.T) {
	reg := NewRegistry()
	out, err := AdaptEmbeddingRequest(reg, []byte(`{"model":"amazon.titan-embed-text-v2:0","input":"hello"}`), FormatOpenAIEmbeddings, FormatBedrockTitanEmbed)
	require.NoError(t, err)

	var got titanEmbedRequest
	require.NoError(t, json.Unmarshal(out, &got))
	assert.Equal(t, "hello", got.InputText)
	assert.Empty(t, got.InputTexts)
}

func TestBedrockTitanEmbedAdapter_OpenAIToTitanBatch(t *testing.T) {
	reg := NewRegistry()
	out, err := AdaptEmbeddingRequest(reg, []byte(`{"model":"amazon.titan-embed-text-v2:0","input":["a","b"]}`), FormatOpenAIEmbeddings, FormatBedrockTitanEmbed)
	require.NoError(t, err)

	var got titanEmbedRequest
	require.NoError(t, json.Unmarshal(out, &got))
	assert.Equal(t, []string{"a", "b"}, got.InputTexts)
	assert.Empty(t, got.InputText)
}

func TestBedrockTitanEmbedAdapter_TitanToOpenAIResponse(t *testing.T) {
	reg := NewRegistry()
	out, err := AdaptEmbeddingResponse(reg, []byte(`{"embedding":[0.1,0.2],"inputTextTokenCount":3}`), FormatOpenAIEmbeddings, FormatBedrockTitanEmbed)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))
	data := got["data"].([]any)
	require.Len(t, data, 1)
	assert.Equal(t, []any{0.1, 0.2}, data[0].(map[string]any)["embedding"])
	usage := got["usage"].(map[string]any)
	assert.Equal(t, float64(3), usage["prompt_tokens"])
}

func TestBedrockTitanEmbed_DoesNotUseChatTitanAdapter(t *testing.T) {
	reg := NewRegistry()
	out, err := AdaptEmbeddingRequest(reg, []byte(`{"model":"amazon.titan-embed-text-v1","input":"hi"}`), FormatOpenAIEmbeddings, FormatBedrockTitanEmbed)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))
	assert.NotContains(t, got, "textGenerationConfig")
	assert.Equal(t, "hi", got["inputText"])
}

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

	"github.com/NeuralTrust/TrustGate/pkg/domain/provider"
)

func canonicalEmbedding(t *testing.T, emb CanonicalEmbeddingRequest) *CanonicalRequest {
	t.Helper()
	raw, err := json.Marshal(emb)
	require.NoError(t, err)
	return &CanonicalRequest{Model: emb.Model, Metadata: map[string]interface{}{"embedding": json.RawMessage(raw)}}
}

func TestEmbeddingFields_VertexCarriesTaskTypeTitleAndDimensions(t *testing.T) {
	req := canonicalEmbedding(t, CanonicalEmbeddingRequest{
		Model:      "gemini-embedding-001",
		Inputs:     []string{"a", "b"},
		TaskType:   "RETRIEVAL_DOCUMENT",
		Titles:     []string{"first", ""},
		Dimensions: 256,
	})

	out, err := (&VertexEmbedAdapter{}).EncodeRequest(req)
	require.NoError(t, err)

	assert.JSONEq(t, `{"requests":[
		{"content":{"parts":[{"text":"a"}]},"taskType":"RETRIEVAL_DOCUMENT","title":"first","outputDimensionality":256},
		{"content":{"parts":[{"text":"b"}]},"taskType":"RETRIEVAL_DOCUMENT","outputDimensionality":256}
	]}`, string(out))
}

func TestEmbeddingFields_VertexSingleCarriesFields(t *testing.T) {
	req := canonicalEmbedding(t, CanonicalEmbeddingRequest{
		Inputs:     []string{"a"},
		TaskType:   "CLUSTERING",
		Titles:     []string{"t"},
		Dimensions: 128,
	})

	out, err := (&VertexEmbedAdapter{}).EncodeRequest(req)
	require.NoError(t, err)

	assert.JSONEq(t, `{"content":{"parts":[{"text":"a"}]},"taskType":"CLUSTERING","title":"t","outputDimensionality":128}`, string(out))
}

func TestEmbeddingFields_CohereInputTypeFromTaskType(t *testing.T) {
	cases := map[string]string{
		"RETRIEVAL_QUERY":     "search_query",
		"RETRIEVAL_DOCUMENT":  "search_document",
		"CLASSIFICATION":      "classification",
		"CLUSTERING":          "clustering",
		"SEMANTIC_SIMILARITY": "search_document",
		"":                    "search_document",
	}
	for taskType, want := range cases {
		t.Run(taskType, func(t *testing.T) {
			req := canonicalEmbedding(t, CanonicalEmbeddingRequest{Model: "embed-v4.0", Inputs: []string{"a"}, TaskType: taskType, Dimensions: 256, Titles: []string{"t"}})

			out, err := (&CohereEmbedAdapter{}).EncodeRequest(req)
			require.NoError(t, err)

			assert.JSONEq(t, `{"model":"embed-v4.0","texts":["a"],"input_type":"`+want+`","embedding_types":["float"]}`, string(out))
		})
	}
}

func TestEmbeddingFields_CohereExplicitInputTypeWins(t *testing.T) {
	req := canonicalEmbedding(t, CanonicalEmbeddingRequest{Inputs: []string{"a"}, InputType: "classification", TaskType: "RETRIEVAL_QUERY"})

	out, err := (&CohereEmbedAdapter{}).EncodeRequest(req)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))
	assert.Equal(t, "classification", got["input_type"])
}

func TestEmbeddingFields_TitanDropsTaskTypeTitleAndDimensions(t *testing.T) {
	req := canonicalEmbedding(t, CanonicalEmbeddingRequest{Model: "amazon.titan-embed-text-v2:0", Inputs: []string{"a"}, TaskType: "RETRIEVAL_QUERY", Titles: []string{"t"}, Dimensions: 256})

	out, err := (&BedrockTitanEmbedAdapter{}).EncodeRequest(req)
	require.NoError(t, err)

	assert.NotContains(t, string(out), "256")
	assert.NotContains(t, string(out), "RETRIEVAL_QUERY")
	assert.NotContains(t, string(out), `"t"`)
}

func TestEmbeddingFields_OpenAIEncodesDimensions(t *testing.T) {
	req := canonicalEmbedding(t, CanonicalEmbeddingRequest{Model: "text-embedding-3-small", Inputs: []string{"a"}, TaskType: "RETRIEVAL_QUERY", Titles: []string{"t"}, Dimensions: 256})

	out, err := (&OpenAIEmbeddingsAdapter{}).EncodeRequest(req)
	require.NoError(t, err)

	assert.JSONEq(t, `{"model":"text-embedding-3-small","input":"a","dimensions":256}`, string(out))
}

func TestWithoutEmbeddingDimensions(t *testing.T) {
	req := canonicalEmbedding(t, CanonicalEmbeddingRequest{Model: "m", Inputs: []string{"a"}, Dimensions: 256})

	got, err := withoutEmbeddingDimensions(req)
	require.NoError(t, err)

	emb, err := embeddingFromCanonical(got)
	require.NoError(t, err)
	assert.Zero(t, emb.Dimensions)
	assert.Equal(t, []string{"a"}, emb.Inputs)
}

func TestAcceptsEmbeddingDimensions(t *testing.T) {
	assert.True(t, acceptsEmbeddingDimensions(provider.OpenAI))
	assert.True(t, acceptsEmbeddingDimensions(provider.Azure))
	assert.False(t, acceptsEmbeddingDimensions(provider.Mistral))
	assert.False(t, acceptsEmbeddingDimensions(provider.OpenAICompatible))
	assert.False(t, acceptsEmbeddingDimensions(""))
}

func TestEmbeddingFields_OpenAIInputEncodesAsBefore(t *testing.T) {
	reg := NewRegistry()
	body := []byte(`{"model":"m","input":["a","b"],"dimensions":256}`)
	cases := map[Format]string{
		FormatVertexEmbed:       `{"requests":[{"content":{"parts":[{"text":"a"}]}},{"content":{"parts":[{"text":"b"}]}}]}`,
		FormatCohereEmbed:       `{"model":"m","texts":["a","b"],"input_type":"search_document","embedding_types":["float"]}`,
		FormatBedrockTitanEmbed: `{"inputTexts":["a","b"]}`,
	}
	for target, want := range cases {
		t.Run(string(target), func(t *testing.T) {
			out, err := AdaptEmbeddingRequestForProvider(reg, body, FormatOpenAIEmbeddings, target, provider.OpenAI)
			require.NoError(t, err)
			assert.JSONEq(t, want, string(out))
		})
	}
}

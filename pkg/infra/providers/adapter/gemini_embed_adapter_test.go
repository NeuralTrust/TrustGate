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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/domain/provider"
)

func decodeGeminiEmbedding(t *testing.T, f Format, body string) *CanonicalEmbeddingRequest {
	t.Helper()
	a, err := NewRegistry().GetAdapter(f)
	require.NoError(t, err)
	req, err := a.DecodeRequest([]byte(body))
	require.NoError(t, err)
	emb, err := embeddingFromCanonical(req)
	require.NoError(t, err)
	assert.Equal(t, emb.Model, req.Model)
	return emb
}

func TestGeminiEmbed_DecodeSingle(t *testing.T) {
	emb := decodeGeminiEmbedding(t, FormatGeminiEmbed, `{
		"model":"models/gemini-embedding-001",
		"content":{"parts":[{"text":"hello"},{"text":"world"}]},
		"taskType":"RETRIEVAL_QUERY","title":"greeting","outputDimensionality":768}`)

	assert.Equal(t, &CanonicalEmbeddingRequest{
		Model:      "gemini-embedding-001",
		Inputs:     []string{"hello\nworld"},
		TaskType:   "RETRIEVAL_QUERY",
		Titles:     []string{"greeting"},
		Dimensions: 768,
	}, emb)
}

func TestGeminiEmbed_DecodeBatchIgnoresPerRequestModel(t *testing.T) {
	emb := decodeGeminiEmbedding(t, FormatGeminiBatchEmbed, `{
		"model":"gemini-embedding-001",
		"requests":[
			{"model":"models/auto","content":{"parts":[{"text":"a"}]},"taskType":"CLUSTERING"},
			{"model":"models/other","content":{"parts":[{"text":"b"}]},"taskType":"CLUSTERING","title":"bee"}
		]}`)

	assert.Equal(t, "gemini-embedding-001", emb.Model)
	assert.Equal(t, []string{"a", "b"}, emb.Inputs)
	assert.Equal(t, []string{"", "bee"}, emb.Titles)
	assert.Equal(t, "CLUSTERING", emb.TaskType)
}

func TestGeminiEmbed_DecodeWithoutModel(t *testing.T) {
	emb := decodeGeminiEmbedding(t, FormatGeminiBatchEmbed, `{"requests":[{"model":"models/x","content":{"parts":[{"text":"a"}]}}]}`)

	assert.Empty(t, emb.Model)
	assert.Nil(t, emb.Titles)
}

func TestGeminiEmbed_EmbedContentConfigFallback(t *testing.T) {
	emb := decodeGeminiEmbedding(t, FormatGeminiEmbed, `{
		"content":{"parts":[{"text":"a"}]},
		"taskType":"RETRIEVAL_DOCUMENT",
		"embedContentConfig":{"taskType":"CLUSTERING","title":"t","outputDimensionality":64,"autoTruncate":true}}`)

	assert.Equal(t, "RETRIEVAL_DOCUMENT", emb.TaskType)
	assert.Equal(t, []string{"t"}, emb.Titles)
	assert.Equal(t, 64, emb.Dimensions)
}

func TestGeminiEmbed_DecodeErrors(t *testing.T) {
	cases := []struct {
		name   string
		format Format
		body   string
	}{
		{"no content", FormatGeminiEmbed, `{"model":"m"}`},
		{"no parts", FormatGeminiEmbed, `{"content":{"parts":[]}}`},
		{"inline data", FormatGeminiEmbed, `{"content":{"parts":[{"inlineData":{"mimeType":"image/png","data":"AA=="}}]}}`},
		{"text and file data", FormatGeminiEmbed, `{"content":{"parts":[{"text":"a","fileData":{"fileUri":"gs://b/o"}}]}}`},
		{"negative dimensionality", FormatGeminiEmbed, `{"content":{"parts":[{"text":"a"}]},"outputDimensionality":-1}`},
		{"empty batch", FormatGeminiBatchEmbed, `{"requests":[]}`},
		{"mixed task type", FormatGeminiBatchEmbed, `{"requests":[{"content":{"parts":[{"text":"a"}]},"taskType":"CLUSTERING"},{"content":{"parts":[{"text":"b"}]}}]}`},
		{"mixed dimensionality", FormatGeminiBatchEmbed, `{"requests":[{"content":{"parts":[{"text":"a"}]},"outputDimensionality":64},{"content":{"parts":[{"text":"b"}]},"outputDimensionality":128}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := NewRegistry().GetAdapter(tc.format)
			require.NoError(t, err)
			_, err = a.DecodeRequest([]byte(tc.body))
			var unsupported *UnsupportedContentError
			assert.True(t, errors.As(err, &unsupported), "got %v", err)
		})
	}
}

func TestGeminiEmbed_MalformedJSONIsARequestDecodeError(t *testing.T) {
	for _, f := range []Format{FormatGeminiEmbed, FormatGeminiBatchEmbed} {
		a, err := NewRegistry().GetAdapter(f)
		require.NoError(t, err)
		_, err = a.DecodeRequest([]byte(`{"content":`))
		var decodeErr *RequestDecodeError
		require.True(t, errors.As(err, &decodeErr), "got %v", err)
		assert.Equal(t, f, decodeErr.Format)
	}
}

func TestGeminiEmbed_ResponseShapeFollowsTheAction(t *testing.T) {
	reg := NewRegistry()
	one := `{"data":[{"index":0,"embedding":[0.1,0.2]}]}`
	two := `{"data":[{"index":0,"embedding":[0.1]},{"index":1,"embedding":[0.2]}]}`

	out, err := AdaptEmbeddingResponse(reg, []byte(one), FormatGeminiEmbed, FormatOpenAIEmbeddings)
	require.NoError(t, err)
	assert.JSONEq(t, `{"embedding":{"values":[0.1,0.2]}}`, string(out))

	out, err = AdaptEmbeddingResponse(reg, []byte(one), FormatGeminiBatchEmbed, FormatOpenAIEmbeddings)
	require.NoError(t, err)
	assert.JSONEq(t, `{"embeddings":[{"values":[0.1,0.2]}]}`, string(out))

	out, err = AdaptEmbeddingResponse(reg, []byte(two), FormatGeminiBatchEmbed, FormatOpenAIEmbeddings)
	require.NoError(t, err)
	assert.JSONEq(t, `{"embeddings":[{"values":[0.1]},{"values":[0.2]}]}`, string(out))

	_, err = AdaptEmbeddingResponse(reg, []byte(two), FormatGeminiEmbed, FormatOpenAIEmbeddings)
	assert.Error(t, err)
}

func TestGeminiEmbed_ResponseFromEachTarget(t *testing.T) {
	reg := NewRegistry()
	cases := map[Format]string{
		FormatVertexEmbed:       `{"embedding":{"values":[0.5]}}`,
		FormatOpenAIEmbeddings:  `{"data":[{"index":0,"embedding":[0.5]}]}`,
		FormatCohereEmbed:       `{"embeddings":[[0.5]]}`,
		FormatBedrockTitanEmbed: `{"embedding":[0.5],"inputTextTokenCount":1}`,
	}
	for target, body := range cases {
		t.Run(string(target), func(t *testing.T) {
			out, err := AdaptEmbeddingResponse(reg, []byte(body), FormatGeminiBatchEmbed, target)
			require.NoError(t, err)
			assert.JSONEq(t, `{"embeddings":[{"values":[0.5]}]}`, string(out))
		})
	}
}

func TestGeminiEmbed_CrossFormatRequests(t *testing.T) {
	reg := NewRegistry()
	batchOfOne := `{"model":"gemini-embedding-001","requests":[{"content":{"parts":[{"text":"a"}]},"taskType":"RETRIEVAL_QUERY","title":"t","outputDimensionality":256}]}`
	cases := []struct {
		target   Format
		provider string
		want     string
	}{
		{FormatVertexEmbed, provider.Vertex, `{"content":{"parts":[{"text":"a"}]},"taskType":"RETRIEVAL_QUERY","title":"t","outputDimensionality":256}`},
		{FormatOpenAIEmbeddings, provider.OpenAI, `{"model":"gemini-embedding-001","input":"a","dimensions":256}`},
		{FormatOpenAIEmbeddings, provider.Azure, `{"model":"gemini-embedding-001","input":"a","dimensions":256}`},
		{FormatOpenAIEmbeddings, provider.Mistral, `{"model":"gemini-embedding-001","input":"a"}`},
		{FormatOpenAIEmbeddings, provider.OpenAICompatible, `{"model":"gemini-embedding-001","input":"a"}`},
		{FormatCohereEmbed, provider.Cohere, `{"model":"gemini-embedding-001","texts":["a"],"input_type":"search_query","embedding_types":["float"]}`},
		{FormatBedrockTitanEmbed, provider.Bedrock, `{"inputText":"a"}`},
	}
	for _, tc := range cases {
		t.Run(string(tc.target)+"/"+tc.provider, func(t *testing.T) {
			out, err := AdaptEmbeddingRequestForProvider(reg, []byte(batchOfOne), FormatGeminiBatchEmbed, tc.target, tc.provider)
			require.NoError(t, err)
			assert.JSONEq(t, tc.want, string(out))
		})
	}
}

func TestGeminiEmbed_EncodeRequestRoundTrip(t *testing.T) {
	reg := NewRegistry()
	batch := `{"model":"m","requests":[{"content":{"parts":[{"text":"a"}]},"taskType":"CLUSTERING"},{"content":{"parts":[{"text":"b"}]},"taskType":"CLUSTERING","title":"bee"}]}`

	out, err := AdaptEmbeddingRequest(reg, []byte(batch), FormatGeminiBatchEmbed, FormatOpenAIEmbeddings)
	require.NoError(t, err)
	back, err := AdaptEmbeddingRequest(reg, out, FormatOpenAIEmbeddings, FormatGeminiBatchEmbed)
	require.NoError(t, err)
	assert.JSONEq(t, `{"requests":[{"model":"models/m","content":{"parts":[{"text":"a"}]}},{"model":"models/m","content":{"parts":[{"text":"b"}]}}]}`, string(back))

	single, err := AdaptEmbeddingRequest(reg, []byte(`{"model":"m","input":"a"}`), FormatOpenAIEmbeddings, FormatGeminiEmbed)
	require.NoError(t, err)
	assert.JSONEq(t, `{"model":"models/m","content":{"parts":[{"text":"a"}]}}`, string(single))

	_, err = AdaptEmbeddingRequest(reg, []byte(`{"model":"m","input":["a","b"]}`), FormatOpenAIEmbeddings, FormatGeminiEmbed)
	assert.Error(t, err)
}

func TestGeminiEmbed_FormatLists(t *testing.T) {
	for _, f := range []Format{FormatGeminiEmbed, FormatGeminiBatchEmbed} {
		assert.True(t, ModelInPath(f), f)
		assert.True(t, SupportedSourceFormat(f), f)
		assert.False(t, IsChatRequest("", f), f)
		assert.Equal(t, FormatGemini, errorDialect(f), f)
		assert.False(t, OpenAIErrorDialect(f), f)
	}
	assert.True(t, ModelInPath(FormatGemini))
	assert.False(t, ModelInPath(FormatVertexEmbed))
	assert.False(t, ModelInPath(FormatOpenAIEmbeddings))
}

func TestGeminiEmbed_GatewayErrorsUseTheGeminiEnvelope(t *testing.T) {
	for _, f := range []Format{FormatGeminiEmbed, FormatGeminiBatchEmbed} {
		assert.True(t, NeedsAdaptedError(f), f)
		assert.JSONEq(t, `{"error":{"code":400,"message":"bad","status":"INVALID_ARGUMENT"}}`, string(EncodeErrorBody(f, 400, "bad")), f)
	}
}

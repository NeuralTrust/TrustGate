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

	"github.com/NeuralTrust/TrustGate/pkg/domain/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVertexPredictEmbed_DecodeRequest(t *testing.T) {
	t.Parallel()
	a := &VertexPredictEmbedAdapter{}
	body := `{"model":"gemini-embedding-001","instances":[{"content":"a","task_type":"RETRIEVAL_QUERY"},{"content":"b"}],"parameters":{"outputDimensionality":256,"autoTruncate":true}}`

	canonical, err := a.DecodeRequest([]byte(body))
	require.NoError(t, err)
	emb, err := embeddingFromCanonical(canonical)
	require.NoError(t, err)
	assert.Equal(t, "gemini-embedding-001", emb.Model)
	assert.Equal(t, []string{"a", "b"}, emb.Inputs)
	assert.Equal(t, 256, emb.Dimensions)
}

func TestVertexPredictEmbed_DecodeRequestRejectsBodiesWithoutText(t *testing.T) {
	t.Parallel()
	a := &VertexPredictEmbedAdapter{}
	for name, body := range map[string]string{
		"missing instances": `{"parameters":{}}`,
		"empty instances":   `{"instances":[]}`,
		"no content":        `{"instances":[{"task_type":"RETRIEVAL_QUERY"}]}`,
		"blank content":     `{"instances":[{"content":"a"},{"content":"  "}]}`,
		"not json":          `{"instances":`,
		"content not text":  `{"instances":[{"content":{"parts":[]}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := a.DecodeRequest([]byte(body))
			require.Error(t, err)
			assert.True(t, IsRequestDecodeError(err), err)
		})
	}
}

func TestVertexPredictEmbed_EncodeRequestRoundTrip(t *testing.T) {
	t.Parallel()
	a := &VertexPredictEmbedAdapter{}

	canonical, err := a.DecodeRequest([]byte(`{"instances":[{"content":"a"},{"content":"b"}],"parameters":{"outputDimensionality":128}}`))
	require.NoError(t, err)
	out, err := a.EncodeRequest(canonical)
	require.NoError(t, err)
	assert.JSONEq(t, `{"instances":[{"content":"a"},{"content":"b"}],"parameters":{"outputDimensionality":128}}`, string(out))

	canonical, err = a.DecodeRequest([]byte(`{"instances":[{"content":"a"}]}`))
	require.NoError(t, err)
	out, err = a.EncodeRequest(canonical)
	require.NoError(t, err)
	assert.JSONEq(t, `{"instances":[{"content":"a"}]}`, string(out))
}

func TestVertexPredictEmbed_DecodeResponseSumsTokenCounts(t *testing.T) {
	t.Parallel()
	a := &VertexPredictEmbedAdapter{}
	body := `{"predictions":[{"embeddings":{"values":[0.1,0.2],"statistics":{"token_count":3,"truncated":false}}},{"embeddings":{"values":[0.3,0.4],"statistics":{"token_count":5}}}],"metadata":{"billableCharacterCount":7}}`

	resp, err := a.DecodeResponse([]byte(body))
	require.NoError(t, err)
	require.NotNil(t, resp.Usage)
	assert.Equal(t, 8, resp.Usage.InputTokens)
	assert.Equal(t, 8, resp.Usage.TotalTokens)

	emb, err := embeddingResponseFromCanonical(resp)
	require.NoError(t, err)
	assert.Equal(t, [][]float64{{0.1, 0.2}, {0.3, 0.4}}, emb.Embeddings)
}

func TestVertexPredictEmbed_DecodeResponseWithoutStatistics(t *testing.T) {
	t.Parallel()
	a := &VertexPredictEmbedAdapter{}

	resp, err := a.DecodeResponse([]byte(`{"predictions":[{"embeddings":{"values":[0.5]}}]}`))
	require.NoError(t, err)
	assert.Nil(t, resp.Usage)
	emb, err := embeddingResponseFromCanonical(resp)
	require.NoError(t, err)
	assert.Equal(t, [][]float64{{0.5}}, emb.Embeddings)
}

func TestVertexPredictEmbed_CrossFormatToOpenAI(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()

	out, err := AdaptEmbeddingRequest(reg,
		[]byte(`{"model":"text-embedding-3-small","instances":[{"content":"a","task_type":"RETRIEVAL_QUERY"},{"content":"b"}],"parameters":{"outputDimensionality":256}}`),
		FormatVertexPredictEmbed, FormatOpenAIEmbeddings)
	require.NoError(t, err)
	assert.JSONEq(t, `{"model":"text-embedding-3-small","input":["a","b"],"dimensions":256}`, string(out))

	out, err = AdaptEmbeddingRequest(reg,
		[]byte(`{"model":"text-embedding-3-small","instances":[{"content":"a"}]}`),
		FormatVertexPredictEmbed, FormatOpenAIEmbeddings)
	require.NoError(t, err)
	assert.JSONEq(t, `{"model":"text-embedding-3-small","input":"a"}`, string(out))

	resp, err := AdaptEmbeddingResponse(reg,
		[]byte(`{"model":"text-embedding-3-small","data":[{"index":0,"embedding":[0.1]},{"index":1,"embedding":[0.2]}],"usage":{"prompt_tokens":2,"total_tokens":2}}`),
		FormatVertexPredictEmbed, FormatOpenAIEmbeddings)
	require.NoError(t, err)
	assert.JSONEq(t, `{"predictions":[{"embeddings":{"values":[0.1]}},{"embeddings":{"values":[0.2]}}]}`, string(resp))
}

func TestVertexPredictEmbed_CrossFormatRejectsEmptyInstances(t *testing.T) {
	t.Parallel()
	_, err := AdaptEmbeddingRequest(NewRegistry(), []byte(`{"instances":[]}`), FormatVertexPredictEmbed, FormatOpenAIEmbeddings)
	require.Error(t, err)
	assert.True(t, IsRequestDecodeError(err))
}

func TestVertexPredictEmbed_SameFormatIsForwardedAsReceived(t *testing.T) {
	t.Parallel()
	body := []byte(`{"instances":[{"content":"a","title":"t"}],"parameters":{"autoTruncate":false}}`)
	out, err := AdaptEmbeddingRequest(NewRegistry(), body, FormatVertexPredictEmbed, FormatVertexPredictEmbed)
	require.NoError(t, err)
	assert.Equal(t, body, out)
}

func TestResolveTargetFormatForCapability_VertexPredictEmbed(t *testing.T) {
	t.Parallel()
	assert.Equal(t, FormatVertexPredictEmbed,
		ResolveTargetFormatForCapability(provider.Vertex, "embeddings", FormatVertexPredictEmbed, nil))
	assert.Equal(t, FormatVertexEmbed,
		ResolveTargetFormatForCapability(provider.Vertex, "embeddings", FormatOpenAIEmbeddings, nil))
	assert.Equal(t, FormatOpenAIEmbeddings,
		ResolveTargetFormatForCapability(provider.OpenAI, "embeddings", FormatVertexPredictEmbed, nil))
	assert.Equal(t, FormatCohereEmbed,
		ResolveTargetFormatForCapability(provider.Cohere, "embeddings", FormatVertexPredictEmbed, nil))
}

func TestVertexPredictEmbed_RegisteredAsSourceFormat(t *testing.T) {
	t.Parallel()
	assert.True(t, SupportedSourceFormat(FormatVertexPredictEmbed))
	_, err := NewRegistry().GetAdapter(FormatVertexPredictEmbed)
	require.NoError(t, err)
}

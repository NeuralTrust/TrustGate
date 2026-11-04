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

package proxy_test

import (
	"context"
	"encoding/json"
	"iter"
	"net/http"
	"testing"

	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	factorymocks "github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type embeddingsTestClient struct {
	embeddingsFn func(ctx context.Context, cfg *providers.Config, body []byte) ([]byte, error)
}

func (c *embeddingsTestClient) Completions(context.Context, *providers.Config, []byte) ([]byte, error) {
	return nil, nil
}

func (c *embeddingsTestClient) CompletionsStream(context.Context, *providers.Config, []byte) (iter.Seq2[[]byte, error], error) {
	return nil, nil
}

func (c *embeddingsTestClient) Embeddings(ctx context.Context, cfg *providers.Config, body []byte) ([]byte, error) {
	return c.embeddingsFn(ctx, cfg, body)
}

func TestProviderInvoke_VertexEmbeddingsCrossFormat(t *testing.T) {
	var sentBody []byte
	client := &embeddingsTestClient{
		embeddingsFn: func(_ context.Context, _ *providers.Config, body []byte) ([]byte, error) {
			sentBody = body
			return []byte(`{"predictions":[{"embeddings":{"values":[0.1,0.2],"statistics":{"token_count":1}}}]}`), nil
		},
	}

	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("vertex").Return(client, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())

	req := &infracontext.RequestContext{
		Body:            []byte(`{"model":"text-embedding-004","input":["hello"]}`),
		SourceFormat:    string(adapter.FormatOpenAIEmbeddings),
		ProxyCapability: "embeddings",
	}
	resp, err := inv.Invoke(context.Background(), apiKeyTarget("vertex"), req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "vertex_predict_embed", req.TargetFormat)
	assert.JSONEq(t, `{"model":"text-embedding-004","instances":[{"content":"hello"}]}`, string(sentBody))

	var openaiResp map[string]any
	require.NoError(t, json.Unmarshal(resp.Body, &openaiResp))
	assert.Len(t, openaiResp["data"].([]any), 1)
}

func TestProviderInvoke_BedrockTitanEmbeddingsCrossFormat(t *testing.T) {
	var sentBody []byte
	client := &embeddingsTestClient{
		embeddingsFn: func(_ context.Context, _ *providers.Config, body []byte) ([]byte, error) {
			sentBody = body
			return []byte(`{"embedding":[0.3,0.4],"inputTextTokenCount":2}`), nil
		},
	}

	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("bedrock").Return(client, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())

	req := &infracontext.RequestContext{
		Body:            []byte(`{"model":"amazon.titan-embed-text-v2:0","input":["hello"]}`),
		SourceFormat:    string(adapter.FormatOpenAIEmbeddings),
		ProxyCapability: "embeddings",
	}
	resp, err := inv.Invoke(context.Background(), apiKeyTarget("bedrock"), req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "bedrock_titan_embed", req.TargetFormat)

	var titanReq map[string]any
	require.NoError(t, json.Unmarshal(sentBody, &titanReq))
	assert.Equal(t, "hello", titanReq["inputText"])
	assert.NotContains(t, titanReq, "textGenerationConfig")

	var openaiResp map[string]any
	require.NoError(t, json.Unmarshal(resp.Body, &openaiResp))
	assert.Len(t, openaiResp["data"].([]any), 1)
}

func vertexPredictRequest(body string) *infracontext.RequestContext {
	return &infracontext.RequestContext{
		Body:            []byte(body),
		Path:            "/c/v1beta1/projects/p/locations/global/publishers/google/models/gemini-embedding-001:predict",
		SourceFormat:    string(adapter.FormatVertexPredictEmbed),
		ProxyCapability: "embeddings",
	}
}

func TestProviderInvoke_VertexPredictPassthrough(t *testing.T) {
	const body = `{"model":"gemini-embedding-001","instances":[{"content":"a","task_type":"RETRIEVAL_QUERY"},{"content":"b"}],"parameters":{"outputDimensionality":256}}`
	const upstream = `{"predictions":[{"embeddings":{"values":[0.1],"statistics":{"token_count":3}}},{"embeddings":{"values":[0.2],"statistics":{"token_count":5}}}]}`
	var sentBody []byte
	var sentModel string
	client := &embeddingsTestClient{
		embeddingsFn: func(_ context.Context, cfg *providers.Config, body []byte) ([]byte, error) {
			sentBody = body
			sentModel = cfg.Model
			return []byte(upstream), nil
		},
	}
	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("vertex").Return(client, nil).Once()
	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())

	req := vertexPredictRequest(body)
	resp, err := inv.Invoke(context.Background(), apiKeyTarget("vertex"), req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "vertex_predict_embed", req.TargetFormat)
	assert.Equal(t, "gemini-embedding-001", sentModel)
	assert.Equal(t, "gemini-embedding-001", resp.SentModel)
	assert.JSONEq(t, body, string(sentBody))
	assert.JSONEq(t, upstream, string(resp.Body))
	require.NotNil(t, resp.Usage)
	assert.Equal(t, 8, resp.Usage.InputTokens)
}

func TestProviderInvoke_VertexPredictPassthroughWithoutStatistics(t *testing.T) {
	client := &embeddingsTestClient{
		embeddingsFn: func(context.Context, *providers.Config, []byte) ([]byte, error) {
			return []byte(`{"predictions":[{"embeddings":{"values":[0.1]}}]}`), nil
		},
	}
	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("vertex").Return(client, nil).Once()
	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())

	resp, err := inv.Invoke(context.Background(), apiKeyTarget("vertex"),
		vertexPredictRequest(`{"model":"gemini-embedding-001","instances":[{"content":"a"}]}`))

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Nil(t, resp.Usage)
}

func TestProviderInvoke_VertexPredictCrossFormatToOpenAI(t *testing.T) {
	cases := map[string]struct {
		body     string
		wantSent string
	}{
		"with output dimensionality": {
			body:     `{"model":"text-embedding-3-small","instances":[{"content":"a"},{"content":"b"}],"parameters":{"outputDimensionality":256}}`,
			wantSent: `{"model":"text-embedding-3-small","input":["a","b"],"dimensions":256}`,
		},
		"without output dimensionality": {
			body:     `{"model":"text-embedding-3-small","instances":[{"content":"a"},{"content":"b"}]}`,
			wantSent: `{"model":"text-embedding-3-small","input":["a","b"]}`,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var sentBody []byte
			client := &embeddingsTestClient{
				embeddingsFn: func(_ context.Context, _ *providers.Config, body []byte) ([]byte, error) {
					sentBody = body
					return []byte(`{"model":"text-embedding-3-small","data":[{"index":0,"embedding":[0.1]},{"index":1,"embedding":[0.2]}],"usage":{"prompt_tokens":2,"total_tokens":2}}`), nil
				},
			}
			locator := factorymocks.NewProviderLocator(t)
			locator.EXPECT().Get("openai").Return(client, nil).Once()
			inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())

			req := vertexPredictRequest(tc.body)
			resp, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), req)

			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "openai_embeddings", req.TargetFormat)
			assert.JSONEq(t, tc.wantSent, string(sentBody))
			assert.JSONEq(t, `{"predictions":[{"embeddings":{"values":[0.1]}},{"embeddings":{"values":[0.2]}}]}`, string(resp.Body))
		})
	}
}

func TestProviderInvoke_VertexPredictCrossFormatRejectsEmptyInstances(t *testing.T) {
	client := &embeddingsTestClient{
		embeddingsFn: func(context.Context, *providers.Config, []byte) ([]byte, error) {
			t.Fatal("upstream must not be called")
			return nil, nil
		},
	}
	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("openai").Return(client, nil).Once()
	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())

	_, err := inv.Invoke(context.Background(), apiKeyTarget("openai"),
		vertexPredictRequest(`{"model":"text-embedding-3-small","instances":[]}`))

	require.ErrorIs(t, err, appproxy.ErrInvalidRequestPayload)
}

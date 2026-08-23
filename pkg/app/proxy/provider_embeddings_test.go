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
			return []byte(`{"embedding":{"values":[0.1,0.2]}}`), nil
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
	assert.Equal(t, "vertex_embed", req.TargetFormat)

	var vertexReq map[string]any
	require.NoError(t, json.Unmarshal(sentBody, &vertexReq))
	content := vertexReq["content"].(map[string]any)
	parts := content["parts"].([]any)
	assert.Equal(t, "hello", parts[0].(map[string]any)["text"])

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

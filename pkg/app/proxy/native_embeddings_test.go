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
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/TrustGate/pkg/app/proxy/mocks"
	domainconsumer "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	factorymocks "github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory/mocks"
)

const geminiBatchOfOne = `{"requests":[{"model":"models/gemini-embedding-001","content":{"parts":[{"text":"hello"}]},"taskType":"RETRIEVAL_QUERY","outputDimensionality":256}]}`

func TestForward_GeminiEmbeddingsPathModelIsStamped(t *testing.T) {
	cases := map[string]string{
		"gemini": "/slug/v1beta/models/gemini-embedding-001:batchEmbedContents",
		"vertex": "/slug/v1/projects/any-project/locations/any-region/publishers/google/models/gemini-embedding-001:batchEmbedContents",
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			gatewayID := ids.New[ids.GatewayKind]()
			vertex := backendFor(gatewayID, "vertex")
			rc := routableConsumerWith(gatewayID, vertex)
			rc.Consumer.ModelPolicies = domainconsumer.ModelPolicies{
				vertex.ID: {Allowed: []string{"gemini-embedding-001"}},
			}

			invoker := proxymocks.NewProviderInvoker(t)
			invoker.EXPECT().
				Invoke(mock.Anything, mock.Anything, mock.Anything).
				Run(func(_ context.Context, _ *registrydomain.Registry, req *infracontext.RequestContext) {
					if !strings.Contains(string(req.Body), `"model":"gemini-embedding-001"`) {
						t.Fatalf("model from the path was not stamped into the body: %s", req.Body)
					}
				}).
				Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil).
				Once()

			fwd := newTestForwarder(t, invoker)
			res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
				GatewayID: gatewayID,
				Consumer:  rc,
				Request: &infracontext.RequestContext{
					Path:            path,
					Body:            []byte(`{"requests":[{"content":{"parts":[{"text":"hello"}]}}]}`),
					SourceFormat:    string(adapter.FormatGeminiBatchEmbed),
					ProxyCapability: "embeddings",
				},
			})
			require.NoError(t, err)
			assert.Equal(t, 200, res.StatusCode)
		})
	}
}

func geminiEmbeddingsInvoker(t *testing.T, providerName, upstreamResponse string, sent *[]byte) appproxy.ProviderInvoker {
	t.Helper()
	client := &embeddingsTestClient{
		embeddingsFn: func(_ context.Context, _ *providers.Config, body []byte) ([]byte, error) {
			*sent = body
			return []byte(upstreamResponse), nil
		},
	}
	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get(providerName).Return(client, nil).Once()
	return appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
}

func TestProviderInvoke_GeminiEmbeddingsAcrossTargets(t *testing.T) {
	cases := []struct {
		name     string
		provider string
		format   adapter.Format
		body     string
		upstream string
		wantSent string
		wantResp string
	}{
		{
			name:     "batch of one to vertex stays a batch",
			provider: "vertex",
			format:   adapter.FormatGeminiBatchEmbed,
			body:     geminiBatchOfOne,
			upstream: `{"embedding":{"values":[0.1,0.2]}}`,
			wantSent: `{"content":{"parts":[{"text":"hello"}]},"taskType":"RETRIEVAL_QUERY","outputDimensionality":256}`,
			wantResp: `{"embeddings":[{"values":[0.1,0.2]}]}`,
		},
		{
			name:     "single to vertex",
			provider: "vertex",
			format:   adapter.FormatGeminiEmbed,
			body:     `{"model":"gemini-embedding-001","content":{"parts":[{"text":"hello"}]}}`,
			upstream: `{"embedding":{"values":[0.1]}}`,
			wantSent: `{"model":"gemini-embedding-001","content":{"parts":[{"text":"hello"}]}}`,
			wantResp: `{"embedding":{"values":[0.1]}}`,
		},
		{
			name:     "openai keeps dimensions",
			provider: "openai",
			format:   adapter.FormatGeminiBatchEmbed,
			body:     `{"model":"text-embedding-3-small","requests":[{"content":{"parts":[{"text":"a"}]},"outputDimensionality":256},{"content":{"parts":[{"text":"b"}]},"outputDimensionality":256}]}`,
			upstream: `{"model":"text-embedding-3-small","data":[{"index":0,"embedding":[0.1]},{"index":1,"embedding":[0.2]}]}`,
			wantSent: `{"model":"text-embedding-3-small","input":["a","b"],"dimensions":256}`,
			wantResp: `{"embeddings":[{"values":[0.1]},{"values":[0.2]}]}`,
		},
		{
			name:     "mistral drops dimensions",
			provider: "mistral",
			format:   adapter.FormatGeminiEmbed,
			body:     `{"model":"mistral-embed","content":{"parts":[{"text":"a"}]},"outputDimensionality":256}`,
			upstream: `{"model":"mistral-embed","data":[{"index":0,"embedding":[0.3]}]}`,
			wantSent: `{"model":"mistral-embed","input":"a"}`,
			wantResp: `{"embedding":{"values":[0.3]}}`,
		},
		{
			name:     "cohere gets input_type",
			provider: "cohere",
			format:   adapter.FormatGeminiEmbed,
			body:     `{"model":"embed-v4.0","content":{"parts":[{"text":"a"}]},"taskType":"RETRIEVAL_QUERY"}`,
			upstream: `{"embeddings":[[0.4]]}`,
			wantSent: `{"model":"embed-v4.0","texts":["a"],"input_type":"search_query","embedding_types":["float"]}`,
			wantResp: `{"embedding":{"values":[0.4]}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var sent []byte
			inv := geminiEmbeddingsInvoker(t, tc.provider, tc.upstream, &sent)

			resp, err := inv.Invoke(context.Background(), apiKeyTarget(tc.provider), &infracontext.RequestContext{
				Method:          http.MethodPost,
				Body:            []byte(tc.body),
				SourceFormat:    string(tc.format),
				ProxyCapability: "embeddings",
			})

			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.JSONEq(t, tc.wantSent, string(sent))
			assert.JSONEq(t, tc.wantResp, string(resp.Body))
		})
	}
}

func TestProviderInvoke_GeminiEmbeddingsModelNotAllowed(t *testing.T) {
	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("vertex").Return(&embeddingsTestClient{}, nil).Once()
	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())

	_, err := inv.Invoke(context.Background(), apiKeyTarget("vertex"), &infracontext.RequestContext{
		Method:          http.MethodPost,
		Path:            "/acme/v1beta/models/gemini-embedding-001:batchEmbedContents",
		Body:            []byte(`{"model":"gemini-embedding-001","requests":[{"content":{"parts":[{"text":"a"}]}}]}`),
		SourceFormat:    string(adapter.FormatGeminiBatchEmbed),
		ProxyCapability: "embeddings",
		AllowedModels:   []string{"text-embedding-005"},
	})

	assert.ErrorIs(t, err, appproxy.ErrModelNotAllowed)
}

func TestProviderInvoke_GeminiEmbeddingsInvalidBodiesAre400s(t *testing.T) {
	bodies := map[string]string{
		"mixed task type": `{"requests":[{"content":{"parts":[{"text":"a"}]},"taskType":"CLUSTERING"},{"content":{"parts":[{"text":"b"}]}}]}`,
		"malformed json":  `{"requests":`,
		"non-text part":   `{"requests":[{"content":{"parts":[{"inlineData":{"mimeType":"image/png","data":"AA=="}}]}}]}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			locator := factorymocks.NewProviderLocator(t)
			locator.EXPECT().Get("vertex").Return(&embeddingsTestClient{}, nil).Once()
			inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())

			_, err := inv.Invoke(context.Background(), apiKeyTarget("vertex"), &infracontext.RequestContext{
				Method:          http.MethodPost,
				Body:            []byte(body),
				SourceFormat:    string(adapter.FormatGeminiBatchEmbed),
				ProxyCapability: "embeddings",
			})

			assert.ErrorIs(t, err, appproxy.ErrInvalidRequestPayload)
		})
	}
}

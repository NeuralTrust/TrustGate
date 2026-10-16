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
	"strings"
	"testing"

	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	factorymocks "github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory/mocks"
	providermocks "github.com/NeuralTrust/TrustGate/pkg/infra/providers/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type cohereTestClient struct {
	completionsFn func(ctx context.Context, cfg *providers.Config, body []byte) ([]byte, error)
	embeddingsFn  func(ctx context.Context, cfg *providers.Config, body []byte) ([]byte, error)
	rerankFn      func(ctx context.Context, cfg *providers.Config, body []byte) ([]byte, error)
}

func (c *cohereTestClient) Completions(ctx context.Context, cfg *providers.Config, body []byte) ([]byte, error) {
	return c.completionsFn(ctx, cfg, body)
}

func (c *cohereTestClient) CompletionsStream(context.Context, *providers.Config, []byte) (iter.Seq2[[]byte, error], error) {
	return nil, nil
}

func (c *cohereTestClient) Embeddings(ctx context.Context, cfg *providers.Config, body []byte) ([]byte, error) {
	return c.embeddingsFn(ctx, cfg, body)
}

func (c *cohereTestClient) Rerank(ctx context.Context, cfg *providers.Config, body []byte) ([]byte, error) {
	return c.rerankFn(ctx, cfg, body)
}

func TestProviderInvoke_CohereEmbeddingsCrossFormat(t *testing.T) {
	var sentBody []byte
	client := &cohereTestClient{
		embeddingsFn: func(_ context.Context, _ *providers.Config, body []byte) ([]byte, error) {
			sentBody = body
			return []byte(`{"embeddings":[[0.1,0.2]]}`), nil
		},
	}

	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("cohere").Return(client, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())

	req := &infracontext.RequestContext{
		Body:            []byte(`{"model":"embed-english-v3.0","input":["hello"]}`),
		SourceFormat:    string(adapter.FormatOpenAIEmbeddings),
		ProxyCapability: "embeddings",
	}
	resp, err := inv.Invoke(context.Background(), apiKeyTarget("cohere"), req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "cohere_embed", req.TargetFormat)

	var cohereReq map[string]any
	require.NoError(t, json.Unmarshal(sentBody, &cohereReq))
	assert.Equal(t, "embed-english-v3.0", cohereReq["model"])
	assert.Equal(t, []any{"hello"}, cohereReq["texts"])

	var openaiResp map[string]any
	require.NoError(t, json.Unmarshal(resp.Body, &openaiResp))
	data := openaiResp["data"].([]any)
	assert.Len(t, data, 1)
}

func TestProviderInvoke_CohereRerankPassthrough(t *testing.T) {
	var sentBody []byte
	client := &cohereTestClient{
		rerankFn: func(_ context.Context, _ *providers.Config, body []byte) ([]byte, error) {
			sentBody = body
			return []byte(`{"results":[{"index":0,"relevance_score":0.9}]}`), nil
		},
	}

	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("cohere").Return(client, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())

	body := `{"model":"rerank-english-v3.0","query":"q","documents":["a"]}`
	req := &infracontext.RequestContext{
		Body:            []byte(body),
		SourceFormat:    string(adapter.FormatCohereRerank),
		ProxyCapability: "rerank",
	}
	resp, err := inv.Invoke(context.Background(), apiKeyTarget("cohere"), req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.JSONEq(t, body, string(sentBody))
	assert.JSONEq(t, `{"results":[{"index":0,"relevance_score":0.9}]}`, string(resp.Body))
}

func TestProviderInvoke_CohereChatNativeFormat(t *testing.T) {
	client := &cohereTestClient{
		completionsFn: func(_ context.Context, _ *providers.Config, _ []byte) ([]byte, error) {
			return []byte(`{"id":"chat-1","finish_reason":"COMPLETE","message":{"role":"assistant","content":[{"type":"text","text":"hi"}]}}`), nil
		},
	}

	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("cohere").Return(client, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())

	req := &infracontext.RequestContext{
		Body:         []byte(`{"model":"command-r-plus","messages":[{"role":"user","content":"hi"}]}`),
		SourceFormat: string(adapter.FormatCohere),
	}
	resp, err := inv.Invoke(context.Background(), apiKeyTarget("cohere"), req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.JSONEq(t, `{"id":"chat-1","finish_reason":"COMPLETE","message":{"role":"assistant","content":[{"type":"text","text":"hi"}]}}`, string(resp.Body))
}

func TestProviderInvoke_CohereEmbeddingsUnsupportedProvider(t *testing.T) {
	client := providermocks.NewClient(t)

	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("openai").Return(client, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())

	req := &infracontext.RequestContext{
		Body:            []byte(`{"model":"text-embedding-3-small","input":"hi"}`),
		SourceFormat:    string(adapter.FormatOpenAIEmbeddings),
		ProxyCapability: "embeddings",
	}
	_, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), req)

	require.Error(t, err)
	assert.ErrorIs(t, err, appproxy.ErrCapabilityNotSupported)
}

func TestProviderInvoke_CohereChatResponseModel(t *testing.T) {
	t.Parallel()
	const model = "command-r7b-12-2024"
	for _, tc := range []struct {
		name  string
		body  string
		model string
	}{
		{name: "explicit model", body: `{"model":"command-r-plus","messages":[{"role":"user","content":"hi"}]}`, model: "command-r-plus"},
		{name: "routed default", body: `{"messages":[{"role":"user","content":"hi"}]}`, model: model},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client := &cohereTestClient{completionsFn: func(_ context.Context, cfg *providers.Config, body []byte) ([]byte, error) {
				var sent struct {
					Model string `json:"model"`
				}
				require.NoError(t, json.Unmarshal(body, &sent))
				require.Equal(t, tc.model, sent.Model)
				require.Equal(t, tc.model, cfg.Model)
				return []byte(`{"id":"chat-1","finish_reason":"COMPLETE","message":{"role":"assistant","content":[{"type":"text","text":"QA_OK"}]},"usage":{"tokens":{"input_tokens":512,"output_tokens":6},"cached_tokens":480}}`), nil
			}}
			locator := factorymocks.NewProviderLocator(t)
			locator.EXPECT().Get("cohere").Return(client, nil).Once()
			inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
			resp, err := inv.Invoke(context.Background(), apiKeyTarget("cohere"), &infracontext.RequestContext{
				Body: []byte(tc.body), SourceFormat: string(adapter.FormatOpenAI),
				DefaultModel: model, AllowedModels: []string{model, "command-r-plus"},
			})
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, tc.model, resp.SentModel)
			assert.Equal(t, []string{tc.model}, resp.Headers["X-Selected-Model"])
			assert.JSONEq(t, strings.ReplaceAll(`{"id":"chat-1","object":"chat.completion","model":"command-r7b-12-2024","choices":[{"index":0,"message":{"role":"assistant","content":"QA_OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":512,"completion_tokens":6,"total_tokens":518,"prompt_tokens_details":{"cached_tokens":480}}}`, model, tc.model), string(resp.Body))
		})
	}
}

func TestProviderInvoke_CohereChatStreamResponseModel(t *testing.T) {
	t.Parallel()
	const model = "command-r7b-12-2024"
	client := providermocks.NewClient(t)
	client.EXPECT().CompletionsStream(mock.Anything, mock.Anything, mock.Anything).Return(seqOf(
		[]byte(`data: {"id":"chat-stream","type":"message-start","delta":{"message":{"role":"assistant"}}}`),
		[]byte(`data: {"type":"content-delta","delta":{"message":{"content":{"type":"text","text":"QA_OK"}}}}`),
		[]byte(`data: {"type":"message-end","delta":{"finish_reason":"COMPLETE","usage":{"tokens":{"input_tokens":10,"output_tokens":2}}}}`),
	), nil).Once()
	inv := newStreamInvoker(t, "cohere", client)
	resp, err := inv.InvokeStream(context.Background(), apiKeyTarget("cohere"), &infracontext.RequestContext{
		Body:         []byte(`{"stream":true,"messages":[{"role":"user","content":"hi"}]}`),
		SourceFormat: string(adapter.FormatOpenAI), DefaultModel: model, AllowedModels: []string{model},
	})
	require.NoError(t, err)
	var text string
	var chunks int
	for _, line := range collectStream(t, resp.Stream) {
		payload, ok := strings.CutPrefix(line, "data: ")
		if !ok || payload == "[DONE]" {
			continue
		}
		var chunk struct {
			Model   string `json:"model"`
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		require.NoError(t, json.Unmarshal([]byte(payload), &chunk))
		assert.Equal(t, model, chunk.Model)
		for _, choice := range chunk.Choices {
			text += choice.Delta.Content
		}
		chunks++
	}
	assert.Positive(t, chunks)
	assert.Equal(t, "QA_OK", text)
}

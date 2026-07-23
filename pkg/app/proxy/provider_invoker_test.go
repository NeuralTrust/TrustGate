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
	"net/http"
	"testing"

	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	factorymocks "github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory/mocks"
	providermocks "github.com/NeuralTrust/TrustGate/pkg/infra/providers/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	openaiRequestBody  = `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`
	openaiResponseBody = `{"id":"x","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`

	anthropicRequestBody  = `{"model":"claude","max_tokens":10,"system":"be nice","messages":[{"role":"user","content":"hi"}]}`
	anthropicResponseBody = `{"id":"msg_1","type":"message","role":"assistant","model":"claude","content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn","usage":{"input_tokens":30,"output_tokens":15}}`
)

func apiKeyTarget(provider string) *registrydomain.Registry {
	return &registrydomain.Registry{
		ID:   ids.New[ids.RegistryKind](),
		Name: "t1",
		LLMTarget: &registrydomain.LLMTarget{
			Provider: provider,
			Auth:     registrydomain.NewAPIKeyAuth("secret"),
		},
	}
}

func TestProviderInvoke_SameFormatPassthrough(t *testing.T) {
	client := providermocks.NewClient(t)
	client.EXPECT().
		Completions(mock.Anything, mock.Anything, mock.Anything).
		Return([]byte(openaiResponseBody), nil).
		Once()

	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("openai").Return(client, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())

	req := &infracontext.RequestContext{Body: []byte(openaiRequestBody)}
	resp, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, []string{"openai"}, resp.Headers["X-Selected-Provider"])
	// Same wire format: response is returned without cross-format adaptation.
	assert.JSONEq(t, openaiResponseBody, string(resp.Body))
	assert.Equal(t, "openai", req.Provider)
	assert.Equal(t, "openai", req.SourceFormat)
	assert.Equal(t, "openai", req.TargetFormat)
}

func TestProviderInvoke_DecodesUsageOnFinish(t *testing.T) {
	client := providermocks.NewClient(t)
	client.EXPECT().
		Completions(mock.Anything, mock.Anything, mock.Anything).
		Return([]byte(openaiResponseBody), nil).
		Once()

	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("openai").Return(client, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())

	req := &infracontext.RequestContext{Body: []byte(openaiRequestBody)}
	resp, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), req)

	require.NoError(t, err)
	require.NotNil(t, resp.Usage, "non-streaming usage must be decoded on finish")
	assert.Equal(t, 1, resp.Usage.InputTokens)
	assert.Equal(t, 1, resp.Usage.OutputTokens)
	assert.Equal(t, 2, resp.Usage.TotalTokens)
}

func TestProviderInvoke_DecodesUsageOnFinishCrossFormat(t *testing.T) {
	client := providermocks.NewClient(t)
	client.EXPECT().
		Completions(mock.Anything, mock.Anything, mock.Anything).
		Return([]byte(anthropicResponseBody), nil).
		Once()

	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("anthropic").Return(client, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())

	req := &infracontext.RequestContext{Body: []byte(openaiRequestBody)}
	resp, err := inv.Invoke(context.Background(), apiKeyTarget("anthropic"), req)

	require.NoError(t, err)
	require.NotNil(t, resp.Usage)
	assert.Equal(t, 30, resp.Usage.InputTokens)
	assert.Equal(t, 15, resp.Usage.OutputTokens)
	assert.Equal(t, 45, resp.Usage.TotalTokens)
}

func TestProviderInvoke_CrossFormatAdapt(t *testing.T) {
	var sentBody []byte
	client := providermocks.NewClient(t)
	client.EXPECT().
		Completions(mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, _ *providers.Config, body []byte) ([]byte, error) {
			sentBody = body
			return []byte(anthropicResponseBody), nil
		}).
		Once()

	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("anthropic").Return(client, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())

	req := &infracontext.RequestContext{Body: []byte(openaiRequestBody)}
	resp, err := inv.Invoke(context.Background(), apiKeyTarget("anthropic"), req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "openai", req.SourceFormat)
	assert.Equal(t, "anthropic", req.TargetFormat)

	// Request was transformed openai -> anthropic before hitting the registry.
	var anthropicReq map[string]any
	require.NoError(t, json.Unmarshal(sentBody, &anthropicReq))
	assert.Contains(t, anthropicReq, "messages")
	assert.NotContains(t, string(sentBody), `"object"`)

	// Response was transformed anthropic -> openai for the client.
	var openaiResp map[string]any
	require.NoError(t, json.Unmarshal(resp.Body, &openaiResp))
	assert.Contains(t, openaiResp, "choices")
}

func TestProviderInvoke_BackendErrorPassthrough(t *testing.T) {
	errBody := []byte(`{"error":{"message":"rate limited"}}`)
	client := providermocks.NewClient(t)
	client.EXPECT().
		Completions(mock.Anything, mock.Anything, mock.Anything).
		Return(nil, registrydomain.NewBackendError(http.StatusTooManyRequests, errBody)).
		Once()

	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("openai").Return(client, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())

	req := &infracontext.RequestContext{Body: []byte(openaiRequestBody)}
	resp, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	assert.Equal(t, errBody, resp.Body)
	assert.Equal(t, []string{"application/json"}, resp.Headers["Content-Type"])
}

func TestProviderInvoke_SourceFormatFromPath(t *testing.T) {
	t.Run("empty source format defaults to openai", func(t *testing.T) {
		client := providermocks.NewClient(t)
		client.EXPECT().
			Completions(mock.Anything, mock.Anything, mock.Anything).
			Return([]byte(openaiResponseBody), nil).
			Once()
		locator := factorymocks.NewProviderLocator(t)
		locator.EXPECT().Get("openai").Return(client, nil).Once()

		inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
		req := &infracontext.RequestContext{Body: []byte(openaiRequestBody)}
		_, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), req)

		require.NoError(t, err)
		assert.Equal(t, "openai", req.SourceFormat)
	})

	t.Run("stamped anthropic source adapts request and response cross-format", func(t *testing.T) {
		client := providermocks.NewClient(t)
		client.EXPECT().
			Completions(mock.Anything, mock.Anything, mock.MatchedBy(func(body []byte) bool {
				return adapter.DetectFormat(body) == adapter.FormatOpenAI
			})).
			Return([]byte(openaiResponseBody), nil).
			Once()
		locator := factorymocks.NewProviderLocator(t)
		locator.EXPECT().Get("openai").Return(client, nil).Once()

		inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
		req := &infracontext.RequestContext{
			Body:         []byte(anthropicRequestBody),
			SourceFormat: string(adapter.FormatAnthropic),
		}
		resp, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), req)

		require.NoError(t, err)
		assert.Equal(t, "anthropic", req.SourceFormat, "stamped source format is preserved")
		var anthropicResp struct {
			Type string `json:"type"`
		}
		require.NoError(t, json.Unmarshal(resp.Body, &anthropicResp))
		assert.Equal(t, "message", anthropicResp.Type, "response adapted back to anthropic")
	})
}

func TestProviderInvoke_GeminiUsesDefaultModelAfterAutoRouting(t *testing.T) {
	const defaultModel = "gemini-2.5-flash"
	client := providermocks.NewClient(t)
	client.EXPECT().
		Completions(mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, config *providers.Config, body []byte) ([]byte, error) {
			model, err := adapter.ExtractModel(body)
			require.NoError(t, err)
			assert.Equal(t, defaultModel, model)
			assert.Equal(t, defaultModel, config.Model)
			assert.NotContains(t, string(body), `"auto"`)
			return []byte(`{"candidates":[]}`), nil
		}).
		Once()

	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("google").Return(client, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
	req := &infracontext.RequestContext{
		Body:          []byte(`{"contents":[]}`),
		SourceFormat:  string(adapter.FormatGemini),
		AllowedModels: []string{defaultModel},
		DefaultModel:  defaultModel,
	}
	resp, err := inv.Invoke(context.Background(), apiKeyTarget("google"), req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

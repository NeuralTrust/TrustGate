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
	reasoningToolsBody    = `{"model":"gpt-5.6-luna","max_tokens":32,"messages":[{"role":"user","content":"hi"}],"tools":[{"name":"Read","description":"Read a file","input_schema":{"type":"object","properties":{}}}]}`
	reasoningToolsError   = `{"error":{"message":"Function tools with reasoning_effort are not supported for gpt-5.6-luna in /v1/chat/completions. To use function tools, use /v1/responses or set reasoning_effort to 'none'."}}`
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

func TestProviderInvoke_AdvertisesServedRoute(t *testing.T) {
	const defaultModel = "gpt-4o-mini"
	client := providermocks.NewClient(t)
	client.EXPECT().
		Completions(mock.Anything, mock.Anything, mock.Anything).
		Return([]byte(openaiResponseBody), nil).
		Once()

	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("openai").Return(client, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())

	target := apiKeyTarget("openai")
	req := &infracontext.RequestContext{
		Body:          []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
		AllowedModels: []string{defaultModel},
		DefaultModel:  defaultModel,
	}
	resp, err := inv.Invoke(context.Background(), target, req)

	require.NoError(t, err)
	assert.Equal(t, []string{"openai"}, resp.Headers["X-Selected-Provider"])
	assert.Empty(t, resp.Headers["X-Selected-Registry"])
	assert.Equal(t, []string{defaultModel}, resp.Headers["X-Selected-Model"],
		"the header must carry the model the route resolved to, which the client never sent")
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
	assert.Equal(t, []string{"openai"}, resp.Headers["X-Selected-Provider"])
	assert.Equal(t, []string{"gpt-4"}, resp.Headers["X-Selected-Model"],
		"a failed attempt must still say which route was tried")
}

func TestProviderInvoke_RetriesReasoningToolsWithoutEffort(t *testing.T) {
	client := providermocks.NewClient(t)
	client.EXPECT().
		Completions(mock.Anything, mock.Anything, mock.MatchedBy(func(body []byte) bool {
			return !strings.Contains(string(body), `"reasoning_effort"`)
		})).
		Return(nil, registrydomain.NewBackendError(http.StatusBadRequest, []byte(reasoningToolsError))).
		Once()
	client.EXPECT().
		Completions(mock.Anything, mock.Anything, mock.MatchedBy(func(body []byte) bool {
			var request map[string]any
			if json.Unmarshal(body, &request) != nil {
				return false
			}
			return request["reasoning_effort"] == "none" &&
				request["max_completion_tokens"] == float64(32) && request["tools"] != nil
		})).
		Return([]byte(openaiResponseBody), nil).
		Once()

	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("openai").Return(client, nil).Once()
	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
	req := &infracontext.RequestContext{Body: []byte(reasoningToolsBody), SourceFormat: string(adapter.FormatAnthropic)}

	resp, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(resp.Body), `"type":"message"`)
}

func TestProviderInvoke_DoesNotOverrideExplicitReasoningEffort(t *testing.T) {
	body := `{"model":"gpt-5.6-luna","max_tokens":32,"reasoning_effort":"high","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"Read","parameters":{"type":"object"}}}]}`
	client := providermocks.NewClient(t)
	client.EXPECT().
		Completions(mock.Anything, mock.Anything, mock.Anything).
		Return(nil, registrydomain.NewBackendError(http.StatusBadRequest, []byte(reasoningToolsError))).
		Once()

	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("openai").Return(client, nil).Once()
	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
	req := &infracontext.RequestContext{Body: []byte(body)}

	resp, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.JSONEq(t, reasoningToolsError, string(resp.Body))
}

func TestProviderInvoke_DoesNotRetryReasoningToolsOutsideExactCase(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		status   int
		body     string
		options  map[string]any
	}{
		{name: "different status", provider: "openai", status: http.StatusUnprocessableEntity, body: reasoningToolsBody},
		{name: "compatible provider", provider: "openai_compatible", status: http.StatusBadRequest, body: reasoningToolsBody},
		{name: "missing tools", provider: "openai", status: http.StatusBadRequest, body: openaiRequestBody},
		{name: "empty tools", provider: "openai", status: http.StatusBadRequest, body: `{"model":"gpt-5.6-luna","messages":[],"tools":[]}`},
		{name: "null tools", provider: "openai", status: http.StatusBadRequest, body: `{"model":"gpt-5.6-luna","messages":[],"tools":null}`},
		{name: "responses target", provider: "openai", status: http.StatusBadRequest, body: reasoningToolsBody, options: map[string]any{"api": "responses"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := providermocks.NewClient(t)
			client.EXPECT().
				Completions(mock.Anything, mock.Anything, mock.Anything).
				Return(nil, registrydomain.NewBackendError(tt.status, []byte(reasoningToolsError))).
				Once()

			locator := factorymocks.NewProviderLocator(t)
			locator.EXPECT().Get(tt.provider).Return(client, nil).Once()
			inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
			target := apiKeyTarget(tt.provider)
			target.LLMTarget.ProviderOptions = tt.options
			req := &infracontext.RequestContext{Body: []byte(tt.body), SourceFormat: string(adapter.FormatAnthropic)}

			resp, err := inv.Invoke(context.Background(), target, req)

			require.NoError(t, err)
			assert.Equal(t, tt.status, resp.StatusCode)
			assert.JSONEq(t, reasoningToolsError, string(resp.Body))
		})
	}
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

func TestProviderInvoke_TokenParamKeyPerProvider(t *testing.T) {
	const openaiPassthroughBody = `{"model":"gpt-5","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}`

	tests := []struct {
		name         string
		provider     string
		sourceFormat string
		body         string
		stream       bool
		wantKey      string
		absentKey    string
	}{
		{name: "anthropic ingress to openai", provider: "openai", sourceFormat: "anthropic", body: anthropicRequestBody, wantKey: "max_completion_tokens", absentKey: "max_tokens"},
		{name: "anthropic ingress to azure", provider: "azure", sourceFormat: "anthropic", body: anthropicRequestBody, wantKey: "max_completion_tokens", absentKey: "max_tokens"},
		{name: "anthropic ingress to cerebras keeps max_tokens", provider: "cerebras", sourceFormat: "anthropic", body: anthropicRequestBody, wantKey: "max_tokens", absentKey: "max_completion_tokens"},
		{name: "openai passthrough to openai", provider: "openai", body: openaiPassthroughBody, wantKey: "max_completion_tokens", absentKey: "max_tokens"},
		{name: "openai passthrough to openai_compatible keeps max_tokens", provider: "openai_compatible", body: openaiPassthroughBody, wantKey: "max_tokens", absentKey: "max_completion_tokens"},
		{name: "anthropic ingress to openai stream", provider: "openai", sourceFormat: "anthropic", body: anthropicRequestBody, stream: true, wantKey: "max_completion_tokens", absentKey: "max_tokens"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var sent []byte
			client := providermocks.NewClient(t)
			if tc.stream {
				client.EXPECT().
					CompletionsStream(mock.Anything, mock.Anything, mock.Anything).
					RunAndReturn(func(_ context.Context, _ *providers.Config, body []byte) (iter.Seq2[[]byte, error], error) {
						sent = body
						return seqOf([]byte("data: [DONE]")), nil
					}).
					Once()
			} else {
				client.EXPECT().
					Completions(mock.Anything, mock.Anything, mock.Anything).
					RunAndReturn(func(_ context.Context, _ *providers.Config, body []byte) ([]byte, error) {
						sent = body
						return []byte(openaiResponseBody), nil
					}).
					Once()
			}
			inv := newStreamInvoker(t, tc.provider, client)
			req := &infracontext.RequestContext{Body: []byte(tc.body), SourceFormat: tc.sourceFormat}

			if tc.stream {
				resp, err := inv.InvokeStream(context.Background(), apiKeyTarget(tc.provider), req)
				require.NoError(t, err)
				collectStream(t, resp.Stream)
			} else {
				_, err := inv.Invoke(context.Background(), apiKeyTarget(tc.provider), req)
				require.NoError(t, err)
			}

			var got map[string]any
			require.NoError(t, json.Unmarshal(sent, &got))
			assert.EqualValues(t, 10, got[tc.wantKey])
			assert.NotContains(t, got, tc.absentKey)
			if tc.stream {
				assert.Equal(t, true, got["stream"])
			}
		})
	}
}

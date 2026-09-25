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
	"errors"
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

func TestProviderInvoke_CacheKeysFollowTheTargetProvider(t *testing.T) {
	const responsesBody = `{"model":"gpt-4o-mini","instructions":"terse","input":"hi","prompt_cache_key":"k","prompt_cache_retention":"24h"}`

	tests := []struct {
		provider string
		want     map[string]any
	}{
		{provider: "openai", want: map[string]any{"prompt_cache_key": "k", "prompt_cache_retention": "24h"}},
		{provider: "azure", want: map[string]any{"prompt_cache_key": "k", "prompt_cache_retention": "24h"}},
		{provider: "mistral", want: map[string]any{"prompt_cache_key": "k"}},
		{provider: "cerebras"},
		{provider: "openai_compatible"},
	}
	for _, tc := range tests {
		t.Run(tc.provider, func(t *testing.T) {
			var sent []byte
			client := providermocks.NewClient(t)
			client.EXPECT().
				Completions(mock.Anything, mock.Anything, mock.Anything).
				RunAndReturn(func(_ context.Context, _ *providers.Config, body []byte) ([]byte, error) {
					sent = body
					return []byte(openaiResponseBody), nil
				}).
				Once()
			inv := newStreamInvoker(t, tc.provider, client)
			req := &infracontext.RequestContext{Body: []byte(responsesBody), SourceFormat: string(adapter.FormatOpenAIResponses)}

			_, err := inv.Invoke(context.Background(), apiKeyTarget(tc.provider), req)
			require.NoError(t, err)

			var got map[string]any
			require.NoError(t, json.Unmarshal(sent, &got))
			cache := map[string]any{}
			for k, v := range got {
				if strings.HasPrefix(k, "prompt_cache") {
					cache[k] = v
				}
			}
			if tc.want == nil {
				assert.Empty(t, cache)
				return
			}
			assert.Equal(t, tc.want, cache)
		})
	}
}

func TestProviderInvoke_CacheProfileFollowsTheInjectedDefaultModel(t *testing.T) {
	const strippedBody = `{"max_tokens":10,"messages":[{"role":"user","content":[{"type":"text","text":"hi","cache_control":{"type":"ephemeral"}}]}]}`
	const responsesBody = `{"id":"r","object":"response","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hi"}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`

	tests := []struct {
		defaultModel   string
		wantBreakpoint bool
	}{
		{defaultModel: "gpt-5.6", wantBreakpoint: true},
		{defaultModel: "gpt-4o"},
	}
	for _, tc := range tests {
		t.Run(tc.defaultModel, func(t *testing.T) {
			var sent []byte
			client := providermocks.NewClient(t)
			client.EXPECT().
				Completions(mock.Anything, mock.Anything, mock.Anything).
				RunAndReturn(func(_ context.Context, _ *providers.Config, body []byte) ([]byte, error) {
					sent = body
					return []byte(responsesBody), nil
				}).
				Once()
			inv := newStreamInvoker(t, "openai", client)
			target := apiKeyTarget("openai")
			target.LLMTarget.ProviderOptions = map[string]any{"api": "responses"}
			req := &infracontext.RequestContext{
				Body:         []byte(strippedBody),
				SourceFormat: string(adapter.FormatAnthropic),
				DefaultModel: tc.defaultModel,
			}

			_, err := inv.Invoke(context.Background(), target, req)
			require.NoError(t, err)

			model, err := adapter.ExtractModel(sent)
			require.NoError(t, err)
			assert.Equal(t, tc.defaultModel, model)
			assert.Equal(t, tc.wantBreakpoint, strings.Contains(string(sent), "prompt_cache_breakpoint"), string(sent))
		})
	}
}

func TestProviderInvoke_BedrockBindingDefaultSpeaksConverse(t *testing.T) {
	const novaModel = "eu.amazon.nova-pro-v1:0"
	const novaResponseBody = `{"output":{"message":{"role":"assistant","content":[{"text":"hi"}]}},"stopReason":"end_turn","usage":{"inputTokens":1,"outputTokens":1,"totalTokens":2}}`

	var sent []byte
	client := providermocks.NewClient(t)
	client.EXPECT().
		Completions(mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ context.Context, _ *providers.Config, body []byte) {
			sent = body
		}).
		Return([]byte(novaResponseBody), nil).
		Once()

	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("bedrock").Return(client, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())

	req := &infracontext.RequestContext{
		Body:          []byte(`{"messages":[{"role":"user","content":"hi"}],"max_tokens":256}`),
		AllowedModels: []string{novaModel},
		DefaultModel:  novaModel,
	}
	_, err := inv.Invoke(context.Background(), apiKeyTarget("bedrock"), req)
	require.NoError(t, err)

	var body map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(sent, &body))
	assert.NotContains(t, body, "max_tokens",
		"Nova rejects the Claude-on-Bedrock max_tokens outright (RUN-1554)")
	assert.NotContains(t, body, "anthropic_version")
	assert.Contains(t, body, "inferenceConfig")
}

func TestProviderInvoke_UnsupportedImageIsInvalidPayload(t *testing.T) {
	t.Parallel()

	const (
		ftpImageBody   = `{"model":"gpt-4","messages":[{"role":"user","content":[{"type":"text","text":"hi"},{"type":"image_url","image_url":{"url":"ftp://example.com/private.png"}}]}]}`
		httpsImageBody = `{"model":"gpt-4","messages":[{"role":"user","content":[{"type":"text","text":"hi"},{"type":"image_url","image_url":{"url":"https://example.com/private.png"}}]}]}`
	)

	tests := []struct {
		name      string
		provider  string
		body      string
		stream    bool
		leakCheck string
	}{
		{name: "anthropic ftp url", provider: "anthropic", body: ftpImageBody, leakCheck: "private.png"},
		{name: "anthropic ftp url stream", provider: "anthropic", body: ftpImageBody, stream: true, leakCheck: "private.png"},
		{name: "bedrock https url", provider: "bedrock", body: httpsImageBody, leakCheck: "private.png"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			locator := factorymocks.NewProviderLocator(t)
			locator.EXPECT().Get(tc.provider).Return(providermocks.NewClient(t), nil).Maybe()
			inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
			req := &infracontext.RequestContext{Body: []byte(tc.body)}

			var err error
			if tc.stream {
				_, err = inv.InvokeStream(context.Background(), apiKeyTarget(tc.provider), req)
			} else {
				_, err = inv.Invoke(context.Background(), apiKeyTarget(tc.provider), req)
			}

			require.Error(t, err)
			assert.ErrorIs(t, err, appproxy.ErrInvalidRequestPayload)
			assert.ErrorIs(t, err, adapter.ErrUnsupportedContent)
			for _, leak := range []string{tc.leakCheck, tc.provider, "adapter"} {
				assert.NotContains(t, err.Error(), leak)
			}
		})
	}
}

func TestProviderInvoke_ClientDecodeErrorIsInvalidPayload(t *testing.T) {
	t.Parallel()

	const converseBody = `{"messages":[{"role":"user","content":[{"image":{"format":"png","source":{"bytes":"@@@"}}}]}]}`
	decodeErr := &adapter.RequestDecodeError{Format: adapter.FormatBedrock, Cause: errors.New("illegal base64 data at input byte 0")}
	networkErr := errors.New("dial tcp: timeout")

	tests := []struct {
		name        string
		clientErr   error
		stream      bool
		wantInvalid bool
	}{
		{name: "decode error buffered", clientErr: decodeErr, wantInvalid: true},
		{name: "decode error stream", clientErr: decodeErr, stream: true, wantInvalid: true},
		{name: "network error buffered stays retryable", clientErr: networkErr},
		{name: "network error stream stays retryable", clientErr: networkErr, stream: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client := providermocks.NewClient(t)
			if tc.stream {
				client.EXPECT().CompletionsStream(mock.Anything, mock.Anything, mock.Anything).Return(nil, tc.clientErr).Once()
			} else {
				client.EXPECT().Completions(mock.Anything, mock.Anything, mock.Anything).Return(nil, tc.clientErr).Once()
			}
			locator := factorymocks.NewProviderLocator(t)
			locator.EXPECT().Get("bedrock").Return(client, nil).Once()
			inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
			req := &infracontext.RequestContext{Body: []byte(converseBody), SourceFormat: string(adapter.FormatBedrock)}

			var err error
			if tc.stream {
				_, err = inv.InvokeStream(context.Background(), apiKeyTarget("bedrock"), req)
			} else {
				_, err = inv.Invoke(context.Background(), apiKeyTarget("bedrock"), req)
			}

			require.Error(t, err)
			if tc.wantInvalid {
				assert.ErrorIs(t, err, appproxy.ErrInvalidRequestPayload)
				assert.True(t, adapter.IsRequestDecodeError(err))
				return
			}
			assert.NotErrorIs(t, err, appproxy.ErrInvalidRequestPayload)
			assert.ErrorIs(t, err, networkErr)
		})
	}
}

func TestProviderInvoke_OpenAIChatPassesThroughToGroqAndOpenRouter(t *testing.T) {
	const body = `{"model":"m","seed":7,"prompt_cache_key":"k","session_id":"s-1",` +
		`"provider":{"order":["Anthropic"]},"models":["a","b"],"transforms":["middle-out"],"route":"fallback",` +
		`"messages":[{"role":"system","content":[{"type":"text","text":"sys","cache_control":{"type":"ephemeral"}}]},{"role":"user","content":"hi"}]}`
	const upstream = `{"id":"x","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],` +
		`"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2},"x_groq":{"id":"req_1"},"provider":"Anthropic"}`

	for _, name := range []string{"groq", "openrouter"} {
		t.Run(name, func(t *testing.T) {
			var sent []byte
			client := providermocks.NewClient(t)
			client.EXPECT().
				Completions(mock.Anything, mock.Anything, mock.Anything).
				RunAndReturn(func(_ context.Context, _ *providers.Config, b []byte) ([]byte, error) {
					sent = b
					return []byte(upstream), nil
				}).
				Once()
			inv := newStreamInvoker(t, name, client)
			req := &infracontext.RequestContext{Body: []byte(body), SourceFormat: string(adapter.FormatOpenAI)}

			resp, err := inv.Invoke(context.Background(), apiKeyTarget(name), req)
			require.NoError(t, err)

			assert.JSONEq(t, body, string(sent))
			assert.NotContains(t, string(resp.Body), "x_groq", "the response is still re-encoded")
			assert.NotContains(t, string(resp.Body), `"provider"`)
		})
	}
}

func TestProviderInvoke_GroqPassthroughKeepsGatewayMutations(t *testing.T) {
	const body = `{"seed":7,"prompt_cache_key":"k","tools":[{"function":{"name":"f","parameters":{"type":"object"}}}],"messages":[{"role":"user","content":"hi"}]}`

	var sent []byte
	client := providermocks.NewClient(t)
	client.EXPECT().
		CompletionsStream(mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, _ *providers.Config, b []byte) (iter.Seq2[[]byte, error], error) {
			sent = b
			return func(func([]byte, error) bool) {}, nil
		}).
		Once()
	inv := newStreamInvoker(t, "groq", client)
	req := &infracontext.RequestContext{Body: []byte(body), SourceFormat: string(adapter.FormatOpenAI), DefaultModel: "openai/gpt-oss-120b"}

	_, err := inv.InvokeStream(context.Background(), apiKeyTarget("groq"), req)
	require.NoError(t, err)

	var got map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(sent, &got))
	assert.JSONEq(t, `"openai/gpt-oss-120b"`, string(got["model"]), "EnforceModel still injects the default model")
	assert.JSONEq(t, `true`, string(got["stream"]))
	assert.JSONEq(t, `{"include_usage":true}`, string(got["stream_options"]))
	assert.JSONEq(t, `false`, string(got["parallel_tool_calls"]), "Groq normalisation still applies")
	assert.JSONEq(t, `7`, string(got["seed"]))
	assert.JSONEq(t, `"k"`, string(got["prompt_cache_key"]))
}

func TestProviderInvokeStream_ResponsesToAzureChatCarriesKeyAndRetention(t *testing.T) {
	const responsesBody = `{"model":"prod-chat","input":"hi","stream":true,"prompt_cache_key":"k1","prompt_cache_retention":"24h"}`

	var sent []byte
	client := providermocks.NewClient(t)
	client.EXPECT().
		CompletionsStream(mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, _ *providers.Config, b []byte) (iter.Seq2[[]byte, error], error) {
			sent = b
			return func(func([]byte, error) bool) {}, nil
		}).
		Once()
	inv := newStreamInvoker(t, "azure", client)
	req := &infracontext.RequestContext{Body: []byte(responsesBody), SourceFormat: string(adapter.FormatOpenAIResponses)}

	_, err := inv.InvokeStream(context.Background(), apiKeyTarget("azure"), req)
	require.NoError(t, err)

	var got map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(sent, &got))
	assert.Contains(t, got, "messages", "Azure is still sent as Chat")
	assert.JSONEq(t, `"k1"`, string(got["prompt_cache_key"]))
	assert.JSONEq(t, `"24h"`, string(got["prompt_cache_retention"]))
}

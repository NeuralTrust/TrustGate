package proxy_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	appproxy "github.com/NeuralTrust/AgentGateway/pkg/app/proxy"
	domainbackend "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
	factorymocks "github.com/NeuralTrust/AgentGateway/pkg/infra/providers/factory/mocks"
	providermocks "github.com/NeuralTrust/AgentGateway/pkg/infra/providers/mocks"
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

func apiKeyTarget(provider string) *domainbackend.Backend {
	return &domainbackend.Backend{
		ID:       ids.New[ids.BackendKind](),
		Name:     "t1",
		Provider: provider,
		Auth:     domainbackend.NewAPIKeyAuth("secret"),
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

	req := &infracontext.RequestContext{Context: context.Background(), Body: []byte(openaiRequestBody)}
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

	req := &infracontext.RequestContext{Context: context.Background(), Body: []byte(openaiRequestBody)}
	resp, err := inv.Invoke(context.Background(), apiKeyTarget("anthropic"), req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "openai", req.SourceFormat)
	assert.Equal(t, "anthropic", req.TargetFormat)

	// Request was transformed openai -> anthropic before hitting the backend.
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
		Return(nil, domainbackend.NewBackendError(http.StatusTooManyRequests, errBody)).
		Once()

	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("openai").Return(client, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())

	req := &infracontext.RequestContext{Context: context.Background(), Body: []byte(openaiRequestBody)}
	resp, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	assert.Equal(t, errBody, resp.Body)
	assert.Equal(t, []string{"application/json"}, resp.Headers["Content-Type"])
}

func TestProviderInvoke_SourceFormatHeaderTrustedVsAutoDetect(t *testing.T) {
	t.Run("auto-detect from body", func(t *testing.T) {
		client := providermocks.NewClient(t)
		client.EXPECT().
			Completions(mock.Anything, mock.Anything, mock.Anything).
			Return([]byte(openaiResponseBody), nil).
			Once()
		locator := factorymocks.NewProviderLocator(t)
		locator.EXPECT().Get("openai").Return(client, nil).Once()

		inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
		req := &infracontext.RequestContext{Context: context.Background(), Body: []byte(anthropicRequestBody)}
		_, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), req)

		require.NoError(t, err)
		assert.Equal(t, "anthropic", req.SourceFormat, "format auto-detected from body")
	})

	t.Run("trusted X-Provider hint", func(t *testing.T) {
		client := providermocks.NewClient(t)
		client.EXPECT().
			Completions(mock.Anything, mock.Anything, mock.Anything).
			Return([]byte(openaiResponseBody), nil).
			Once()
		locator := factorymocks.NewProviderLocator(t)
		locator.EXPECT().Get("openai").Return(client, nil).Once()

		inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
		// Body looks like anthropic, but the trusted hint wins.
		req := &infracontext.RequestContext{
			Context:      context.Background(),
			Body:         []byte(anthropicRequestBody),
			SourceFormat: "openai",
		}
		_, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), req)

		require.NoError(t, err)
		assert.Equal(t, "openai", req.SourceFormat, "trusted hint overrides auto-detection")
	})
}

package openai

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"iter"
	"net/http"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
)

// ChatCompletionsClient performs OpenAI-compatible chat completion HTTP calls
// (non-streaming) for a fixed provider pool key and endpoint URL.
type ChatCompletionsClient struct {
	ProviderKey string
	Pool        *providers.HTTPClientPool
}

func NewChatCompletionsClient(providerKey string, pool *providers.HTTPClientPool) *ChatCompletionsClient {
	if pool == nil {
		pool = providers.NewHTTPClientPool()
	}
	return &ChatCompletionsClient{ProviderKey: providerKey, Pool: pool}
}

func (c *ChatCompletionsClient) Completions(
	ctx context.Context,
	endpointURL string,
	config *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	return c.CompletionsWithHeaders(ctx, endpointURL, config, reqBody, nil)
}

// CompletionsWithHeaders is Completions with extra request headers merged in
// (applied after the default Content-Type/Authorization, so a caller may
// override them). Used by OpenAI-compatible backends that require custom headers.
func (c *ChatCompletionsClient) CompletionsWithHeaders(
	ctx context.Context,
	endpointURL string,
	config *providers.Config,
	reqBody []byte,
	extraHeaders map[string]string,
) ([]byte, error) {
	if config.Credentials.ApiKey == "" {
		return nil, fmt.Errorf("API key is required")
	}
	return c.post(ctx, endpointURL, config.Credentials.ApiKey, reqBody, extraHeaders)
}

func (c *ChatCompletionsClient) CompletionsStream(
	ctx context.Context,
	endpointURL string,
	config *providers.Config,
	reqBody []byte,
) (iter.Seq2[[]byte, error], error) {
	return c.CompletionsStreamWithHeaders(ctx, endpointURL, config, reqBody, nil)
}

// CompletionsStreamWithHeaders is CompletionsStream with extra request headers
// merged in (applied after the defaults). See CompletionsWithHeaders.
func (c *ChatCompletionsClient) CompletionsStreamWithHeaders(
	ctx context.Context,
	endpointURL string,
	config *providers.Config,
	reqBody []byte,
	extraHeaders map[string]string,
) (iter.Seq2[[]byte, error], error) {
	if config.Credentials.ApiKey == "" {
		return nil, fmt.Errorf("API key is required")
	}

	httpClient := c.Pool.GetStream(c.ProviderKey)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+config.Credentials.ApiKey)
	applyExtraHeaders(httpReq, extraHeaders)

	resp, err := httpClient.Do(httpReq) // #nosec G704 -- endpointURL is set by the provider wrapper, not user input
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	if registry.IsHTTPError(resp.StatusCode) {
		var preview bytes.Buffer
		_, _ = io.CopyN(&preview, resp.Body, 64*1024)
		providers.DrainBody(resp.Body)
		return nil, registry.NewBackendHTTPError(resp.StatusCode, preview.Bytes(), resp.Header)
	}

	return providers.StreamResponse(ctx, resp.Body), nil
}

func (c *ChatCompletionsClient) post(
	ctx context.Context,
	endpointURL, apiKey string,
	reqBody []byte,
	extraHeaders map[string]string,
) ([]byte, error) {
	httpClient := c.Pool.Get(c.ProviderKey, providers.DefaultHTTPTimeout)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	applyExtraHeaders(httpReq, extraHeaders)

	resp, err := httpClient.Do(httpReq) // #nosec G704 -- endpointURL is set by the provider wrapper, not user input
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var body bytes.Buffer
	if _, err := body.ReadFrom(resp.Body); err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if registry.IsHTTPError(resp.StatusCode) {
		return nil, registry.NewBackendHTTPError(resp.StatusCode, body.Bytes(), resp.Header)
	}

	return body.Bytes(), nil
}

func applyExtraHeaders(req *http.Request, headers map[string]string) {
	for k, v := range headers {
		if k == "" {
			continue
		}
		req.Header.Set(k, v)
	}
}

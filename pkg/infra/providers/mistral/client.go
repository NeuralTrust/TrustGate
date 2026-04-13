package mistral

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	domainUpstream "github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

const (
	chatCompletionsURL = "https://api.mistral.ai/v1/chat/completions"
)

type client struct {
	pool *providers.HTTPClientPool
}

// NewMistralClient returns a providers.Client that calls Mistral's chat completions API.
// See https://docs.mistral.ai/api (POST /v1/chat/completions).
func NewMistralClient() providers.Client {
	return &client{
		pool: providers.NewHTTPClientPool(),
	}
}

// Completions performs a non-streaming chat completion request to Mistral.
func (c *client) Completions(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	if config.Credentials.ApiKey == "" {
		return nil, fmt.Errorf("API key is required")
	}
	return c.rawPost(ctx, chatCompletionsURL, config.Credentials.ApiKey, reqBody)
}

// CompletionsStream performs a streaming chat completion request and forwards
// SSE lines to streamChan. Uses the same SSE format as OpenAI (data: {...}).
func (c *client) CompletionsStream(
	req *types.RequestContext,
	config *providers.Config,
	reqBody []byte,
	streamChan chan []byte,
	breakChan chan struct{},
) error {
	if config.Credentials.ApiKey == "" {
		return fmt.Errorf("API key is required")
	}

	httpClient := c.pool.Get(providers.ProviderMistral, providers.DefaultHTTPTimeout)
	httpReq, err := http.NewRequestWithContext(
		req.C.Context(), http.MethodPost, chatCompletionsURL, bytes.NewReader(reqBody),
	)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+config.Credentials.ApiKey)

	resp, err := httpClient.Do(httpReq) // #nosec G704 -- URL is compile-time constant
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer providers.DrainBody(resp.Body)

	if domainUpstream.IsHTTPError(resp.StatusCode) {
		var preview bytes.Buffer
		_, _ = io.CopyN(&preview, resp.Body, 64*1024)
		return domainUpstream.NewUpstreamError(resp.StatusCode, preview.Bytes())
	}
	close(breakChan)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return providers.StreamSSE(ctx, resp.Body, streamChan)
}

func (c *client) rawPost(
	ctx context.Context,
	url, apiKey string,
	reqBody []byte,
) ([]byte, error) {
	httpClient := c.pool.Get(providers.ProviderMistral, providers.DefaultHTTPTimeout)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := httpClient.Do(httpReq) // #nosec G704 -- URL is compile-time constant
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var body bytes.Buffer
	if _, err := body.ReadFrom(resp.Body); err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if domainUpstream.IsHTTPError(resp.StatusCode) {
		return nil, domainUpstream.NewUpstreamError(resp.StatusCode, body.Bytes())
	}

	return body.Bytes(), nil
}

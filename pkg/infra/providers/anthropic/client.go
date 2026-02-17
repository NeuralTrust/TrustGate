package anthropic

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	pkgTypes "github.com/NeuralTrust/TrustGate/pkg/types"
)

const (
	messagesURL      = "https://api.anthropic.com/v1/messages"
	anthropicVersion = "2023-06-01"
)

type client struct {
	pool *providers.HTTPClientPool
}

func NewAnthropicClient() providers.Client {
	return &client{
		pool: providers.NewHTTPClientPool(),
	}
}

// ---------------------------------------------------------------------------
// Completions (non-streaming)
// ---------------------------------------------------------------------------

func (c *client) Completions(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	if config.Credentials.ApiKey == "" {
		return nil, fmt.Errorf("API key is required")
	}

	return c.rawPost(ctx, config.Credentials.ApiKey, reqBody)
}

// ---------------------------------------------------------------------------
// CompletionsStream (SSE)
// ---------------------------------------------------------------------------

func (c *client) CompletionsStream(
	reqCtx *pkgTypes.RequestContext,
	config *providers.Config,
	reqBody []byte,
	streamChan chan []byte,
	breakChan chan struct{},
) error {
	if config.Credentials.ApiKey == "" {
		return fmt.Errorf("API key is required")
	}

	httpClient := c.pool.Get(providers.ProviderAnthropic, providers.DefaultHTTPTimeout)

	httpReq, err := http.NewRequestWithContext(
		reqCtx.C.Context(), http.MethodPost, messagesURL, bytes.NewReader(reqBody),
	)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}
	c.setHeaders(httpReq, config.Credentials.ApiKey)

	resp, err := httpClient.Do(httpReq) // #nosec G704 -- URL is a compile-time constant (messagesURL), not user-controlled
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer providers.DrainBody(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var preview bytes.Buffer
		_, _ = io.CopyN(&preview, resp.Body, 64*1024)
		return fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, preview.String())
	}

	// Do not forward upstream headers or use reqCtx.C from this goroutine:
	// Fiber's context is not safe to use from another goroutine.

	close(breakChan)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return providers.StreamSSE(ctx, resp.Body, streamChan)
}

// ---------------------------------------------------------------------------
// Raw HTTP POST
// ---------------------------------------------------------------------------

func (c *client) rawPost(ctx context.Context, apiKey string, reqBody []byte) ([]byte, error) {
	httpClient := c.pool.Get(providers.ProviderAnthropic, providers.DefaultHTTPTimeout)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, messagesURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	c.setHeaders(httpReq, apiKey)

	resp, err := httpClient.Do(httpReq) // #nosec G704 -- URL is a compile-time constant (messagesURL), not user-controlled
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var body bytes.Buffer
	if _, err := body.ReadFrom(resp.Body); err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, body.String())
	}

	return body.Bytes(), nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (c *client) setHeaders(req *http.Request, apiKey string) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", anthropicVersion)
}

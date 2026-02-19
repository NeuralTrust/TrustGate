package openai

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/mitchellh/mapstructure"
)

const (
	CompletionsAPI = "completions"
	ResponsesAPI   = "responses"
	completionsURL = "https://api.openai.com/v1/chat/completions"
	responsesURL   = "https://api.openai.com/v1/responses"
)

type openaiOptions struct {
	API string `json:"api"`
}

type client struct {
	pool *providers.HTTPClientPool
}

func NewOpenaiClient() providers.Client {
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

	options := c.parseOptions(config)

	var url string
	switch options.API {
	case ResponsesAPI:
		url = responsesURL
	default:
		url = completionsURL
	}

	return c.rawPost(ctx, url, config.Credentials.ApiKey, reqBody)
}

// ---------------------------------------------------------------------------
// CompletionsStream (SSE)
// ---------------------------------------------------------------------------

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

	options := c.parseOptions(config)

	var url string
	switch options.API {
	case ResponsesAPI:
		url = responsesURL
	default:
		url = completionsURL
	}

	httpClient := c.pool.Get(providers.ProviderOpenAI, providers.DefaultHTTPTimeout)
	httpReq, err := http.NewRequestWithContext(
		req.C.UserContext(), http.MethodPost, url, bytes.NewReader(reqBody),
	)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+config.Credentials.ApiKey)

	resp, err := httpClient.Do(httpReq) // #nosec G704 -- URL is a compile-time constant (completionsURL/responsesURL), not user-controlled
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer providers.DrainBody(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var preview bytes.Buffer
		_, _ = io.CopyN(&preview, resp.Body, 64*1024)
		return fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, preview.String())
	}
	close(breakChan)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return providers.StreamSSE(ctx, resp.Body, streamChan)
}

// ---------------------------------------------------------------------------
// Raw HTTP POST
// ---------------------------------------------------------------------------

func (c *client) rawPost(
	ctx context.Context,
	url, apiKey string,
	reqBody []byte,
) ([]byte, error) {
	httpClient := c.pool.Get(providers.ProviderOpenAI, providers.DefaultHTTPTimeout)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := httpClient.Do(httpReq) // #nosec G704 -- URL is a compile-time constant (completionsURL/responsesURL), not user-controlled
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

func (c *client) parseOptions(config *providers.Config) openaiOptions {
	var options openaiOptions
	if len(config.Options) > 0 {
		if err := mapstructure.Decode(config.Options, &options); err != nil {
			options = openaiOptions{API: CompletionsAPI}
		}
	} else {
		options = openaiOptions{API: CompletionsAPI}
	}
	return options
}

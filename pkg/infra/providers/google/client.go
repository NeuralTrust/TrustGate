package google

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"golang.org/x/sync/singleflight"
)

const (
	httpClientTimeout = 120
	geminiBaseURL     = "https://generativelanguage.googleapis.com/v1beta/models"
)

type client struct {
	httpClientPool *sync.Map
	sf             singleflight.Group
}

func NewGoogleClient() providers.Client {
	return &client{
		httpClientPool: &sync.Map{},
	}
}

//
// ---------------------------------------------------------------------------
// Completions (non-streaming)
// ---------------------------------------------------------------------------
//

func (c *client) Completions(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) ([]byte, error) {

	if config.Credentials.ApiKey == "" {
		return nil, fmt.Errorf("API key is required")
	}

	model, err := c.extractModel(reqBody)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/%s:generateContent", geminiBaseURL, model)

	return c.rawPost(ctx, url, config.Credentials.ApiKey, reqBody)
}

//
// ---------------------------------------------------------------------------
// CompletionsStream (SSE)
// ---------------------------------------------------------------------------
//

func (c *client) CompletionsStream(
	reqCtx *types.RequestContext,
	config *providers.Config,
	reqBody []byte,
	streamChan chan []byte,
	breakChan chan struct{},
) error {

	if config.Credentials.ApiKey == "" {
		return fmt.Errorf("API key is required")
	}

	model, err := c.extractModel(reqBody)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/%s:streamGenerateContent?alt=sse", geminiBaseURL, model)

	httpClient := c.getOrCreateHTTPClient()

	httpReq, err := http.NewRequestWithContext(
		reqCtx.C.Context(),
		http.MethodPost,
		url,
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-goog-api-key", config.Credentials.ApiKey)

	resp, err := httpClient.Do(httpReq) // #nosec G704 -- URL is built from compile-time constant (geminiBaseURL) with model name, not user-controlled
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return parseGeminiError(resp)
	}

	// Do not forward upstream headers or use reqCtx.C from this goroutine:
	// Fiber's context is not safe to use from another goroutine.

	close(breakChan)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return providers.StreamSSE(ctx, resp.Body, streamChan)
}

//
// ---------------------------------------------------------------------------
// Raw HTTP POST
// ---------------------------------------------------------------------------
//

func (c *client) rawPost(
	ctx context.Context,
	url string,
	apiKey string,
	reqBody []byte,
) ([]byte, error) {

	httpClient := c.getOrCreateHTTPClient()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-goog-api-key", apiKey)

	resp, err := httpClient.Do(httpReq) // #nosec G704 -- URL is built from compile-time constant (geminiBaseURL) with model name, not user-controlled
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseGeminiError(resp)
	}

	var body bytes.Buffer
	if _, err := body.ReadFrom(resp.Body); err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return body.Bytes(), nil
}

//
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
//

func (c *client) extractModel(reqBody []byte) (string, error) {

	model, err := adapter.ExtractModel(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to extract model: %w", err)
	}

	if model == "" {
		return "", fmt.Errorf("model is required for Gemini requests")
	}

	return model, nil
}

func parseGeminiError(resp *http.Response) error {

	var body bytes.Buffer
	_, _ = body.ReadFrom(resp.Body)

	var gemErr struct {
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Status  string `json:"status"`
		} `json:"error"`
	}

	if err := json.Unmarshal(body.Bytes(), &gemErr); err == nil && gemErr.Error.Message != "" {
		return fmt.Errorf("gemini error (%d - %s): %s",
			gemErr.Error.Code,
			gemErr.Error.Status,
			gemErr.Error.Message,
		)
	}

	return fmt.Errorf("gemini API error (%d): %s",
		resp.StatusCode,
		body.String(),
	)
}

func (c *client) getOrCreateHTTPClient() *http.Client {

	const clientKey = "default"

	if v, ok := c.httpClientPool.Load(clientKey); ok {
		if cl, ok := v.(*http.Client); ok {
			return cl
		}
	}

	v, err, _ := c.sf.Do(clientKey, func() (any, error) {

		if v2, ok := c.httpClientPool.Load(clientKey); ok {
			return v2, nil
		}

		httpClient := &http.Client{
			Timeout: httpClientTimeout * time.Second,
		}

		c.httpClientPool.Store(clientKey, httpClient)
		return httpClient, nil
	})

	if err != nil {
		return &http.Client{Timeout: httpClientTimeout * time.Second}
	}

	if cl, ok := v.(*http.Client); ok {
		return cl
	}

	return &http.Client{Timeout: httpClientTimeout * time.Second}
}

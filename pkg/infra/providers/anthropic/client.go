package anthropic

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	pkgTypes "github.com/NeuralTrust/TrustGate/pkg/types"
	"golang.org/x/sync/singleflight"
)

const (
	httpClientTimeout = 120
	messagesURL       = "https://api.anthropic.com/v1/messages"
	anthropicVersion  = "2023-06-01"
)

type client struct {
	httpClientPool *sync.Map
	sf             singleflight.Group
}

func NewAnthropicClient() providers.Client {
	return &client{
		httpClientPool: &sync.Map{},
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

	httpClient := c.getOrCreateHTTPClient()

	httpReq, err := http.NewRequestWithContext(
		reqCtx.C.Context(), http.MethodPost, messagesURL, bytes.NewReader(reqBody),
	)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}
	c.setHeaders(httpReq, config.Credentials.ApiKey)

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var preview bytes.Buffer
		_, _ = io.CopyN(&preview, resp.Body, 64*1024)
		return fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, preview.String())
	}

	// Forward response headers.
	for key, values := range resp.Header {
		for _, v := range values {
			reqCtx.C.Set(key, v)
		}
	}

	select {
	case <-reqCtx.C.Context().Done():
		return reqCtx.C.Context().Err()
	default:
	}
	close(breakChan)

	return c.streamSSE(reqCtx.C.Context(), resp.Body, streamChan)
}

// ---------------------------------------------------------------------------
// Raw HTTP POST
// ---------------------------------------------------------------------------

func (c *client) rawPost(ctx context.Context, apiKey string, reqBody []byte) ([]byte, error) {
	httpClient := c.getOrCreateHTTPClient()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, messagesURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	c.setHeaders(httpReq, apiKey)

	resp, err := httpClient.Do(httpReq)
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
// SSE streaming
// ---------------------------------------------------------------------------

func (c *client) streamSSE(ctx context.Context, r io.Reader, out chan []byte) error {
	sc := bufio.NewScanner(r)
	buf := make([]byte, 0, 512*1024)
	sc.Buffer(buf, 2*1024*1024)

	for sc.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := sc.Text()

		// Only process SSE data lines; skip event:, empty, and comment lines.
		if !strings.HasPrefix(line, "data:") {
			continue
		}

		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))

		if data == "" || data == "[DONE]" {
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- []byte(data):
		}
	}

	if err := sc.Err(); err != nil {
		if errors.Is(err, io.EOF) ||
			strings.Contains(strings.ToLower(err.Error()), "use of closed network connection") ||
			strings.Contains(strings.ToLower(err.Error()), "connection reset by peer") {
			return nil
		}
		return fmt.Errorf("sse scanner error: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (c *client) setHeaders(req *http.Request, apiKey string) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", anthropicVersion)
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

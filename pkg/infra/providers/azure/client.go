package azure

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	pkgTypes "github.com/NeuralTrust/TrustGate/pkg/types"
	"golang.org/x/sync/singleflight"
)

const (
	httpClientTimeout = 120
)

type client struct {
	httpClientPool *sync.Map
	sf             singleflight.Group
}

func NewAzureClient() providers.Client {
	return &client{
		httpClientPool: &sync.Map{},
	}
}

// ---------------------------------------------------------------------------
// Completions (non-streaming) — sends reqBody raw to Azure OpenAI endpoint
// ---------------------------------------------------------------------------

func (c *client) Completions(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	if config.Credentials.Azure == nil {
		return nil, fmt.Errorf("azure configuration is required")
	}
	if config.Credentials.Azure.Endpoint == "" {
		return nil, fmt.Errorf("azure endpoint is required")
	}

	model, err := adapter.ExtractModel(reqBody)
	if err != nil || model == "" {
		return nil, fmt.Errorf("model (deployment ID) is required")
	}

	token, err := c.getToken(ctx, config)
	if err != nil {
		return nil, err
	}

	url := c.buildURL(config, model)

	return c.rawPost(ctx, url, token, config.Credentials.Azure.UseIdentity, reqBody)
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
	if config.Credentials.Azure == nil {
		return fmt.Errorf("azure configuration is required")
	}
	if config.Credentials.Azure.Endpoint == "" {
		return fmt.Errorf("azure endpoint is required")
	}

	model, err := adapter.ExtractModel(reqBody)
	if err != nil || model == "" {
		return fmt.Errorf("model (deployment ID) is required")
	}

	token, err := c.getToken(reqCtx.C.Context(), config)
	if err != nil {
		return err
	}

	url := c.buildURL(config, model)

	httpClient := c.getOrCreateHTTPClient()
	httpReq, err := http.NewRequestWithContext(
		reqCtx.C.Context(), http.MethodPost, url, bytes.NewReader(reqBody),
	)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	c.applyAuthHeader(httpReq, config.Credentials.Azure.UseIdentity, token)

	resp, err := httpClient.Do(httpReq) // #nosec G704 -- URL is built from admin-configured Azure endpoint, not user-controlled
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var preview bytes.Buffer
		_, _ = io.CopyN(&preview, resp.Body, 64*1024)
		return fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, preview.String())
	}

	// Do not forward upstream headers here: CompletionsStream runs in a goroutine and
	// Fiber's Ctx is not safe to use from another goroutine. The HTTP handler already
	// sets stream headers (Content-Type: text/event-stream, etc.) before starting the stream.
	// Do not use reqCtx.C.Context() from this goroutine: Fiber's context can panic on Done().

	close(breakChan)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return providers.StreamSSE(ctx, resp.Body, streamChan)
}

// ---------------------------------------------------------------------------
// Raw HTTP POST
// ---------------------------------------------------------------------------

func (c *client) rawPost(ctx context.Context, url, token string, useIdentity bool, reqBody []byte) ([]byte, error) {
	httpClient := c.getOrCreateHTTPClient()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	c.applyAuthHeader(httpReq, useIdentity, token)

	resp, err := httpClient.Do(httpReq) // #nosec G704 -- URL is built from admin-configured Azure endpoint, not user-controlled
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

func (c *client) applyAuthHeader(req *http.Request, useIdentity bool, token string) {
	if useIdentity {
		req.Header.Set("Authorization", "Bearer "+token)
	} else {
		req.Header.Set("api-key", token)
	}
}

func (c *client) getToken(ctx context.Context, config *providers.Config) (string, error) {
	if config.Credentials.Azure.UseIdentity {
		token, err := getAzureADToken(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to get Azure AD token: %w", err)
		}
		return token, nil
	}
	if config.Credentials.ApiKey == "" {
		return "", fmt.Errorf("API key is required when not using Azure identity")
	}
	return config.Credentials.ApiKey, nil
}

func (c *client) buildURL(config *providers.Config, model string) string {
	apiVersion := "2024-05-01-preview"
	if config.Credentials.Azure.ApiVersion != "" {
		apiVersion = config.Credentials.Azure.ApiVersion
	}
	return fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=%s",
		config.Credentials.Azure.Endpoint, model, apiVersion)
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

func getAzureADToken(ctx context.Context) (string, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return "", fmt.Errorf("failed to create credential: %w", err)
	}
	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://cognitiveservices.azure.com/.default"},
	})
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}
	return token.Token, nil
}

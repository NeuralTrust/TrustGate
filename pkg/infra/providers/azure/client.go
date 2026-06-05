package azure

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"iter"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
)

const defaultAPIVersion = "2024-05-01-preview"

type client struct {
	pool *providers.HTTPClientPool
}

func NewAzureClient() providers.Client {
	return &client{
		pool: providers.NewHTTPClientPool(),
	}
}

// Completions sends reqBody raw to the Azure OpenAI endpoint (non-streaming).
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

func (c *client) rawPost(ctx context.Context, url, token string, useIdentity bool, reqBody []byte) ([]byte, error) {
	httpClient := c.pool.Get(providers.ProviderAzure, providers.DefaultHTTPTimeout)

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

	if registry.IsHTTPError(resp.StatusCode) {
		return nil, registry.NewBackendHTTPError(resp.StatusCode, body.Bytes(), resp.Header)
	}

	return body.Bytes(), nil
}

func (c *client) CompletionsStream(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) (iter.Seq2[[]byte, error], error) {
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

	httpClient := c.pool.GetStream(providers.ProviderAzure)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	c.applyAuthHeader(httpReq, config.Credentials.Azure.UseIdentity, token)

	resp, err := httpClient.Do(httpReq) // #nosec G704 -- URL is built from admin-configured Azure endpoint, not user-controlled
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
	apiVersion := defaultAPIVersion
	if config.Credentials.Azure.ApiVersion != "" {
		apiVersion = config.Credentials.Azure.ApiVersion
	}
	return fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=%s",
		config.Credentials.Azure.Endpoint, model, apiVersion)
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

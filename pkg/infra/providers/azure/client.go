package azure

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
)

const (
	defaultAPIVersion = "2024-10-21"
	azureTokenScope   = "https://ai.azure.com/.default" // #nosec G101 -- OAuth audience scope, not a credential value
)

type client struct {
	pool        *providers.HTTPClientPool
	tokenSource azureTokenSource
}

func NewAzureClient() providers.Client {
	return &client{
		pool:        providers.NewHTTPClientPool(),
		tokenSource: getAzureBearerToken,
	}
}

type azureTokenSource func(context.Context, *providers.Azure) (string, error)

type authHeader struct {
	name  string
	value string
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

	auth, err := c.resolveAuth(ctx, config)
	if err != nil {
		return nil, err
	}

	url := c.buildURL(config, model)

	return c.rawPost(ctx, url, auth, reqBody)
}

func (c *client) rawPost(ctx context.Context, url string, auth authHeader, reqBody []byte) ([]byte, error) {
	httpClient := c.pool.Get(providers.ProviderAzure, providers.DefaultHTTPTimeout)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	auth.apply(httpReq)

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

	auth, err := c.resolveAuth(ctx, config)
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
	auth.apply(httpReq)

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

func (h authHeader) apply(req *http.Request) {
	req.Header.Set(h.name, h.value)
}

func (c *client) resolveAuth(ctx context.Context, config *providers.Config) (authHeader, error) {
	az := config.Credentials.Azure
	switch azureAuthMode(az) {
	case providers.AzureAuthModeAPIKey:
		if config.Credentials.ApiKey == "" {
			return authHeader{}, fmt.Errorf("API key is required for Azure API key authentication")
		}
		return authHeader{name: "api-key", value: config.Credentials.ApiKey}, nil
	case providers.AzureAuthModeServicePrincipal, providers.AzureAuthModeDefaultAzureCredential:
		token, err := c.bearerToken(ctx, az)
		if err != nil {
			slog.WarnContext(ctx, "azure bearer token acquisition failed",
				slog.String("auth_mode", string(azureAuthMode(az))),
				slog.String("error", err.Error()),
			)
			return authHeader{}, err
		}
		return authHeader{name: "Authorization", value: "Bearer " + token}, nil
	default:
		return authHeader{}, fmt.Errorf("unsupported Azure auth mode %q", az.AuthMode)
	}
}

func (c *client) bearerToken(ctx context.Context, az *providers.Azure) (string, error) {
	tokenSource := c.tokenSource
	if tokenSource == nil {
		tokenSource = getAzureBearerToken
	}
	token, err := tokenSource(ctx, az)
	if err != nil {
		return "", fmt.Errorf("%w: failed to get Azure bearer token: %w", registry.ErrCredentialAcquisition, err)
	}
	return token, nil
}

func azureAuthMode(az *providers.Azure) providers.AzureAuthMode {
	if az.AuthMode != "" {
		return az.AuthMode
	}
	if az.UseIdentity {
		return providers.AzureAuthModeDefaultAzureCredential
	}
	if az.TenantID != "" || az.ClientID != "" || az.ClientSecret != "" {
		return providers.AzureAuthModeServicePrincipal
	}
	return providers.AzureAuthModeAPIKey
}

func (c *client) buildURL(config *providers.Config, model string) string {
	originalEndpoint := config.Credentials.Azure.Endpoint
	endpoint := azureRESTEndpoint(originalEndpoint)
	apiVersion := defaultAPIVersion
	if config.Credentials.Azure.ApiVersion != "" {
		apiVersion = config.Credentials.Azure.ApiVersion
	}
	finalURL := fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=%s",
		endpoint, model, apiVersion)
	return finalURL
}

func azureRESTEndpoint(endpoint string) string {
	if idx := strings.Index(endpoint, "/api/projects/"); idx >= 0 {
		return endpoint[:idx]
	}
	return strings.TrimRight(endpoint, "/")
}

func getAzureBearerToken(ctx context.Context, az *providers.Azure) (string, error) {
	cred, err := azureCredential(az)
	if err != nil {
		return "", err
	}
	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{azureTokenScope},
	})
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}
	return token.Token, nil
}

func azureCredential(az *providers.Azure) (azcore.TokenCredential, error) {
	switch azureAuthMode(az) {
	case providers.AzureAuthModeServicePrincipal:
		if az.TenantID == "" || az.ClientID == "" || az.ClientSecret == "" {
			return nil, fmt.Errorf("azure service principal requires tenant_id, client_id, and client_secret")
		}
		cred, err := azidentity.NewClientSecretCredential(az.TenantID, az.ClientID, az.ClientSecret, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create Azure client secret credential: %w", err)
		}
		return cred, nil
	case providers.AzureAuthModeDefaultAzureCredential:
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create Azure default credential: %w", err)
		}
		return cred, nil
	default:
		return nil, fmt.Errorf("unsupported Azure bearer auth mode %q", az.AuthMode)
	}
}

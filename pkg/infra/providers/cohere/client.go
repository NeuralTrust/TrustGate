// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cohere

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"iter"
	"net/http"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

type client struct {
	pool *providers.HTTPClientPool
}

func NewCohereClient() providers.Client {
	return &client{
		pool: providers.NewHTTPClientPool(),
	}
}

func (c *client) Completions(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	if config.Credentials.ApiKey == "" {
		return nil, fmt.Errorf("API key is required")
	}
	url, err := chatURL(config.Options)
	if err != nil {
		return nil, err
	}
	return c.rawPost(ctx, url, config.Credentials.ApiKey, reqBody)
}

func (c *client) CompletionsStream(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) (iter.Seq2[[]byte, error], error) {
	if config.Credentials.ApiKey == "" {
		return nil, fmt.Errorf("API key is required")
	}
	url, err := chatURL(config.Options)
	if err != nil {
		return nil, err
	}

	httpClient := c.pool.GetStream(providers.ProviderCohere)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	setHeaders(httpReq, config.Credentials.ApiKey)

	resp, err := httpClient.Do(httpReq) // #nosec G704 -- URL from provider options or compile-time default host
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

func (c *client) Embeddings(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	if config.Credentials.ApiKey == "" {
		return nil, fmt.Errorf("API key is required")
	}
	url, err := embedURL(config.Options)
	if err != nil {
		return nil, err
	}
	return c.rawPost(ctx, url, config.Credentials.ApiKey, reqBody)
}

func (c *client) Rerank(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	if config.Credentials.ApiKey == "" {
		return nil, fmt.Errorf("API key is required")
	}
	url, err := rerankURL(config.Options)
	if err != nil {
		return nil, err
	}
	return c.rawPost(ctx, url, config.Credentials.ApiKey, reqBody)
}

func (c *client) rawPost(
	ctx context.Context,
	url, apiKey string,
	reqBody []byte,
) ([]byte, error) {
	httpClient := c.pool.Get(providers.ProviderCohere, providers.DefaultHTTPTimeout)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	setHeaders(httpReq, apiKey)

	resp, err := httpClient.Do(httpReq) // #nosec G704 -- URL from provider options or compile-time default host
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

func setHeaders(req *http.Request, apiKey string) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
}

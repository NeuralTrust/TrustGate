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

package google

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"iter"
	"net/http"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const (
	geminiBaseURL = "https://generativelanguage.googleapis.com/v1beta/models"
)

type client struct {
	pool *providers.HTTPClientPool
}

func NewGoogleClient() providers.Client {
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

	model, err := c.extractModel(reqBody)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/%s:generateContent", geminiBaseURL, model)

	return c.rawPost(ctx, url, config.Credentials.ApiKey, reqBody)
}

func (c *client) rawPost(
	ctx context.Context,
	url string,
	apiKey string,
	reqBody []byte,
) ([]byte, error) {
	httpClient := c.pool.Get(providers.ProviderGoogle, providers.DefaultHTTPTimeout)

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

	if registry.IsHTTPError(resp.StatusCode) {
		return nil, readBackendError(resp)
	}

	var body bytes.Buffer
	if _, err := body.ReadFrom(resp.Body); err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return body.Bytes(), nil
}

func (c *client) CompletionsStream(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) (iter.Seq2[[]byte, error], error) {
	if config.Credentials.ApiKey == "" {
		return nil, fmt.Errorf("API key is required")
	}

	model, err := c.extractModel(reqBody)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/%s:streamGenerateContent?alt=sse", geminiBaseURL, model)

	httpClient := c.pool.GetStream(providers.ProviderGoogle)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-goog-api-key", config.Credentials.ApiKey)

	resp, err := httpClient.Do(httpReq) // #nosec G704 -- URL is built from compile-time constant (geminiBaseURL) with model name, not user-controlled
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

func readBackendError(resp *http.Response) *registry.BackendError {
	var preview bytes.Buffer
	_, _ = io.CopyN(&preview, resp.Body, 64*1024)
	providers.DrainBody(resp.Body)
	return registry.NewBackendHTTPError(resp.StatusCode, preview.Bytes(), resp.Header)
}

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

package vertex

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"iter"
	"net/http"
	"strings"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
)

const (
	defaultAction = "generateContent"
	streamAction  = "streamGenerateContent"

	optKeyAction = "action"
)

type client struct {
	pool *providers.HTTPClientPool
}

func NewVertexClient() providers.Client {
	return &client{pool: providers.NewHTTPClientPool()}
}

func (c *client) Completions(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	url, err := c.buildRequestURL(config, reqBody, false)
	if err != nil {
		return nil, err
	}

	req, err := c.newHTTPRequest(ctx, url, config.Credentials.ApiKey, reqBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("vertex request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if registry.IsHTTPError(resp.StatusCode) {
		return nil, readBackendError(resp)
	}

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, fmt.Errorf("reading vertex response: %w", err)
	}
	return buf.Bytes(), nil
}

func (c *client) CompletionsStream(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) (iter.Seq2[[]byte, error], error) {
	url, err := c.buildRequestURL(config, reqBody, true)
	if err != nil {
		return nil, err
	}

	req, err := c.newHTTPRequest(ctx, url, config.Credentials.ApiKey, reqBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.pool.GetStream(providers.ProviderVertex).Do(req)
	if err != nil {
		return nil, fmt.Errorf("vertex request failed: %w", err)
	}
	if registry.IsHTTPError(resp.StatusCode) {
		var preview bytes.Buffer
		_, _ = io.CopyN(&preview, resp.Body, 64*1024)
		providers.DrainBody(resp.Body)
		return nil, registry.NewBackendHTTPError(resp.StatusCode, preview.Bytes(), resp.Header)
	}

	return providers.StreamResponse(ctx, resp.Body), nil
}

func (c *client) buildRequestURL(config *providers.Config, reqBody []byte, stream bool) (string, error) {
	if config.Credentials.ApiKey == "" {
		return "", fmt.Errorf("bearer token (api_key) is required for Vertex AI")
	}

	opts, err := providers.DecodeVertexOptions(config.Options)
	if err != nil {
		return "", err
	}

	model, err := resolveModel(reqBody, config)
	if err != nil {
		return "", err
	}

	action := resolveAction(config.Options, stream)
	return buildVertexURL(opts, model, action), nil
}

func (c *client) newHTTPRequest(ctx context.Context, url, token string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating vertex request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return req, nil
}

func (c *client) httpClient() *http.Client {
	return c.pool.Get(providers.ProviderVertex, providers.DefaultHTTPTimeout)
}

func resolveModel(reqBody []byte, config *providers.Config) (string, error) {
	model := config.Model
	if model == "" {
		model = config.DefaultModel
	}
	if model == "" {
		model, _ = adapter.ExtractModel(reqBody)
	}
	if model == "" {
		return "", fmt.Errorf("model is required for Vertex AI requests")
	}

	if len(config.AllowedModels) > 0 && !isModelAllowed(model, config.AllowedModels) {
		return "", fmt.Errorf("model %q is not in the allowed models list", model)
	}

	return model, nil
}

func resolveAction(options map[string]any, stream bool) string {
	action := defaultAction
	if a, ok := options[optKeyAction]; ok {
		if s, ok := a.(string); ok && s != "" {
			action = s
		}
	}
	if stream && action == defaultAction {
		action = streamAction
	}
	return action
}

func isModelAllowed(model string, allowed []string) bool {
	for _, m := range allowed {
		if m == model {
			return true
		}
	}
	return false
}

func buildVertexURL(opts providers.VertexOptions, model, action string) string {
	var sb strings.Builder
	sb.WriteString("https://")
	sb.WriteString(opts.Location)
	sb.WriteString("-aiplatform.googleapis.com/")
	sb.WriteString(opts.Version)
	sb.WriteString("/projects/")
	sb.WriteString(opts.Project)
	sb.WriteString("/locations/")
	sb.WriteString(opts.Location)
	sb.WriteString("/publishers/google/models/")
	sb.WriteString(model)
	sb.WriteByte(':')
	sb.WriteString(action)

	if action == streamAction {
		sb.WriteString("?alt=sse")
	}

	return sb.String()
}

func readBackendError(resp *http.Response) *registry.BackendError {
	var preview bytes.Buffer
	_, _ = io.CopyN(&preview, resp.Body, 64*1024)
	providers.DrainBody(resp.Body)
	return registry.NewBackendHTTPError(resp.StatusCode, preview.Bytes(), resp.Header)
}

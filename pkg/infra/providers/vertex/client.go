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
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net/http"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const (
	defaultAction    = "generateContent"
	streamAction     = "streamGenerateContent"
	embedAction      = "embedContent"
	batchEmbedAction = "batchEmbedContents"

	optKeyAction = "action"

	globalLocation = "global"
)

var (
	_ providers.Client           = (*client)(nil)
	_ providers.EmbeddingsClient = (*client)(nil)
)

type client struct {
	pool        *providers.HTTPClientPool
	tokenSource tokenSource
}

func NewVertexClient() providers.Client {
	return &client{
		pool:        providers.NewHTTPClientPool(),
		tokenSource: defaultTokenCache.token,
	}
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

	token, err := c.bearerToken(ctx, config)
	if err != nil {
		return nil, err
	}

	req, err := c.newHTTPRequest(ctx, url, token, reqBody)
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

	token, err := c.bearerToken(ctx, config)
	if err != nil {
		return nil, err
	}

	req, err := c.newHTTPRequest(ctx, url, token, reqBody)
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

func (c *client) Embeddings(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	url, err := c.buildEmbeddingsURL(config, reqBody)
	if err != nil {
		return nil, err
	}

	token, err := c.bearerToken(ctx, config)
	if err != nil {
		return nil, err
	}

	req, err := c.newHTTPRequest(ctx, url, token, reqBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("vertex embeddings request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if registry.IsHTTPError(resp.StatusCode) {
		return nil, readBackendError(resp)
	}

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, fmt.Errorf("reading vertex embeddings response: %w", err)
	}
	return buf.Bytes(), nil
}

func (c *client) buildEmbeddingsURL(config *providers.Config, reqBody []byte) (string, error) {
	opts, err := providers.DecodeVertexOptions(config.Options)
	if err != nil {
		return "", err
	}

	model, err := resolveModel(reqBody, config)
	if err != nil {
		return "", err
	}

	action := embeddingsAction(reqBody)
	if opts.BaseURL != "" {
		return strings.TrimRight(opts.BaseURL, "/") + "/" + model + ":" + action, nil
	}
	return buildVertexURL(opts, model, action), nil
}

func embeddingsAction(reqBody []byte) string {
	var probe struct {
		Requests json.RawMessage `json:"requests"`
	}
	if json.Unmarshal(reqBody, &probe) == nil && len(probe.Requests) > 0 {
		return batchEmbedAction
	}
	return embedAction
}

func (c *client) bearerToken(ctx context.Context, config *providers.Config) (string, error) {
	if config.Credentials.GCP != nil {
		source := c.tokenSource
		if source == nil {
			source = defaultTokenCache.token
		}
		token, err := source(ctx, config.Credentials.GCP)
		if err != nil {
			return "", fmt.Errorf("%w: failed to get Vertex AI bearer token: %w", registry.ErrCredentialAcquisition, err)
		}
		return token, nil
	}

	if config.Credentials.ApiKey == "" {
		return "", fmt.Errorf(
			"%w: vertex requires either gcp service account credentials or a bearer token (api_key)",
			registry.ErrCredentialAcquisition,
		)
	}
	return config.Credentials.ApiKey, nil
}

func (c *client) buildRequestURL(config *providers.Config, reqBody []byte, stream bool) (string, error) {
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

// The global endpoint is the only location reached through an unprefixed host.
func vertexHost(location string) string {
	if location == globalLocation {
		return "aiplatform.googleapis.com"
	}
	return location + "-aiplatform.googleapis.com"
}

func buildVertexURL(opts providers.VertexOptions, model, action string) string {
	var sb strings.Builder
	sb.WriteString("https://")
	sb.WriteString(vertexHost(opts.Location))
	sb.WriteByte('/')
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

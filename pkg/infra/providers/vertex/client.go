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
	defaultAPIVer = "v1"

	OptKeyProject  = "project"
	OptKeyLocation = "location"
	OptKeyVersion  = "version"
	optKeyAction   = "action"
)

type vertexOptions struct {
	Project  string
	Location string
	Version  string
}

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

	opts, err := parseOptions(config.Options)
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

func parseOptions(opts map[string]any) (vertexOptions, error) {
	vo := vertexOptions{Version: defaultAPIVer}

	vo.Project = stringOpt(opts, OptKeyProject)
	if vo.Project == "" {
		return vo, fmt.Errorf("vertex provider_options.%s is required", OptKeyProject)
	}

	vo.Location = stringOpt(opts, OptKeyLocation)
	if vo.Location == "" {
		return vo, fmt.Errorf("vertex provider_options.%s is required", OptKeyLocation)
	}

	if v := stringOpt(opts, OptKeyVersion); v != "" {
		vo.Version = v
	}

	return vo, nil
}

func stringOpt(opts map[string]any, key string) string {
	if v, ok := opts[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func buildVertexURL(opts vertexOptions, model, action string) string {
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

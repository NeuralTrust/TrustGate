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

// Package watsonx is the native IBM watsonx.ai provider. The gateway speaks
// OpenAI Chat Completions to it; the client translates each call to the
// watsonx text/chat API and authenticates with an IAM bearer token it mints
// from the registry's IBM Cloud API key and refreshes before it expires.
package watsonx

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"iter"
	"net/http"
	"net/url"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

const (
	chatPath       = "/ml/v1/text/chat"
	chatStreamPath = "/ml/v1/text/chat_stream"
	maxErrorBody   = 64 << 10
)

var (
	_ providers.Client           = (*client)(nil)
	_ providers.ConnectionTester = (*client)(nil)
	_ providers.ModelLister      = (*client)(nil)
)

var defaultTokens = newTokenCache(iamTokenURL)

type client struct {
	pool   *providers.HTTPClientPool
	tokens *tokenCache
}

// NewWatsonxClient returns the IBM watsonx.ai client.
func NewWatsonxClient() providers.Client {
	return &client{
		pool:   providers.NewHTTPClientPool(),
		tokens: defaultTokens,
	}
}

func (c *client) Completions(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	endpoint, body, err := c.prepare(config, reqBody, false)
	if err != nil {
		return nil, err
	}

	resp, err := c.send(ctx, config, endpoint, body, c.pool.Get(providers.ProviderWatsonx, providers.DefaultHTTPTimeout))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, fmt.Errorf("reading watsonx response: %w", err)
	}
	if registry.IsHTTPError(resp.StatusCode) {
		return nil, registry.NewBackendHTTPError(resp.StatusCode, openAIErrorBody(resp.StatusCode, buf.Bytes()), resp.Header)
	}
	return translateResponse(buf.Bytes())
}

func (c *client) CompletionsStream(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) (iter.Seq2[[]byte, error], error) {
	endpoint, body, err := c.prepare(config, reqBody, true)
	if err != nil {
		return nil, err
	}

	resp, err := c.send(ctx, config, endpoint, body, c.pool.GetStream(providers.ProviderWatsonx))
	if err != nil {
		return nil, err
	}
	if registry.IsHTTPError(resp.StatusCode) {
		var preview bytes.Buffer
		_, _ = io.CopyN(&preview, resp.Body, maxErrorBody)
		providers.DrainBody(resp.Body)
		return nil, registry.NewBackendHTTPError(resp.StatusCode, openAIErrorBody(resp.StatusCode, preview.Bytes()), resp.Header)
	}

	return translateStream(providers.StreamResponse(ctx, resp.Body)), nil
}

func (c *client) prepare(config *providers.Config, reqBody []byte, stream bool) (string, []byte, error) {
	opts, err := providers.DecodeWatsonxOptions(config.Options)
	if err != nil {
		return "", nil, err
	}
	body, err := buildChatRequest(reqBody, modelChoice{
		configured: strings.TrimSpace(config.Model),
		fallback:   strings.TrimSpace(config.DefaultModel),
	}, opts.ProjectID)
	if err != nil {
		return "", nil, err
	}
	path := chatPath
	if stream {
		path = chatStreamPath
	}
	return endpointURL(opts, path, nil), body, nil
}

func endpointURL(opts providers.WatsonxOptions, path string, extra url.Values) string {
	query := url.Values{}
	for k, v := range extra {
		query[k] = v
	}
	query.Set("version", opts.APIVersion)
	return opts.Endpoint() + path + "?" + query.Encode()
}

// send makes the call with the cached IAM token. A 401 means IBM no longer
// honours that token (revoked, or expired early), so it is dropped and the
// call is made once more with a freshly minted one.
func (c *client) send(
	ctx context.Context,
	config *providers.Config,
	endpoint string,
	body []byte,
	httpClient *http.Client,
) (*http.Response, error) {
	apiKey := config.Credentials.ApiKey
	for attempt := 0; ; attempt++ {
		token, err := c.tokens.token(ctx, apiKey)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("creating watsonx request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := httpClient.Do(req) // #nosec G704 -- endpoint is the registry's watsonx region or validated base_url
		if err != nil {
			return nil, fmt.Errorf("watsonx request failed: %w", err)
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			providers.DrainBody(resp.Body)
			c.tokens.invalidate(apiKey, token)
			continue
		}
		return resp, nil
	}
}

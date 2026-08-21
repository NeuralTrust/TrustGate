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

package oracle

import (
	"context"
	"iter"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/openai"
)

const chatCompletionsPath = "/chat/completions"

type client struct {
	chat *openai.ChatCompletionsClient
}

func NewOracleClient() providers.Client {
	pool := providers.NewHTTPClientPool()
	return &client{
		chat: openai.NewChatCompletionsClient(providers.ProviderOracle, pool),
	}
}

func (c *client) Completions(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	opts, err := providers.DecodeOracleOptions(config.Options)
	if err != nil {
		return nil, err
	}
	return c.chat.Completions(ctx, chatCompletionsURL(opts), config, reqBody, requestHeaders(opts))
}

func (c *client) CompletionsStream(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) (iter.Seq2[[]byte, error], error) {
	opts, err := providers.DecodeOracleOptions(config.Options)
	if err != nil {
		return nil, err
	}
	return c.chat.CompletionsStream(ctx, chatCompletionsURL(opts), config, reqBody, requestHeaders(opts))
}

func chatCompletionsURL(opts providers.OracleOptions) string {
	return strings.TrimRight(opts.BaseURL, "/") + chatCompletionsPath
}

func requestHeaders(opts providers.OracleOptions) map[string]string {
	headers := make(map[string]string, len(opts.Headers)+1)
	for key, value := range opts.Headers {
		headers[key] = value
	}
	if opts.Project != "" {
		headers["OpenAI-Project"] = opts.Project
	}
	return headers
}

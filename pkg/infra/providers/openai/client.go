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

package openai

import (
	"context"
	"iter"
	"strings"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
)

const (
	completionsURL = "https://api.openai.com/v1/chat/completions"
	responsesURL   = "https://api.openai.com/v1/responses"

	completionsPath = "/chat/completions"
	responsesPath   = "/responses"
)

type client struct {
	chat *ChatCompletionsClient
}

func NewOpenaiClient() providers.Client {
	pool := providers.NewHTTPClientPool()
	return &client{
		chat: NewChatCompletionsClient(providers.ProviderOpenAI, pool),
	}
}

func (c *client) Completions(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	endpointURL, err := c.resolveURL(config)
	if err != nil {
		return nil, err
	}
	return c.chat.Completions(ctx, endpointURL, config, reqBody, nil)
}

func (c *client) CompletionsStream(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) (iter.Seq2[[]byte, error], error) {
	endpointURL, err := c.resolveURL(config)
	if err != nil {
		return nil, err
	}
	return c.chat.CompletionsStream(ctx, endpointURL, config, reqBody, nil)
}

func (c *client) resolveURL(config *providers.Config) (string, error) {
	opts, err := providers.DecodeOpenAIOptions(config.Options)
	if err != nil {
		return "", err
	}
	base := strings.TrimRight(opts.BaseURL, "/")
	if opts.API == providers.OpenAIAPIResponses {
		if base != "" {
			return base + responsesPath, nil
		}
		return responsesURL, nil
	}
	if base != "" {
		return base + completionsPath, nil
	}
	return completionsURL, nil
}

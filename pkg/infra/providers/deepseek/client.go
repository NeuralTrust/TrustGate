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

package deepseek

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/openai"
)

const (
	chatCompletionsURL = "https://api.deepseek.com/chat/completions"
	reasonerModelName  = "deepseek-reasoner"
	reasonerMaxTokens  = 64000
)

type client struct {
	chat *openai.ChatCompletionsClient
}

type chatCompletionsRequest struct {
	Model               string `json:"model,omitempty"`
	MaxTokens           *int   `json:"max_tokens,omitempty"`
	MaxCompletionTokens *int   `json:"max_completion_tokens,omitempty"`
}

// NewDeepSeekClient returns a providers.Client for DeepSeek's OpenAI-compatible
// Chat Completions API.
func NewDeepSeekClient() providers.Client {
	return &client{
		chat: openai.NewChatCompletionsClient(providers.ProviderDeepSeek, nil),
	}
}

func (c *client) Completions(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	if err := validateRequest(reqBody); err != nil {
		return nil, err
	}
	return c.chat.Completions(ctx, chatCompletionsURL, config, reqBody, nil)
}

func (c *client) CompletionsStream(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) (iter.Seq2[[]byte, error], error) {
	if err := validateRequest(reqBody); err != nil {
		return nil, err
	}
	return c.chat.CompletionsStream(ctx, chatCompletionsURL, config, reqBody, nil)
}

// validateRequest rejects deepseek-reasoner requests whose max token budget
// exceeds DeepSeek's published limit before the upstream call is made.
func validateRequest(reqBody []byte) error {
	var req chatCompletionsRequest
	if err := json.Unmarshal(reqBody, &req); err != nil {
		return nil
	}

	maxTokens := 0
	if req.MaxCompletionTokens != nil {
		maxTokens = *req.MaxCompletionTokens
	} else if req.MaxTokens != nil {
		maxTokens = *req.MaxTokens
	}

	if req.Model == reasonerModelName && maxTokens > reasonerMaxTokens {
		return fmt.Errorf(
			"invalid max tokens for model %q: %d exceeds DeepSeek limit %d",
			reasonerModelName,
			maxTokens,
			reasonerMaxTokens,
		)
	}
	return nil
}

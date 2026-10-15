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

package digitalocean

import (
	"context"
	"iter"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/openai"
)

// DigitalOcean Serverless Inference serves its whole catalog, Claude and GPT
// included, behind one OpenAI wire-compatible endpoint authenticated with a
// model access key. Models are named by DigitalOcean's own slugs
// ("anthropic-claude-sonnet-5.5", "openai-gpt-6-1-sol"), never the vendor id,
// so the catalog comes from models.dev's "digitalocean" key and /v1/models.
const defaultBaseURL = "https://inference.do-ai.run/v1"

type client struct {
	chat    *openai.ChatCompletionsClient
	baseURL string
}

// NewDigitalOceanClient returns the DigitalOcean Serverless Inference client.
func NewDigitalOceanClient() providers.Client {
	return newClient(defaultBaseURL)
}

func newClient(baseURL string) *client {
	return &client{
		chat:    openai.NewChatCompletionsClient(providers.ProviderDigitalOcean, nil),
		baseURL: baseURL,
	}
}

func (c *client) Completions(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	return c.chat.Completions(ctx, c.baseURL+"/chat/completions", config, reqBody, nil)
}

func (c *client) CompletionsStream(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) (iter.Seq2[[]byte, error], error) {
	return c.chat.CompletionsStream(ctx, c.baseURL+"/chat/completions", config, reqBody, nil)
}

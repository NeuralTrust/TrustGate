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

package zai

import (
	"context"
	"iter"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/openai"
)

// Z.AI (Zhipu) serves the GLM models behind an OpenAI wire-compatible
// endpoint under /api/paas/v4.
//
// The base URL is the international host. Zhipu also runs a separate China
// endpoint (open.bigmodel.cn) on its own accounts; that one is reachable
// through the openai_compatible provider with a custom base URL.
const chatCompletionsURL = "https://api.z.ai/api/paas/v4/chat/completions"

type client struct {
	chat *openai.ChatCompletionsClient
}

func NewZAIClient() providers.Client {
	return &client{
		chat: openai.NewChatCompletionsClient(providers.ProviderZAI, nil),
	}
}

func (c *client) Completions(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	return c.chat.Completions(ctx, chatCompletionsURL, config, reqBody, nil)
}

func (c *client) CompletionsStream(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) (iter.Seq2[[]byte, error], error) {
	return c.chat.CompletionsStream(ctx, chatCompletionsURL, config, reqBody, nil)
}

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

package moonshot

import (
	"context"
	"iter"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/openai"
)

// Moonshot serves the Kimi models behind an OpenAI wire-compatible endpoint:
// same chat-completions shape, Bearer auth, and SSE frames terminated by
// "data: [DONE]". A thin wrapper over the OpenAI client is the whole client.
//
// The base URL is the international host. Moonshot also runs a separate China
// endpoint (api.moonshot.cn) on its own accounts; that one is reachable through
// the openai_compatible provider with a custom base URL.
const chatCompletionsURL = "https://api.moonshot.ai/v1/chat/completions"

type client struct {
	chat *openai.ChatCompletionsClient
}

func NewMoonshotClient() providers.Client {
	return &client{
		chat: openai.NewChatCompletionsClient(providers.ProviderMoonshot, nil),
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

package groq

import (
	"context"
	"iter"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/openai"
)

const chatCompletionsURL = "https://api.groq.com/openai/v1/chat/completions"

type client struct {
	chat *openai.ChatCompletionsClient
}

func NewGroqClient() providers.Client {
	return &client{
		chat: openai.NewChatCompletionsClient(providers.ProviderGroq, nil),
	}
}

func (c *client) Completions(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	return c.chat.Completions(ctx, chatCompletionsURL, config, reqBody)
}

func (c *client) CompletionsStream(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) (iter.Seq2[[]byte, error], error) {
	return c.chat.CompletionsStream(ctx, chatCompletionsURL, config, reqBody)
}

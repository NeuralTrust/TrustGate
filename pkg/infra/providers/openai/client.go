package openai

import (
	"context"
	"iter"
	"strings"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
	"github.com/mitchellh/mapstructure"
)

const (
	CompletionsAPI = "completions"
	ResponsesAPI   = "responses"
	completionsURL = "https://api.openai.com/v1/chat/completions"
	responsesURL   = "https://api.openai.com/v1/responses"

	completionsPath = "/chat/completions"
	responsesPath   = "/responses"
)

type openaiOptions struct {
	API string `json:"api" mapstructure:"api"`
	// BaseURL overrides the default api.openai.com host so a backend can target
	// any OpenAI-compatible endpoint (self-hosted gateways, vLLM, LiteLLM, a test
	// server, ...). It is the API base, e.g. "https://host/v1"; the endpoint path
	// ("/chat/completions" or "/responses") is appended. Empty keeps the defaults.
	BaseURL string `json:"base_url" mapstructure:"base_url"`
}

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
	return c.chat.Completions(ctx, c.resolveURL(config), config, reqBody)
}

func (c *client) CompletionsStream(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) (iter.Seq2[[]byte, error], error) {
	return c.chat.CompletionsStream(ctx, c.resolveURL(config), config, reqBody)
}

func (c *client) resolveURL(config *providers.Config) string {
	options := parseOptions(config)
	base := strings.TrimRight(options.BaseURL, "/")
	if options.API == ResponsesAPI {
		if base != "" {
			return base + responsesPath
		}
		return responsesURL
	}
	if base != "" {
		return base + completionsPath
	}
	return completionsURL
}

func parseOptions(config *providers.Config) openaiOptions {
	var options openaiOptions
	if len(config.Options) > 0 {
		if err := mapstructure.Decode(config.Options, &options); err != nil {
			options = openaiOptions{API: CompletionsAPI}
		}
	} else {
		options = openaiOptions{API: CompletionsAPI}
	}
	return options
}

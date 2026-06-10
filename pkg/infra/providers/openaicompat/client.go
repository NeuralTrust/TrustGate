// Package openaicompat implements a provider client for arbitrary
// OpenAI-compatible Chat Completions endpoints (Together, Fireworks, vLLM,
// Ollama, self-hosted gateways, ...). Unlike the openai package it has no
// default host: callers must supply provider_options.base_url. Only the OpenAI
// Chat Completions API (/chat/completions) is supported. Extra request headers
// can be supplied via provider_options.headers.
package openaicompat

import (
	"context"
	"iter"
	"strings"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/openai"
)

const completionsPath = "/chat/completions"

type client struct {
	chat *openai.ChatCompletionsClient
}

// NewClient builds an OpenAI-compatible provider client backed by a pooled HTTP
// transport keyed on the openai_compatible provider name.
func NewClient() providers.Client {
	pool := providers.NewHTTPClientPool()
	return &client{
		chat: openai.NewChatCompletionsClient(providers.ProviderOpenAICompatible, pool),
	}
}

func (c *client) Completions(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	opts, err := providers.DecodeOpenAICompatibleOptions(config.Options)
	if err != nil {
		return nil, err
	}
	return c.chat.Completions(ctx, completionsURL(opts), config, reqBody, opts.Headers)
}

func (c *client) CompletionsStream(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) (iter.Seq2[[]byte, error], error) {
	opts, err := providers.DecodeOpenAICompatibleOptions(config.Options)
	if err != nil {
		return nil, err
	}
	return c.chat.CompletionsStream(ctx, completionsURL(opts), config, reqBody, opts.Headers)
}

func completionsURL(opts providers.OpenAICompatibleOptions) string {
	return strings.TrimRight(opts.BaseURL, "/") + completionsPath
}

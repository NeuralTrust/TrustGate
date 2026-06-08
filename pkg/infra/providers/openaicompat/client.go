// Package openaicompat implements a provider client for arbitrary
// OpenAI-compatible Chat Completions endpoints (Together, Fireworks, vLLM,
// Ollama, self-hosted gateways, ...). Unlike the openai package it has no
// default host: callers must supply provider_options.base_url. Only the OpenAI
// Chat Completions API (/chat/completions) is supported. Extra request headers
// can be supplied via provider_options.headers.
package openaicompat

import (
	"context"
	"fmt"
	"iter"
	"strings"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/openai"
	"github.com/mitchellh/mapstructure"
)

const completionsPath = "/chat/completions"

type options struct {
	// BaseURL is the API base, e.g. "https://api.together.xyz/v1"; the
	// /chat/completions path is appended. Required — there is no default host.
	BaseURL string `json:"base_url" mapstructure:"base_url"`
	// Headers are extra HTTP headers sent on every upstream request. They are
	// applied after the default Content-Type/Authorization, so they can override
	// them (e.g. a provider that uses a non-Bearer auth header).
	Headers map[string]string `json:"headers" mapstructure:"headers"`
}

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
	opts := parseOptions(config)
	url, err := resolveURL(opts)
	if err != nil {
		return nil, err
	}
	return c.chat.CompletionsWithHeaders(ctx, url, config, reqBody, opts.Headers)
}

func (c *client) CompletionsStream(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) (iter.Seq2[[]byte, error], error) {
	opts := parseOptions(config)
	url, err := resolveURL(opts)
	if err != nil {
		return nil, err
	}
	return c.chat.CompletionsStreamWithHeaders(ctx, url, config, reqBody, opts.Headers)
}

// resolveURL builds the /chat/completions endpoint from base_url. base_url is
// required; an OpenAI-compatible backend with no host is a misconfiguration, not
// a fall back to api.openai.com.
func resolveURL(opts options) (string, error) {
	base := strings.TrimRight(opts.BaseURL, "/")
	if base == "" {
		return "", fmt.Errorf("openai_compatible: base_url is required")
	}
	return base + completionsPath, nil
}

func parseOptions(config *providers.Config) options {
	var opts options
	if len(config.Options) > 0 {
		_ = mapstructure.Decode(config.Options, &opts)
	}
	return opts
}

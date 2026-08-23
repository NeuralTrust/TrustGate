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

// Package openaicompat implements a provider client for arbitrary
// OpenAI-compatible endpoints (Together, Fireworks, vLLM, Ollama, self-hosted
// gateways, ...). Unlike the openai package it has no default host: callers
// must supply provider_options.base_url. Chat Completions (/chat/completions),
// Embeddings (/embeddings), and Audio (/audio/speech, /audio/transcriptions)
// are supported. Extra request headers can be
// supplied via provider_options.headers.
package openaicompat

import (
	"context"
	"iter"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/openai"
)

const (
	completionsPath = "/chat/completions"
	embeddingsPath  = "/embeddings"
)

var (
	_ providers.Client                   = (*client)(nil)
	_ providers.EmbeddingsClient         = (*client)(nil)
	_ providers.AudioSpeechClient        = (*client)(nil)
	_ providers.AudioTranscriptionClient = (*client)(nil)
)

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

func (c *client) Embeddings(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	opts, err := providers.DecodeOpenAICompatibleOptions(config.Options)
	if err != nil {
		return nil, err
	}
	return c.chat.Completions(ctx, embeddingsURL(opts), config, reqBody, opts.Headers)
}

func completionsURL(opts providers.OpenAICompatibleOptions) string {
	return strings.TrimRight(opts.BaseURL, "/") + completionsPath
}

func embeddingsURL(opts providers.OpenAICompatibleOptions) string {
	return strings.TrimRight(opts.BaseURL, "/") + embeddingsPath
}

func (c *client) AudioSpeech(
	ctx context.Context,
	config *providers.Config,
	req providers.AudioRequest,
) (*providers.AudioResult, error) {
	return c.audio(ctx, config, req)
}

func (c *client) AudioTranscription(
	ctx context.Context,
	config *providers.Config,
	req providers.AudioRequest,
) (*providers.AudioResult, error) {
	return c.audio(ctx, config, req)
}

func (c *client) audio(
	ctx context.Context,
	config *providers.Config,
	req providers.AudioRequest,
) (*providers.AudioResult, error) {
	opts, err := providers.DecodeOpenAICompatibleOptions(config.Options)
	if err != nil {
		return nil, err
	}
	return c.chat.Audio(ctx, providers.JoinOpenAIAudioURL(opts.BaseURL, req.Path, req.Query), config, req, opts.Headers)
}

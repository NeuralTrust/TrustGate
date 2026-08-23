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

package openrouter

import (
	"context"
	"iter"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/openai"
)

const (
	chatCompletionsURL = "https://openrouter.ai/api/v1/chat/completions"
	filesBaseURL       = "https://openrouter.ai/api/v1"
)

var (
	_ providers.FilesClient              = (*client)(nil)
	_ providers.AudioSpeechClient        = (*client)(nil)
	_ providers.AudioTranscriptionClient = (*client)(nil)
)

type client struct {
	chat *openai.ChatCompletionsClient
}

// NewOpenRouterClient builds an OpenRouter chat-completions client.
func NewOpenRouterClient() providers.Client {
	return &client{
		chat: openai.NewChatCompletionsClient(providers.ProviderOpenRouter, nil),
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

func (c *client) Files(
	ctx context.Context,
	config *providers.Config,
	req providers.FilesRequest,
) (*providers.FilesResult, error) {
	return c.chat.Files(ctx, providers.JoinOpenAIFilesURL(filesBaseURL, req.Path, req.Query), config, req)
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
	base, err := resolveOpenRouterAudioBaseURL(config)
	if err != nil {
		return nil, err
	}
	return c.chat.Audio(ctx, providers.JoinOpenAIAudioURL(base, req.Path, req.Query), config, req, nil)
}

func resolveOpenRouterAudioBaseURL(config *providers.Config) (string, error) {
	var options map[string]any
	if config != nil {
		options = config.Options
	}
	opts, err := providers.DecodeOpenRouterOptions(options)
	if err != nil {
		return "", err
	}
	if opts.BaseURL != "" {
		return strings.TrimRight(opts.BaseURL, "/"), nil
	}
	return filesBaseURL, nil
}

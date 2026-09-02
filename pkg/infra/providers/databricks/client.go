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

package databricks

import (
	"context"
	"iter"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/openai"
)

// Databricks Model Serving speaks the OpenAI chat-completions shape, but it has
// no shared host and no shared path: each workspace serves from its own domain,
// and a model is a named serving endpoint under it. So unlike every other
// OpenAI-compatible provider here, the URL cannot be a constant — it comes from
// a required provider_options.base_url, with /invocations appended.
//
// Auth is a workspace personal access token sent as a Bearer credential.
const invocationsPath = "/invocations"

type client struct {
	chat *openai.ChatCompletionsClient
}

func NewDatabricksClient() providers.Client {
	return &client{
		chat: openai.NewChatCompletionsClient(providers.ProviderDatabricks, providers.NewHTTPClientPool()),
	}
}

func (c *client) Completions(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	opts, err := providers.DecodeDatabricksOptions(config.Options)
	if err != nil {
		return nil, err
	}
	return c.chat.Completions(ctx, invocationsURL(opts), config, reqBody, opts.Headers)
}

func (c *client) CompletionsStream(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) (iter.Seq2[[]byte, error], error) {
	opts, err := providers.DecodeDatabricksOptions(config.Options)
	if err != nil {
		return nil, err
	}
	return c.chat.CompletionsStream(ctx, invocationsURL(opts), config, reqBody, opts.Headers)
}

func invocationsURL(opts providers.DatabricksOptions) string {
	return strings.TrimRight(opts.BaseURL, "/") + invocationsPath
}

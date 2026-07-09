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

package factory

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/anthropic"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/azure"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/bedrock"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/cohere"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/deepseek"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/google"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/groq"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/mistral"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/openai"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/openaicompat"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/vertex"
)

// Provider name constants — aliased from the providers package so callers that
// import factory.ProviderX continue to compile.
const (
	ProviderOpenAI           = providers.ProviderOpenAI
	ProviderOpenAICompatible = providers.ProviderOpenAICompatible
	ProviderGoogle           = providers.ProviderGoogle
	ProviderVertex           = providers.ProviderVertex
	ProviderAnthropic        = providers.ProviderAnthropic
	ProviderBedrock          = providers.ProviderBedrock
	ProviderAzure            = providers.ProviderAzure
	ProviderMistral          = providers.ProviderMistral
	ProviderGroq             = providers.ProviderGroq
	ProviderDeepSeek         = providers.ProviderDeepSeek
	ProviderCohere           = providers.ProviderCohere
)

//go:generate mockery --name=ProviderLocator --dir=. --output=./mocks --filename=provider_locator_mock.go --case=underscore --with-expecter
type ProviderLocator interface {
	Get(provider string) (providers.Client, error)
	GetTester(provider string) (providers.ConnectionTester, error)
}

type providerLocator struct {
	clients map[string]providers.Client
}

// NewProviderLocator builds one client per provider up front and reuses it for
// the lifetime of the locator. Provider clients are stateless wrappers over an
// HTTP connection pool, so constructing a fresh one per request (as before)
// threw away connection reuse and defeated per-client caches (e.g. the Bedrock
// SDK client pool). The map is read-only after construction, so Get is safe for
// concurrent use.
func NewProviderLocator() ProviderLocator {
	return &providerLocator{
		clients: map[string]providers.Client{
			ProviderOpenAI:           openai.NewOpenaiClient(),
			ProviderOpenAICompatible: openaicompat.NewClient(),
			ProviderGoogle:           google.NewGoogleClient(),
			ProviderAnthropic:        anthropic.NewAnthropicClient(),
			ProviderBedrock:          bedrock.NewBedrockClient(),
			ProviderAzure:            azure.NewAzureClient(),
			ProviderMistral:          mistral.NewMistralClient(),
			ProviderGroq:             groq.NewGroqClient(),
			ProviderDeepSeek:         deepseek.NewDeepSeekClient(),
			ProviderVertex:           vertex.NewVertexClient(),
			ProviderCohere:           cohere.NewCohereClient(),
		},
	}
}

func (f *providerLocator) Get(provider string) (providers.Client, error) {
	if c, ok := f.clients[provider]; ok {
		return c, nil
	}
	return nil, fmt.Errorf("unsupported provider: %s", provider)
}

func (f *providerLocator) GetTester(provider string) (providers.ConnectionTester, error) {
	c, ok := f.clients[provider]
	if !ok {
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
	tester, ok := c.(providers.ConnectionTester)
	if !ok {
		return nil, fmt.Errorf("provider %q does not support connection testing", provider)
	}
	return tester, nil
}

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

package providers_test

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSupportsCapability_MatchesLocatorClients(t *testing.T) {
	locator := factory.NewProviderLocator()
	for _, provider := range []string{
		factory.ProviderOpenAI,
		factory.ProviderOpenAICompatible,
		factory.ProviderGoogle,
		factory.ProviderVertex,
		factory.ProviderAnthropic,
		factory.ProviderBedrock,
		factory.ProviderAzure,
		factory.ProviderMistral,
		factory.ProviderGroq,
		factory.ProviderDeepSeek,
		factory.ProviderXAI,
		factory.ProviderCerebras,
		factory.ProviderOpenRouter,
		factory.ProviderCohere,
	} {
		t.Run(provider, func(t *testing.T) {
			client, err := locator.Get(provider)
			require.NoError(t, err)
			assert.Equal(t,
				providers.ClientSupportsCapability(client, providers.CapabilityEmbeddings),
				providers.SupportsCapability(provider, providers.CapabilityEmbeddings),
			)
			assert.Equal(t,
				providers.ClientSupportsCapability(client, providers.CapabilityRerank),
				providers.SupportsCapability(provider, providers.CapabilityRerank),
			)
		})
	}
}

func TestProviderCapabilities(t *testing.T) {
	openai := providers.ProviderCapabilities(providers.ProviderOpenAI)
	assert.True(t, openai[providers.CapabilityChat])
	assert.True(t, openai[providers.CapabilityEmbeddings])
	assert.False(t, openai[providers.CapabilityRerank])

	cohere := providers.ProviderCapabilities(providers.ProviderCohere)
	assert.True(t, cohere[providers.CapabilityEmbeddings])
	assert.True(t, cohere[providers.CapabilityRerank])

	anthropic := providers.ProviderCapabilities(providers.ProviderAnthropic)
	assert.True(t, anthropic[providers.CapabilityChat])
	assert.False(t, anthropic[providers.CapabilityEmbeddings])
}

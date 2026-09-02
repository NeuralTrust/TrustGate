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
		factory.ProviderMoonshot,
		factory.ProviderTogether,
		factory.ProviderDeepInfra,
		factory.ProviderNovita,
		factory.ProviderNebius,
		factory.ProviderSiliconFlow,
		factory.ProviderSambaNova,
		factory.ProviderFireworks,
		factory.ProviderZAI,
		factory.ProviderDashScope,
		factory.ProviderNvidia,
		factory.ProviderMiniMax,
		factory.ProviderPerplexity,
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
			assert.Equal(t,
				providers.ClientSupportsCapability(client, providers.CapabilityFiles),
				providers.SupportsCapability(provider, providers.CapabilityFiles),
			)
			assert.Equal(t,
				providers.ClientSupportsCapability(client, providers.CapabilityImages),
				providers.SupportsCapability(provider, providers.CapabilityImages),
			)
			assert.Equal(t,
				providers.ClientSupportsCapability(client, providers.CapabilityAudioSpeech),
				providers.SupportsCapability(provider, providers.CapabilityAudioSpeech),
			)
			assert.Equal(t,
				providers.ClientSupportsCapability(client, providers.CapabilityAudioTranscription),
				providers.SupportsCapability(provider, providers.CapabilityAudioTranscription),
			)
		})
	}
}

func TestProviderCapabilities(t *testing.T) {
	openai := providers.ProviderCapabilities(providers.ProviderOpenAI)
	assert.True(t, openai[providers.CapabilityChat])
	assert.True(t, openai[providers.CapabilityEmbeddings])
	assert.True(t, openai[providers.CapabilityFiles])
	assert.False(t, openai[providers.CapabilityRerank])

	mistral := providers.ProviderCapabilities(providers.ProviderMistral)
	assert.True(t, mistral[providers.CapabilityEmbeddings])
	assert.True(t, mistral[providers.CapabilityFiles])
	assert.False(t, mistral[providers.CapabilityRerank])

	cohere := providers.ProviderCapabilities(providers.ProviderCohere)
	assert.True(t, cohere[providers.CapabilityEmbeddings])
	assert.True(t, cohere[providers.CapabilityRerank])
	assert.False(t, cohere[providers.CapabilityFiles])

	anthropic := providers.ProviderCapabilities(providers.ProviderAnthropic)
	assert.True(t, anthropic[providers.CapabilityChat])
	assert.False(t, anthropic[providers.CapabilityEmbeddings])
	assert.True(t, anthropic[providers.CapabilityFiles])

	vertex := providers.ProviderCapabilities(providers.ProviderVertex)
	assert.True(t, vertex[providers.CapabilityEmbeddings])
	assert.False(t, vertex[providers.CapabilityRerank])
	assert.False(t, vertex[providers.CapabilityFiles])

	bedrock := providers.ProviderCapabilities(providers.ProviderBedrock)
	assert.True(t, bedrock[providers.CapabilityEmbeddings])
	assert.False(t, bedrock[providers.CapabilityRerank])
	assert.False(t, bedrock[providers.CapabilityFiles])

	assert.True(t, providers.ProviderCapabilities(providers.ProviderAzure)[providers.CapabilityFiles])
	assert.True(t, providers.ProviderCapabilities(providers.ProviderOpenRouter)[providers.CapabilityFiles])
	assert.True(t, providers.ProviderCapabilities(providers.ProviderXAI)[providers.CapabilityFiles])
	assert.False(t, providers.ProviderCapabilities(providers.ProviderOpenAICompatible)[providers.CapabilityFiles])
	assert.True(t, providers.ProviderCapabilities(providers.ProviderOpenAI)[providers.CapabilityImages])
	assert.True(t, providers.ProviderCapabilities(providers.ProviderAzure)[providers.CapabilityImages])
	assert.True(t, providers.ProviderCapabilities(providers.ProviderOpenAICompatible)[providers.CapabilityImages])
	assert.True(t, providers.ProviderCapabilities(providers.ProviderOpenRouter)[providers.CapabilityImages])
	assert.False(t, providers.ProviderCapabilities(providers.ProviderGroq)[providers.CapabilityImages])
	assert.False(t, providers.ProviderCapabilities(providers.ProviderAnthropic)[providers.CapabilityImages])

	for _, provider := range []string{
		providers.ProviderOpenAI,
		providers.ProviderOpenAICompatible,
		providers.ProviderAzure,
		providers.ProviderOpenRouter,
		providers.ProviderGroq,
		providers.ProviderMistral,
	} {
		caps := providers.ProviderCapabilities(provider)
		assert.True(t, caps[providers.CapabilityAudioSpeech], provider)
		assert.True(t, caps[providers.CapabilityAudioTranscription], provider)
	}
	assert.False(t, providers.ProviderCapabilities(providers.ProviderAnthropic)[providers.CapabilityAudioSpeech])
	assert.False(t, providers.ProviderCapabilities(providers.ProviderXAI)[providers.CapabilityAudioTranscription])
	assert.False(t, providers.ProviderCapabilities(providers.ProviderCohere)[providers.CapabilityAudioSpeech])
}

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

package providers

const (
	CapabilityChat       = "chat"
	CapabilityEmbeddings = "embeddings"
	CapabilityRerank     = "rerank"
)

func SupportsCapability(provider, capability string) bool {
	switch capability {
	case "", CapabilityChat:
		return true
	case CapabilityEmbeddings:
		switch provider {
		case ProviderOpenAI, ProviderOpenAICompatible, ProviderAzure, ProviderCohere, ProviderMistral:
			return true
		default:
			return false
		}
	case CapabilityRerank:
		return provider == ProviderCohere
	default:
		return false
	}
}

func ProviderCapabilities(provider string) map[string]bool {
	caps := map[string]bool{CapabilityChat: true}
	if SupportsCapability(provider, CapabilityEmbeddings) {
		caps[CapabilityEmbeddings] = true
	}
	if SupportsCapability(provider, CapabilityRerank) {
		caps[CapabilityRerank] = true
	}
	return caps
}

func ClientSupportsCapability(client Client, capability string) bool {
	switch capability {
	case "", CapabilityChat:
		return client != nil
	case CapabilityEmbeddings:
		_, ok := client.(EmbeddingsClient)
		return ok
	case CapabilityRerank:
		_, ok := client.(RerankClient)
		return ok
	default:
		return false
	}
}

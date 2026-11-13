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

import (
	"reflect"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/provider"
)

// TestHonorsBaseURLMatchesTheOptions fails when a provider starts or stops
// reading base_url without provider.HonorsBaseURL following: a store's
// allowed destinations would then check a host the provider does not call.
func TestHonorsBaseURLMatchesTheOptions(t *testing.T) {
	options := map[string]any{
		provider.OpenAI:           OpenAIOptions{},
		provider.OpenAICompatible: OpenAICompatibleOptions{},
		provider.Vertex:           VertexOptions{},
		provider.Cohere:           CohereOptions{},
		provider.Mistral:          MistralOptions{},
		provider.Anthropic:        AnthropicOptions{},
		provider.Groq:             GroqOptions{},
		provider.OpenRouter:       OpenRouterOptions{},
		provider.Azure:            AzureOptions{},
		provider.Bedrock:          BedrockOptions{},
	}
	for _, name := range provider.Supported() {
		reads := false
		if opts, ok := options[name]; ok {
			_, reads = reflect.TypeOf(opts).FieldByName("BaseURL")
		}
		if reads != provider.HonorsBaseURL(name) {
			t.Errorf("provider %q: options read base_url = %v, HonorsBaseURL = %v", name, reads, provider.HonorsBaseURL(name))
		}
	}
}

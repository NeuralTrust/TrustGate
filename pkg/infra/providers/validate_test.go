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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateProviderOptions(t *testing.T) {
	tests := []struct {
		name        string
		provider    string
		options     map[string]any
		errContains string
	}{
		{name: "unknown provider is not validated", provider: "anthropic", options: map[string]any{"foo": "bar"}},

		{name: "openai_compatible with base_url", provider: ProviderOpenAICompatible, options: map[string]any{"base_url": "https://host/v1"}},
		{name: "openai_compatible with http base_url", provider: ProviderOpenAICompatible, options: map[string]any{"base_url": "http://localhost:8080/v1"}},
		{name: "openai_compatible missing base_url", provider: ProviderOpenAICompatible, options: nil, errContains: "base_url"},
		{name: "openai_compatible empty base_url", provider: ProviderOpenAICompatible, options: map[string]any{"base_url": ""}, errContains: "base_url"},
		{name: "openai_compatible whitespace base_url", provider: ProviderOpenAICompatible, options: map[string]any{"base_url": "   "}, errContains: "base_url"},
		{name: "openai_compatible base_url without scheme", provider: ProviderOpenAICompatible, options: map[string]any{"base_url": "host/v1"}, errContains: "base_url"},
		{name: "openai_compatible base_url with bad scheme", provider: ProviderOpenAICompatible, options: map[string]any{"base_url": "ftp://host/v1"}, errContains: "base_url"},
		{name: "openai_compatible non-string base_url", provider: ProviderOpenAICompatible, options: map[string]any{"base_url": 123}, errContains: "openai_compatible"},

		{name: "openai no options is valid", provider: ProviderOpenAI, options: nil},
		{name: "openai explicit completions", provider: ProviderOpenAI, options: map[string]any{"api": "completions"}},
		{name: "openai responses", provider: ProviderOpenAI, options: map[string]any{"api": "responses"}},
		{name: "openai custom base_url", provider: ProviderOpenAI, options: map[string]any{"base_url": "https://host/v1"}},
		{name: "openai invalid api", provider: ProviderOpenAI, options: map[string]any{"api": "chat"}, errContains: "api"},
		{name: "openai invalid base_url", provider: ProviderOpenAI, options: map[string]any{"base_url": "host/v1"}, errContains: "base_url"},
		{name: "openai non-string api", provider: ProviderOpenAI, options: map[string]any{"api": 123}, errContains: "openai"},

		{name: "vertex valid", provider: ProviderVertex, options: map[string]any{"project": "p", "location": "us-central1"}},
		{name: "vertex custom version", provider: ProviderVertex, options: map[string]any{"project": "p", "location": "eu-west1", "version": "v1beta1"}},
		{name: "vertex missing project", provider: ProviderVertex, options: map[string]any{"location": "us-central1"}, errContains: "project"},
		{name: "vertex missing location", provider: ProviderVertex, options: map[string]any{"project": "p"}, errContains: "location"},
		{name: "vertex nil options", provider: ProviderVertex, options: nil, errContains: "project"},
		{name: "vertex project wrong type", provider: ProviderVertex, options: map[string]any{"project": 123, "location": "l"}, errContains: "vertex"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProviderOptions(tt.provider, tt.options)
			if tt.errContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				return
			}
			require.NoError(t, err)
		})
	}
}

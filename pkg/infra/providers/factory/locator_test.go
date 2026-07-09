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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProviderLocator_Get(t *testing.T) {
	locator := NewProviderLocator()

	for _, provider := range []string{
		ProviderOpenAI,
		ProviderOpenAICompatible,
		ProviderGoogle,
		ProviderVertex,
		ProviderAnthropic,
		ProviderBedrock,
		ProviderAzure,
		ProviderMistral,
		ProviderGroq,
		ProviderDeepSeek,
		ProviderXAI,
		ProviderCerebras,
		ProviderOpenRouter,
	} {
		t.Run(provider, func(t *testing.T) {
			client, err := locator.Get(provider)
			require.NoError(t, err)
			assert.NotNil(t, client)
		})
	}
}

func TestProviderLocator_GetUnknown(t *testing.T) {
	_, err := NewProviderLocator().Get("does-not-exist")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported provider")
}

// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package catalog

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProviderOptions_AzureAPISurfaces(t *testing.T) {
	t.Parallel()

	options := ProviderOptions(providers.ProviderAzure)
	require.Len(t, options, 1)
	assert.Equal(t, "api", options[0].Key)
	assert.Equal(t, providers.AzureAPIDeployments, options[0].Default)

	values := make([]string, 0, len(options[0].Enum))
	for _, option := range options[0].Enum {
		values = append(values, option.Value)
	}
	assert.Equal(t, []string{
		providers.AzureAPIDeployments,
		providers.AzureAPIOpenAIV1,
		providers.AzureAPIResponses,
		providers.AzureAPIAnthropic,
	}, values)
}

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

package proxy

import (
	"testing"

	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProviderCredentials_AzureAPIKey(t *testing.T) {
	auth := &registrydomain.TargetAuth{
		Type: registrydomain.AuthTypeAzure,
		Azure: &registrydomain.AzureAuth{
			Endpoint: "https://example.openai.azure.com",
			Version:  "2024-10-21",
			APIKey:   "az-secret-key",
		},
	}

	creds := auth.ProviderCredentials()

	require.NotNil(t, creds.Azure)
	assert.Equal(t, "https://example.openai.azure.com", creds.Azure.Endpoint)
	assert.False(t, creds.Azure.UseIdentity)
	assert.Equal(t, "az-secret-key", creds.ApiKey)
}

func TestProviderCredentials_AzureManagedIdentity(t *testing.T) {
	auth := &registrydomain.TargetAuth{
		Type: registrydomain.AuthTypeAzure,
		Azure: &registrydomain.AzureAuth{
			Endpoint:           "https://example.openai.azure.com",
			UseManagedIdentity: true,
		},
	}

	creds := auth.ProviderCredentials()

	require.NotNil(t, creds.Azure)
	assert.True(t, creds.Azure.UseIdentity)
	assert.Empty(t, creds.ApiKey)
}

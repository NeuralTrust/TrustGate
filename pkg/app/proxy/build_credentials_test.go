package proxy

import (
	"testing"

	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProviderCredentials_AzureAPIKey(t *testing.T) {
	auth := &registrydomain.TargetAuth{
		Type: registrydomain.AuthTypeAzure,
		Azure: &registrydomain.AzureAuth{
			Endpoint: "https://example.openai.azure.com",
			Version:  "2024-05-01-preview",
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

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
		ProviderGoogle,
		ProviderVertex,
		ProviderAnthropic,
		ProviderBedrock,
		ProviderAzure,
		ProviderMistral,
		ProviderGroq,
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

package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateProviderOptions(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		options  map[string]any
		wantErr  bool
	}{
		{name: "openai has no required options", provider: ProviderOpenAI, options: nil},
		{name: "openai_compatible with base_url", provider: ProviderOpenAICompatible, options: map[string]any{"base_url": "https://host/v1"}},
		{name: "openai_compatible with http base_url", provider: ProviderOpenAICompatible, options: map[string]any{"base_url": "http://localhost:8080/v1"}},
		{name: "openai_compatible missing base_url", provider: ProviderOpenAICompatible, options: nil, wantErr: true},
		{name: "openai_compatible empty base_url", provider: ProviderOpenAICompatible, options: map[string]any{"base_url": ""}, wantErr: true},
		{name: "openai_compatible whitespace base_url", provider: ProviderOpenAICompatible, options: map[string]any{"base_url": "   "}, wantErr: true},
		{name: "openai_compatible base_url without scheme", provider: ProviderOpenAICompatible, options: map[string]any{"base_url": "host/v1"}, wantErr: true},
		{name: "openai_compatible base_url with bad scheme", provider: ProviderOpenAICompatible, options: map[string]any{"base_url": "ftp://host/v1"}, wantErr: true},
		{name: "openai_compatible non-string base_url", provider: ProviderOpenAICompatible, options: map[string]any{"base_url": 123}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProviderOptions(tt.provider, tt.options)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "base_url")
				return
			}
			require.NoError(t, err)
		})
	}
}

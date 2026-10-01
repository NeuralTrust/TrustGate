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

package azure

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnthropicConnectionProbeUsesSharedModelsSurface(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		assert.Equal(t, "/openai/v1/models", request.URL.Path)
		assert.Equal(t, "foundry-key", request.Header.Get("api-key"))
		assert.Empty(t, request.Header.Get("x-api-key"))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	result := (&client{}).TestConnection(context.Background(), &providers.Config{
		Options: map[string]any{"api": providers.AzureAPIAnthropic},
		Credentials: providers.Credentials{
			ApiKey: "foundry-key",
			Azure: &providers.Azure{
				Endpoint: server.URL,
				AuthMode: providers.AzureAuthModeAPIKey,
			},
		},
	})

	assert.True(t, result.OK, result.Message)
}

func TestParseAzureDeploymentListKeepsDeploymentAsID(t *testing.T) {
	t.Parallel()

	models, err := parseAzureDeploymentList([]byte(`{
		"data": [
			{"id":"sonnet-prod","model":"claude-sonnet-4-6"},
			{"id":"codex-prod","model":"gpt-5-codex"},
			{"id":"sonnet-prod","model":"claude-sonnet-4-6"}
		]
	}`))
	require.NoError(t, err)
	assert.Equal(t, []providers.LiveModel{
		{ID: "sonnet-prod", DisplayName: "sonnet-prod", ProviderModel: "claude-sonnet-4-6"},
		{ID: "codex-prod", DisplayName: "codex-prod", ProviderModel: "gpt-5-codex"},
	}, models)
}

func TestBuildModelsURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		api     string
		wantURL string
		wantAPI string
	}{
		{
			name:    "deployments",
			api:     providers.AzureAPIDeployments,
			wantURL: "https://x.services.ai.azure.com/openai/deployments?api-version=2024-10-21",
			wantAPI: providers.AzureAPIDeployments,
		},
		{
			name:    "OpenAI v1",
			api:     providers.AzureAPIOpenAIV1,
			wantURL: "https://x.services.ai.azure.com/api/projects/project-a/openai/v1/models",
			wantAPI: providers.AzureAPIOpenAIV1,
		},
		{
			name:    "Responses",
			api:     providers.AzureAPIResponses,
			wantURL: "https://x.services.ai.azure.com/api/projects/project-a/openai/v1/models",
			wantAPI: providers.AzureAPIResponses,
		},
		{
			name:    "Anthropic",
			api:     providers.AzureAPIAnthropic,
			wantURL: "https://x.services.ai.azure.com/api/projects/project-a/openai/v1/models",
			wantAPI: providers.AzureAPIOpenAIV1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &providers.Config{
				Options: map[string]any{"api": tt.api},
				Credentials: providers.Credentials{Azure: &providers.Azure{
					Endpoint: "https://x.services.ai.azure.com/api/projects/project-a",
				}},
			}
			gotURL, gotAPI, err := (&client{}).buildModelsURL(config)
			require.NoError(t, err)
			assert.Equal(t, tt.wantURL, gotURL)
			assert.Equal(t, tt.wantAPI, gotAPI)
		})
	}
}

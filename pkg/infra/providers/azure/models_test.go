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

func TestAnthropicConnectionProbeListsDeployments(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		assert.Equal(t, "/openai/deployments", request.URL.Path)
		assert.Equal(t, deploymentsListAPIVersion, request.URL.Query().Get("api-version"))
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
			{"id":"sonnet-prod","model":"claude-sonnet-4-6"},
			{"id":"draining","model":"gpt-4o","status":"deleting"},
			{"id":"mini-prod","model":"gpt-5.4-mini","status":"succeeded"}
		]
	}`))
	require.NoError(t, err)
	assert.Equal(t, []providers.LiveModel{
		{ID: "sonnet-prod", DisplayName: "sonnet-prod", ProviderModel: "claude-sonnet-4-6"},
		{ID: "codex-prod", DisplayName: "codex-prod", ProviderModel: "gpt-5-codex"},
		{ID: "mini-prod", DisplayName: "mini-prod", ProviderModel: "gpt-5.4-mini"},
	}, models)
}

func TestDeploymentsListURLIgnoresSurfaceAndAPIVersion(t *testing.T) {
	t.Parallel()

	const want = "https://x.services.ai.azure.com/openai/deployments?api-version=2023-03-15-preview"
	for _, api := range []string{
		providers.AzureAPIDeployments,
		providers.AzureAPIOpenAIV1,
		providers.AzureAPIResponses,
		providers.AzureAPIAnthropic,
	} {
		t.Run(api, func(t *testing.T) {
			t.Parallel()

			got, err := deploymentsListURL(&providers.Config{
				Options: map[string]any{"api": api},
				Credentials: providers.Credentials{Azure: &providers.Azure{
					Endpoint:   "https://x.services.ai.azure.com/api/projects/project-a/",
					ApiVersion: "2025-04-01-preview",
				}},
			})
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}
}

func TestDeploymentsListURLRejectsUnknownSurface(t *testing.T) {
	t.Parallel()

	_, err := deploymentsListURL(&providers.Config{
		Options:     map[string]any{"api": "assistants"},
		Credentials: providers.Credentials{Azure: &providers.Azure{Endpoint: "https://x.openai.azure.com"}},
	})
	require.Error(t, err)
}

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
	"sync"
	"sync/atomic"
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
		{ID: "draining", DisplayName: "draining", ProviderModel: "gpt-4o", Pending: true},
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

			got, gotAPI, err := deploymentsListURL(&providers.Config{
				Options: map[string]any{"api": api},
				Credentials: providers.Credentials{Azure: &providers.Azure{
					Endpoint:   "https://x.services.ai.azure.com/api/projects/project-a/",
					ApiVersion: "2025-04-01-preview",
				}},
			})
			require.NoError(t, err)
			assert.Equal(t, want, got)
			assert.Equal(t, api, gotAPI)
		})
	}
}

func TestDeploymentsListURLRejectsUnknownSurface(t *testing.T) {
	t.Parallel()

	_, _, err := deploymentsListURL(&providers.Config{
		Options:     map[string]any{"api": "assistants"},
		Credentials: providers.Credentials{Azure: &providers.Azure{Endpoint: "https://x.openai.azure.com"}},
	})
	require.Error(t, err)
}

func TestDeploymentsForSurface(t *testing.T) {
	t.Parallel()

	models := []providers.LiveModel{
		{ID: "sonnet-prod", ProviderModel: "claude-sonnet-4-6"},
		{ID: "gpt-prod", ProviderModel: "gpt-6-luna"},
		{ID: "unnamed"},
	}
	ids := func(in []providers.LiveModel) []string {
		out := make([]string, 0, len(in))
		for _, model := range in {
			out = append(out, model.ID)
		}
		return out
	}

	assert.Equal(t, []string{"sonnet-prod", "unnamed"}, ids(deploymentsForSurface(models, providers.AzureAPIAnthropic)))
	for _, api := range []string{providers.AzureAPIDeployments, providers.AzureAPIOpenAIV1, providers.AzureAPIResponses} {
		assert.Equal(t, []string{"gpt-prod", "unnamed"}, ids(deploymentsForSurface(models, api)), api)
	}
}

func TestListLiveModelsWithoutEndpointIsMisconfigured(t *testing.T) {
	t.Parallel()

	_, err := (&client{}).ListLiveModels(context.Background(), &providers.Config{})

	require.ErrorIs(t, err, providers.ErrModelListingFailed)
	require.ErrorIs(t, err, providers.ErrModelListingMisconfigured)
}

func TestListLiveModelsReportsTheProviderStatus(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	_, err := (&client{}).ListLiveModels(context.Background(), &providers.Config{
		Credentials: providers.Credentials{
			ApiKey: "wrong-key",
			Azure:  &providers.Azure{Endpoint: server.URL, AuthMode: providers.AzureAuthModeAPIKey},
		},
	})

	var status *providers.ModelListingStatusError
	require.ErrorAs(t, err, &status)
	assert.Equal(t, http.StatusUnauthorized, status.StatusCode)
	assert.NotErrorIs(t, err, providers.ErrModelListingMisconfigured)
}

func TestConnectionProbeFallsBackToV1WhenDeploymentsRouteIsMissing(t *testing.T) {
	t.Parallel()

	var (
		mu    sync.Mutex
		paths []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		mu.Lock()
		paths = append(paths, request.URL.Path)
		mu.Unlock()
		assert.Equal(t, "proxy-key", request.Header.Get("api-key"))
		if request.URL.Path == "/openai/deployments" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	result := (&client{}).TestConnection(context.Background(), &providers.Config{
		Options: map[string]any{"api": providers.AzureAPIOpenAIV1},
		Credentials: providers.Credentials{
			ApiKey: "proxy-key",
			Azure:  &providers.Azure{Endpoint: server.URL, AuthMode: providers.AzureAuthModeAPIKey},
		},
	})

	assert.True(t, result.OK, result.Message)
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"/openai/deployments", "/openai/v1/models"}, paths)
}

func TestConnectionProbeReportsRejectedCredentialsWithoutFallback(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	result := (&client{}).TestConnection(context.Background(), &providers.Config{
		Credentials: providers.Credentials{
			ApiKey: "wrong-key",
			Azure:  &providers.Azure{Endpoint: server.URL, AuthMode: providers.AzureAuthModeAPIKey},
		},
	})

	assert.False(t, result.OK)
	assert.Equal(t, providers.StageAuthentication, result.Stage)
	assert.Equal(t, int32(1), calls.Load())
}

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

package azure

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAzureClient(t *testing.T) {
	assert.NotNil(t, NewAzureClient())
}

func TestAzureTokenScope(t *testing.T) {
	assert.Equal(t, "https://ai.azure.com/.default", azureTokenScope)
}

func TestCompletions_MissingAzureConfig(t *testing.T) {
	_, err := NewAzureClient().Completions(context.Background(), &providers.Config{}, []byte(`{"model":"dep"}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "azure configuration is required")
}

func TestCompletions_MissingEndpoint(t *testing.T) {
	cfg := &providers.Config{Credentials: providers.Credentials{Azure: &providers.Azure{}}}
	_, err := NewAzureClient().Completions(context.Background(), cfg, []byte(`{"model":"dep"}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "azure endpoint is required")
}

func TestBuildURL(t *testing.T) {
	c := &client{}

	t.Run("default api version", func(t *testing.T) {
		cfg := &providers.Config{Credentials: providers.Credentials{Azure: &providers.Azure{Endpoint: "https://x.openai.azure.com"}}}
		url := c.buildURL(cfg, "gpt-4o")
		assert.Equal(t, "https://x.openai.azure.com/openai/deployments/gpt-4o/chat/completions?api-version=2024-10-21", url)
	})

	t.Run("project endpoint default api version", func(t *testing.T) {
		cfg := &providers.Config{Credentials: providers.Credentials{Azure: &providers.Azure{Endpoint: "https://x.services.ai.azure.com/api/projects/project-a"}}}
		url := c.buildURL(cfg, "gpt-4o")
		assert.Equal(t, "https://x.services.ai.azure.com/openai/deployments/gpt-4o/chat/completions?api-version=2024-10-21", url)
	})

	t.Run("custom api version", func(t *testing.T) {
		cfg := &providers.Config{Credentials: providers.Credentials{Azure: &providers.Azure{Endpoint: "https://x.openai.azure.com", ApiVersion: "2025-01-01"}}}
		url := c.buildURL(cfg, "gpt-4o")
		assert.Equal(t, "https://x.openai.azure.com/openai/deployments/gpt-4o/chat/completions?api-version=2025-01-01", url)
	})
}

func TestAuthHeaderApply(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "http://x", nil)

	authHeader{name: "Authorization", value: "Bearer tok"}.apply(req)

	assert.Equal(t, "Bearer tok", req.Header.Get("Authorization"))
	assert.Empty(t, req.Header.Get("api-key"))
}

func TestResolveAuth(t *testing.T) {
	t.Run("api key mode uses api-key header", func(t *testing.T) {
		c := &client{}
		cfg := &providers.Config{Credentials: providers.Credentials{
			ApiKey: "key",
			Azure:  &providers.Azure{AuthMode: providers.AzureAuthModeAPIKey},
		}}

		auth, err := c.resolveAuth(context.Background(), cfg)
		require.NoError(t, err)
		assert.Equal(t, authHeader{name: "api-key", value: "key"}, auth)
	})

	t.Run("service principal mode uses bearer token", func(t *testing.T) {
		c := &client{tokenSource: func(_ context.Context, az *providers.Azure) (string, error) {
			assert.Equal(t, providers.AzureAuthModeServicePrincipal, az.AuthMode)
			assert.Equal(t, "tenant", az.TenantID)
			assert.Equal(t, "client", az.ClientID)
			assert.Equal(t, "secret", az.ClientSecret)
			return "sp-token", nil
		}}
		cfg := &providers.Config{Credentials: providers.Credentials{Azure: &providers.Azure{
			AuthMode:     providers.AzureAuthModeServicePrincipal,
			TenantID:     "tenant",
			ClientID:     "client",
			ClientSecret: "secret",
		}}}

		auth, err := c.resolveAuth(context.Background(), cfg)
		require.NoError(t, err)
		assert.Equal(t, authHeader{name: "Authorization", value: "Bearer sp-token"}, auth)
	})

	t.Run("default credential mode uses bearer token", func(t *testing.T) {
		c := &client{tokenSource: func(_ context.Context, az *providers.Azure) (string, error) {
			assert.Equal(t, providers.AzureAuthModeDefaultAzureCredential, azureAuthMode(az))
			return "dac-token", nil
		}}
		cfg := &providers.Config{Credentials: providers.Credentials{Azure: &providers.Azure{
			AuthMode: providers.AzureAuthModeDefaultAzureCredential,
		}}}

		auth, err := c.resolveAuth(context.Background(), cfg)
		require.NoError(t, err)
		assert.Equal(t, authHeader{name: "Authorization", value: "Bearer dac-token"}, auth)
	})

	t.Run("missing api key", func(t *testing.T) {
		c := &client{}
		cfg := &providers.Config{Credentials: providers.Credentials{Azure: &providers.Azure{AuthMode: providers.AzureAuthModeAPIKey}}}
		_, err := c.resolveAuth(context.Background(), cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "API key is required")
	})
}

func TestAzureAuthModeFallbacks(t *testing.T) {
	tests := []struct {
		name string
		az   *providers.Azure
		want providers.AzureAuthMode
	}{
		{
			name: "explicit mode wins",
			az:   &providers.Azure{AuthMode: providers.AzureAuthModeServicePrincipal, UseIdentity: true},
			want: providers.AzureAuthModeServicePrincipal,
		},
		{
			name: "legacy identity maps to default credential",
			az:   &providers.Azure{UseIdentity: true},
			want: providers.AzureAuthModeDefaultAzureCredential,
		},
		{
			name: "legacy service principal fields map to service principal",
			az:   &providers.Azure{TenantID: "tenant", ClientID: "client", ClientSecret: "secret"},
			want: providers.AzureAuthModeServicePrincipal,
		},
		{
			name: "legacy default maps to api key",
			az:   &providers.Azure{},
			want: providers.AzureAuthModeAPIKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, azureAuthMode(tt.az))
		})
	}
}

func TestCompletions_AppliesAuthMode(t *testing.T) {
	tests := []struct {
		name              string
		credentials       providers.Credentials
		wantAPIKey        string
		wantAuthorization string
	}{
		{
			name: "api key",
			credentials: providers.Credentials{
				ApiKey: "api-key",
				Azure:  &providers.Azure{AuthMode: providers.AzureAuthModeAPIKey},
			},
			wantAPIKey: "api-key",
		},
		{
			name: "service principal",
			credentials: providers.Credentials{
				Azure: &providers.Azure{
					AuthMode:     providers.AzureAuthModeServicePrincipal,
					TenantID:     "tenant",
					ClientID:     "client",
					ClientSecret: "secret",
				},
			},
			wantAuthorization: "Bearer service-principal-token",
		},
		{
			name: "default azure credential",
			credentials: providers.Credentials{
				Azure: &providers.Azure{AuthMode: providers.AzureAuthModeDefaultAzureCredential, UseIdentity: true},
			},
			wantAuthorization: "Bearer default-azure-credential-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotAPIKey, gotAuthorization string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAPIKey = r.Header.Get("api-key")
				gotAuthorization = r.Header.Get("Authorization")
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"az-1"}`))
			}))
			t.Cleanup(srv.Close)

			tt.credentials.Azure.Endpoint = srv.URL
			c := &client{
				pool: providers.NewHTTPClientPool(),
				tokenSource: func(_ context.Context, az *providers.Azure) (string, error) {
					return strings.ReplaceAll(string(azureAuthMode(az)), "_", "-") + "-token", nil
				},
			}

			resp, err := c.Completions(context.Background(), &providers.Config{Credentials: tt.credentials}, []byte(`{"model":"dep"}`))
			require.NoError(t, err)

			assert.JSONEq(t, `{"id":"az-1"}`, string(resp))
			assert.Equal(t, tt.wantAPIKey, gotAPIKey)
			assert.Equal(t, tt.wantAuthorization, gotAuthorization)
		})
	}
}

func TestTestConnection_AppliesAuthMode(t *testing.T) {
	tests := []struct {
		name              string
		credentials       providers.Credentials
		wantAPIKey        string
		wantAuthorization string
	}{
		{
			name: "api key",
			credentials: providers.Credentials{
				ApiKey: "api-key",
				Azure:  &providers.Azure{AuthMode: providers.AzureAuthModeAPIKey},
			},
			wantAPIKey: "api-key",
		},
		{
			name: "service principal",
			credentials: providers.Credentials{
				Azure: &providers.Azure{
					AuthMode:     providers.AzureAuthModeServicePrincipal,
					TenantID:     "tenant",
					ClientID:     "client",
					ClientSecret: "secret",
				},
			},
			wantAuthorization: "Bearer service-principal-token",
		},
		{
			name: "default azure credential",
			credentials: providers.Credentials{
				Azure: &providers.Azure{AuthMode: providers.AzureAuthModeDefaultAzureCredential, UseIdentity: true},
			},
			wantAuthorization: "Bearer default-azure-credential-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotAPIKey, gotAuthorization string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAPIKey = r.Header.Get("api-key")
				gotAuthorization = r.Header.Get("Authorization")
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(srv.Close)

			tt.credentials.Azure.Endpoint = srv.URL
			c := &client{
				pool: providers.NewHTTPClientPool(),
				tokenSource: func(_ context.Context, az *providers.Azure) (string, error) {
					return strings.ReplaceAll(string(azureAuthMode(az)), "_", "-") + "-token", nil
				},
			}

			result := c.TestConnection(context.Background(), &providers.Config{Credentials: tt.credentials})

			assert.True(t, result.OK)
			assert.Equal(t, tt.wantAPIKey, gotAPIKey)
			assert.Equal(t, tt.wantAuthorization, gotAuthorization)
		})
	}
}

func TestAzureCredential_ServicePrincipalValidation(t *testing.T) {
	_, err := azureCredential(&providers.Azure{AuthMode: providers.AzureAuthModeServicePrincipal})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "azure service principal requires")
}

func TestRawPost_RoundTrip(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("api-key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"az-1"}`))
	}))
	t.Cleanup(srv.Close)

	c := &client{pool: providers.NewHTTPClientPool()}
	resp, err := c.rawPost(context.Background(), srv.URL, authHeader{name: "api-key", value: "az-key"}, []byte(`{"model":"dep"}`))
	require.NoError(t, err)

	assert.Equal(t, "az-key", gotKey)
	assert.JSONEq(t, `{"id":"az-1"}`, string(resp))
}

func TestRawPost_BackendErrorPassthrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	t.Cleanup(srv.Close)

	c := &client{pool: providers.NewHTTPClientPool()}
	_, err := c.rawPost(context.Background(), srv.URL, authHeader{name: "api-key", value: "k"}, []byte(`{}`))
	require.Error(t, err)

	be, ok := registry.IsBackendError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, be.StatusCode)
}

package azure

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAzureClient(t *testing.T) {
	assert.NotNil(t, NewAzureClient())
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
		assert.Equal(t, "https://x.openai.azure.com/openai/deployments/gpt-4o/chat/completions?api-version=2024-05-01-preview", url)
	})

	t.Run("custom api version", func(t *testing.T) {
		cfg := &providers.Config{Credentials: providers.Credentials{Azure: &providers.Azure{Endpoint: "https://x.openai.azure.com", ApiVersion: "2025-01-01"}}}
		url := c.buildURL(cfg, "gpt-4o")
		assert.Equal(t, "https://x.openai.azure.com/openai/deployments/gpt-4o/chat/completions?api-version=2025-01-01", url)
	})
}

func TestApplyAuthHeader(t *testing.T) {
	c := &client{}

	t.Run("managed identity uses bearer", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, "http://x", nil)
		c.applyAuthHeader(req, true, "tok")
		assert.Equal(t, "Bearer tok", req.Header.Get("Authorization"))
		assert.Empty(t, req.Header.Get("api-key"))
	})

	t.Run("api key uses api-key header", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, "http://x", nil)
		c.applyAuthHeader(req, false, "tok")
		assert.Equal(t, "tok", req.Header.Get("api-key"))
		assert.Empty(t, req.Header.Get("Authorization"))
	})
}

func TestGetToken_NonIdentity(t *testing.T) {
	c := &client{}

	t.Run("returns api key", func(t *testing.T) {
		cfg := &providers.Config{Credentials: providers.Credentials{ApiKey: "key", Azure: &providers.Azure{}}}
		token, err := c.getToken(context.Background(), cfg)
		require.NoError(t, err)
		assert.Equal(t, "key", token)
	})

	t.Run("missing api key", func(t *testing.T) {
		cfg := &providers.Config{Credentials: providers.Credentials{Azure: &providers.Azure{}}}
		_, err := c.getToken(context.Background(), cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "API key is required")
	})
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
	resp, err := c.rawPost(context.Background(), srv.URL, "az-key", false, []byte(`{"model":"dep"}`))
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
	_, err := c.rawPost(context.Background(), srv.URL, "k", false, []byte(`{}`))
	require.Error(t, err)

	be, ok := backend.IsBackendError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, be.StatusCode)
}

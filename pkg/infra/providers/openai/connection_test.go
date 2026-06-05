package openai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveModelsURL(t *testing.T) {
	c := &client{}
	assert.Equal(t, modelsURL, c.resolveModelsURL(&providers.Config{}))
	assert.Equal(t,
		"https://host/v1/models",
		c.resolveModelsURL(&providers.Config{Options: map[string]any{"base_url": "https://host/v1/"}}),
	)
}

func TestTestConnection_MissingAPIKey(t *testing.T) {
	got := NewOpenaiClient().(*client).TestConnection(context.Background(), &providers.Config{})
	assert.False(t, got.OK)
	assert.Equal(t, providers.StageAuthentication, got.Stage)
}

func TestTestConnection_OK(t *testing.T) {
	var gotAuth, gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotMethod = r.Method
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	t.Cleanup(srv.Close)

	c := NewOpenaiClient().(*client)
	got := c.TestConnection(context.Background(), &providers.Config{
		Credentials: providers.Credentials{ApiKey: "sk-test"},
		Options:     map[string]any{"base_url": srv.URL},
	})

	assert.True(t, got.OK)
	assert.Equal(t, providers.StageAuthentication, got.Stage)
	assert.Equal(t, "Bearer sk-test", gotAuth)
	assert.Equal(t, "/models", gotPath)
	assert.Equal(t, http.MethodGet, gotMethod)
}

func TestTestConnection_AuthFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	c := NewOpenaiClient().(*client)
	got := c.TestConnection(context.Background(), &providers.Config{
		Credentials: providers.Credentials{ApiKey: "sk-bad"},
		Options:     map[string]any{"base_url": srv.URL},
	})

	assert.False(t, got.OK)
	assert.Equal(t, providers.StageAuthentication, got.Stage)
	require.Equal(t, http.StatusUnauthorized, got.StatusCode)
}

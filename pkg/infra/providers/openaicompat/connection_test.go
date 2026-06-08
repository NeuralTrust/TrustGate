package openaicompat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTestConnection_OK(t *testing.T) {
	var gotPath, gotAuth, gotCustom string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotCustom = r.Header.Get("X-Custom-Header")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	tester := NewClient().(providers.ConnectionTester)
	res := tester.TestConnection(context.Background(), &providers.Config{
		Credentials: providers.Credentials{ApiKey: "sk-test"},
		Options: map[string]any{
			"base_url": srv.URL + "/v1",
			"headers":  map[string]any{"X-Custom-Header": "custom-value"},
		},
	})

	require.True(t, res.OK)
	assert.Equal(t, "/v1/models", gotPath)
	assert.Equal(t, "Bearer sk-test", gotAuth)
	assert.Equal(t, "custom-value", gotCustom, "custom headers are applied to the probe too")
}

func TestTestConnection_MissingBaseURL(t *testing.T) {
	tester := NewClient().(providers.ConnectionTester)
	res := tester.TestConnection(context.Background(), &providers.Config{
		Credentials: providers.Credentials{ApiKey: "sk-test"},
	})
	assert.False(t, res.OK)
	assert.Contains(t, res.Message, "base_url is required")
}

func TestTestConnection_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	tester := NewClient().(providers.ConnectionTester)
	res := tester.TestConnection(context.Background(), &providers.Config{
		Credentials: providers.Credentials{ApiKey: "sk-bad"},
		Options:     map[string]any{"base_url": srv.URL},
	})
	assert.False(t, res.OK)
	assert.Equal(t, providers.StageAuthentication, res.Stage)
}

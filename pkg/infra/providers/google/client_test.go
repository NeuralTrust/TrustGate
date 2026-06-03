package google

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGoogleClient(t *testing.T) {
	assert.NotNil(t, NewGoogleClient())
}

func TestCompletions_MissingAPIKey(t *testing.T) {
	_, err := NewGoogleClient().Completions(context.Background(), &providers.Config{}, []byte(`{"model":"gemini-2.5-flash"}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestExtractModel(t *testing.T) {
	c := &client{}

	t.Run("from body", func(t *testing.T) {
		model, err := c.extractModel([]byte(`{"model":"gemini-2.5-flash"}`))
		require.NoError(t, err)
		assert.Equal(t, "gemini-2.5-flash", model)
	})

	t.Run("missing model", func(t *testing.T) {
		_, err := c.extractModel([]byte(`{}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "model is required")
	})
}

func TestReadBackendError(t *testing.T) {
	body := `{"error":{"code":429,"message":"Quota exceeded"}}`
	resp := &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{},
	}
	var err error = readBackendError(resp)

	be, ok := registry.IsBackendError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusTooManyRequests, be.StatusCode)
	assert.JSONEq(t, body, string(be.Body))
}

func TestRawPost_RoundTrip(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-goog-api-key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[]}`))
	}))
	t.Cleanup(srv.Close)

	c := &client{pool: providers.NewHTTPClientPool()}
	resp, err := c.rawPost(context.Background(), srv.URL, "goog-key", []byte(`{"contents":[]}`))
	require.NoError(t, err)

	assert.Equal(t, "goog-key", gotKey)
	assert.JSONEq(t, `{"candidates":[]}`, string(resp))
}

func TestRawPost_BackendErrorPassthrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"bad request"}`))
	}))
	t.Cleanup(srv.Close)

	c := &client{pool: providers.NewHTTPClientPool()}
	_, err := c.rawPost(context.Background(), srv.URL, "k", []byte(`{}`))
	require.Error(t, err)

	be, ok := registry.IsBackendError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, be.StatusCode)
}

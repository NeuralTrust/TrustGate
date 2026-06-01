package openai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/embedding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreator_Generate_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer key-123", r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"data":[{"embedding":[3.0,4.0]}]}`))
	}))
	defer srv.Close()

	c := NewCreator(WithBaseURL(srv.URL))
	emb, err := c.Generate(context.Background(), "hello", "text-embedding-ada-002", &embedding.Config{
		Credentials: embedding.Credentials{APIKey: "key-123"},
	})
	require.NoError(t, err)
	require.Len(t, emb.Value, 2)
	// 3,4 normalized -> 0.6, 0.8
	assert.InDelta(t, 0.6, emb.Value[0], 1e-9)
	assert.InDelta(t, 0.8, emb.Value[1], 1e-9)
}

func TestCreator_Generate_MissingAPIKey(t *testing.T) {
	c := NewCreator()
	_, err := c.Generate(context.Background(), "hi", "m", &embedding.Config{})
	require.Error(t, err)
}

func TestCreator_Generate_NonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewCreator(WithBaseURL(srv.URL))
	_, err := c.Generate(context.Background(), "hi", "m", &embedding.Config{Credentials: embedding.Credentials{APIKey: "k"}})
	require.ErrorIs(t, err, embedding.ErrProviderNonOKResponse)
}

func TestCreator_Generate_EmptyData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	c := NewCreator(WithBaseURL(srv.URL))
	_, err := c.Generate(context.Background(), "hi", "m", &embedding.Config{Credentials: embedding.Credentials{APIKey: "k"}})
	require.Error(t, err)
}

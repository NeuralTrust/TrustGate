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

package cohere

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCohereClient(t *testing.T) {
	assert.NotNil(t, NewCohereClient())
}

func TestCompletions_MissingAPIKey(t *testing.T) {
	_, err := NewCohereClient().Completions(context.Background(), &providers.Config{}, []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestEmbeddings_MissingAPIKey(t *testing.T) {
	c := NewCohereClient().(providers.EmbeddingsClient)
	_, err := c.Embeddings(context.Background(), &providers.Config{}, []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestRerank_MissingAPIKey(t *testing.T) {
	c := NewCohereClient().(providers.RerankClient)
	_, err := c.Rerank(context.Background(), &providers.Config{}, []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestRawPost_RoundTrip(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chat-1"}`))
	}))
	t.Cleanup(srv.Close)

	c := &client{pool: providers.NewHTTPClientPool()}
	resp, err := c.rawPost(context.Background(), srv.URL+"/v2/chat", "cohere-key", []byte(`{"model":"command-r-plus"}`))
	require.NoError(t, err)

	assert.Equal(t, "Bearer cohere-key", gotAuth)
	assert.Equal(t, "/v2/chat", gotPath)
	assert.JSONEq(t, `{"id":"chat-1"}`, string(resp))
}

func TestEmbeddings_RoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v2/embed", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"embeddings":[[0.1,0.2]]}`))
	}))
	t.Cleanup(srv.Close)

	c := NewCohereClient().(providers.EmbeddingsClient)
	resp, err := c.Embeddings(context.Background(), &providers.Config{
		Credentials: providers.Credentials{ApiKey: "cohere-key"},
		Options:     map[string]any{"base_url": srv.URL},
	}, []byte(`{"model":"embed-english-v3.0","texts":["hi"],"input_type":"search_document"}`))
	require.NoError(t, err)
	assert.JSONEq(t, `{"embeddings":[[0.1,0.2]]}`, string(resp))
}

func TestRerank_RoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v2/rerank", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"index":0,"relevance_score":0.9}]}`))
	}))
	t.Cleanup(srv.Close)

	c := NewCohereClient().(providers.RerankClient)
	resp, err := c.Rerank(context.Background(), &providers.Config{
		Credentials: providers.Credentials{ApiKey: "cohere-key"},
		Options:     map[string]any{"base_url": srv.URL},
	}, []byte(`{"model":"rerank-english-v3.0","query":"q","documents":["a"]}`))
	require.NoError(t, err)
	assert.JSONEq(t, `{"results":[{"index":0,"relevance_score":0.9}]}`, string(resp))
}

func TestRawPost_BackendErrorPassthrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"invalid key"}`))
	}))
	t.Cleanup(srv.Close)

	c := &client{pool: providers.NewHTTPClientPool()}
	_, err := c.rawPost(context.Background(), srv.URL, "bad", []byte(`{}`))
	require.Error(t, err)

	be, ok := registry.IsBackendError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, be.StatusCode)
	assert.JSONEq(t, `{"message":"invalid key"}`, string(be.Body))
}

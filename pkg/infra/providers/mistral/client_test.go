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

package mistral

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMistralClient(t *testing.T) {
	assert.NotNil(t, NewMistralClient())
}

func TestCompletions_MissingAPIKey(t *testing.T) {
	_, err := NewMistralClient().Completions(context.Background(), &providers.Config{}, []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestRawPost_RoundTrip(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl-1"}`))
	}))
	t.Cleanup(srv.Close)

	c := &client{pool: providers.NewHTTPClientPool()}
	resp, err := c.rawPost(context.Background(), srv.URL, "mistral-key", []byte(`{"model":"mistral-large"}`))
	require.NoError(t, err)

	assert.Equal(t, "Bearer mistral-key", gotAuth)
	assert.JSONEq(t, `{"id":"cmpl-1"}`, string(resp))
}

func TestRawPost_BackendErrorPassthrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid key"}`))
	}))
	t.Cleanup(srv.Close)

	c := &client{pool: providers.NewHTTPClientPool()}
	_, err := c.rawPost(context.Background(), srv.URL, "bad", []byte(`{}`))
	require.Error(t, err)

	be, ok := registry.IsBackendError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, be.StatusCode)
	assert.JSONEq(t, `{"error":"invalid key"}`, string(be.Body))
}

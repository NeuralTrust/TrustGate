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

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModelsURL_DefaultHost(t *testing.T) {
	got, err := modelsURL(nil)
	require.NoError(t, err)
	assert.Equal(t, "https://api.cohere.com/v1/models", got)
}

func TestModelsURL_CustomBaseURL(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)

	got, err := modelsURL(map[string]any{"base_url": srv.URL})
	require.NoError(t, err)
	assert.Equal(t, srv.URL+"/v1/models", got)
}

func TestTestConnection_MissingAPIKey(t *testing.T) {
	got := NewCohereClient().(*client).TestConnection(context.Background(), &providers.Config{})
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
		_, _ = w.Write([]byte(`{"models":[]}`))
	}))
	t.Cleanup(srv.Close)

	got := NewCohereClient().(*client).TestConnection(context.Background(), &providers.Config{
		Credentials: providers.Credentials{ApiKey: "cohere-key"},
		Options:     map[string]any{"base_url": srv.URL},
	})

	assert.True(t, got.OK)
	assert.Equal(t, "Bearer cohere-key", gotAuth)
	assert.Equal(t, "/v1/models", gotPath)
	assert.Equal(t, http.MethodGet, gotMethod)
}

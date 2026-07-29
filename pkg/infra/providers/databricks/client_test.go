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

package databricks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDatabricksClient(t *testing.T) {
	assert.NotNil(t, NewDatabricksClient())
}

func TestCompletions_MissingBaseURL(t *testing.T) {
	_, err := NewDatabricksClient().Completions(
		context.Background(),
		&providers.Config{Credentials: providers.Credentials{ApiKey: "token"}},
		[]byte(`{}`),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base_url is required")
}

func TestCompletions_InvocationsRoundTrip(t *testing.T) {
	const wantModel = "databricks-meta-llama-3-1-70b-instruct"
	var gotAuth, gotPath, gotModel string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		gotModel, _ = body["model"].(string)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"model": wantModel})
	}))
	t.Cleanup(srv.Close)

	baseURL := srv.URL + "/serving-endpoints/my-endpoint"
	resp, err := NewDatabricksClient().Completions(
		context.Background(),
		&providers.Config{
			Credentials: providers.Credentials{ApiKey: "databricks-token"},
			Options: map[string]any{
				"base_url": baseURL,
			},
		},
		[]byte(`{"model":"`+wantModel+`","messages":[{"role":"user","content":"hello"}]}`),
	)
	require.NoError(t, err)

	assert.Equal(t, "/serving-endpoints/my-endpoint/invocations", gotPath)
	assert.Equal(t, "Bearer databricks-token", gotAuth)
	assert.Equal(t, wantModel, gotModel)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(resp, &parsed))
	assert.Equal(t, wantModel, parsed["model"])
}

func TestTestConnection_MethodNotAllowedIsOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	result := NewDatabricksClient().(providers.ConnectionTester).TestConnection(
		context.Background(),
		&providers.Config{
			Credentials: providers.Credentials{ApiKey: "token"},
			Options: map[string]any{
				"base_url": srv.URL + "/serving-endpoints/demo",
			},
		},
	)
	assert.True(t, result.OK)
}

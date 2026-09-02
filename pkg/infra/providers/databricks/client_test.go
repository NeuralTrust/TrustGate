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

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func configFor(baseURL, apiKey string) *providers.Config {
	return &providers.Config{
		Credentials: providers.Credentials{ApiKey: apiKey},
		Options:     map[string]any{"base_url": baseURL},
	}
}

func TestNewDatabricksClient(t *testing.T) {
	assert.NotNil(t, NewDatabricksClient())
}

func TestInvocationsURL_AppendsPathAndTrimsSlash(t *testing.T) {
	for _, tc := range []struct{ base, want string }{
		{"https://dbc-1.cloud.databricks.com/serving-endpoints/llama", "https://dbc-1.cloud.databricks.com/serving-endpoints/llama/invocations"},
		{"https://dbc-1.cloud.databricks.com/serving-endpoints/llama/", "https://dbc-1.cloud.databricks.com/serving-endpoints/llama/invocations"},
	} {
		assert.Equal(t, tc.want, invocationsURL(providers.DatabricksOptions{BaseURL: tc.base}))
	}
}

func TestCompletions_MissingBaseURL(t *testing.T) {
	_, err := NewDatabricksClient().Completions(
		context.Background(),
		&providers.Config{Credentials: providers.Credentials{ApiKey: "pat"}},
		[]byte(`{}`),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base_url is required")
}

func TestCompletionsStream_MissingBaseURL(t *testing.T) {
	_, err := NewDatabricksClient().CompletionsStream(
		context.Background(),
		&providers.Config{Credentials: providers.Credentials{ApiKey: "pat"}},
		[]byte(`{}`),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base_url is required")
}

func TestCompletions_NonStreamingRoundTrip(t *testing.T) {
	const wantModel = "databricks-meta-llama-3-3-70b-instruct"
	var gotPath, gotAuth, gotModel string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		gotModel, _ = body["model"].(string)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model": wantModel,
			"usage": map[string]any{"total_tokens": 42},
		})
	}))
	t.Cleanup(srv.Close)

	resp, err := NewDatabricksClient().Completions(
		context.Background(),
		configFor(srv.URL+"/serving-endpoints/llama", "databricks-pat"),
		[]byte(`{"model":"`+wantModel+`","messages":[{"role":"user","content":"hello"}]}`),
	)
	require.NoError(t, err)

	assert.Equal(t, "/serving-endpoints/llama/invocations", gotPath)
	assert.Equal(t, "Bearer databricks-pat", gotAuth)
	assert.Equal(t, wantModel, gotModel)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(resp, &parsed))
	assert.Equal(t, wantModel, parsed["model"])
	assert.NotNil(t, parsed["usage"], "usage must survive verbatim passthrough")
}

func TestCompletionsStream_RoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/serving-endpoints/llama/invocations", r.URL.Path)
		assert.Equal(t, "Bearer databricks-pat", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	t.Cleanup(srv.Close)

	seq, err := NewDatabricksClient().CompletionsStream(
		context.Background(),
		configFor(srv.URL+"/serving-endpoints/llama", "databricks-pat"),
		[]byte(`{"model":"databricks-meta-llama-3-3-70b-instruct","stream":true}`),
	)
	require.NoError(t, err)

	var lines []string
	for line, lerr := range seq {
		require.NoError(t, lerr)
		lines = append(lines, string(line))
	}
	require.NotEmpty(t, lines)
	assert.Equal(t, `data: {"choices":[{"delta":{"content":"hi"}}]}`, lines[0])
	assert.Equal(t, `data: [DONE]`, lines[len(lines)-1])
}

func TestCompletions_CustomHeadersReachTheEndpoint(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Databricks-Org-Id")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	cfg := configFor(srv.URL+"/serving-endpoints/llama", "pat")
	cfg.Options["headers"] = map[string]string{"X-Databricks-Org-Id": "12345"}

	_, err := NewDatabricksClient().Completions(context.Background(), cfg, []byte(`{"model":"m"}`))
	require.NoError(t, err)
	assert.Equal(t, "12345", got)
}

func TestCompletions_RateLimitRetryAfter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "2")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"rate limit exceeded"}}`))
	}))
	t.Cleanup(srv.Close)

	_, err := NewDatabricksClient().Completions(
		context.Background(),
		configFor(srv.URL+"/serving-endpoints/llama", "pat"),
		[]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`),
	)
	require.Error(t, err)

	be, ok := registry.IsBackendError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusTooManyRequests, be.StatusCode)
	assert.Equal(t, "2", be.RetryAfter)
}

// /invocations is POST-only, so the GET probe's 405 is the success signal.
func TestTestConnection_MethodNotAllowedCountsAsReachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	t.Cleanup(srv.Close)

	res := NewDatabricksClient().(*client).TestConnection(
		context.Background(),
		configFor(srv.URL+"/serving-endpoints/llama", "pat"),
	)
	assert.True(t, res.OK)
	assert.Equal(t, providers.StageAuthentication, res.Stage)
}

func TestTestConnection_UnauthorizedIsReportedVerbatim(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	res := NewDatabricksClient().(*client).TestConnection(
		context.Background(),
		configFor(srv.URL+"/serving-endpoints/llama", "pat"),
	)
	assert.False(t, res.OK)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

func TestTestConnection_MissingBaseURL(t *testing.T) {
	res := NewDatabricksClient().(*client).TestConnection(
		context.Background(),
		&providers.Config{Credentials: providers.Credentials{ApiKey: "pat"}},
	)
	assert.False(t, res.OK)
	assert.Equal(t, providers.StageProvider, res.Stage)
	assert.Contains(t, res.Message, "base_url is required")
}

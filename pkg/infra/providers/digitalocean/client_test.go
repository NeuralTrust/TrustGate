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

package digitalocean

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testKey = "do-model-access-key"

func keyConfig() *providers.Config {
	return &providers.Config{Credentials: providers.Credentials{ApiKey: testKey}}
}

func TestCompletions_MissingAPIKey(t *testing.T) {
	_, err := NewDigitalOceanClient().Completions(context.Background(), &providers.Config{}, []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestCompletions_SendsTheSlugToChatCompletions(t *testing.T) {
	const slug = "anthropic-claude-5.5-haiku"
	var gotPath, gotAuth, gotModel string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		var body map[string]any
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		gotModel, _ = body["model"].(string)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"` + slug + `","choices":[],"usage":{"total_tokens":3}}`))
	}))
	t.Cleanup(srv.Close)

	resp, err := newClient(srv.URL+"/v1").Completions(
		context.Background(),
		keyConfig(),
		[]byte(`{"model":"`+slug+`","messages":[{"role":"user","content":"hi"}]}`),
	)
	require.NoError(t, err)

	assert.Equal(t, "/v1/chat/completions", gotPath)
	assert.Equal(t, "Bearer "+testKey, gotAuth)
	assert.Equal(t, slug, gotModel)
	assert.JSONEq(t, `{"model":"`+slug+`","choices":[],"usage":{"total_tokens":3}}`, string(resp))
}

func TestCompletionsStream_RelaysFramesUntilDone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/chat/completions", r.URL.Path)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	t.Cleanup(srv.Close)

	seq, err := newClient(srv.URL+"/v1").CompletionsStream(
		context.Background(),
		keyConfig(),
		[]byte(`{"model":"llama3.3-70b-instruct","stream":true}`),
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

func TestListLiveModels_ReturnsTheSlugs(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[
			{"id":"anthropic-claude-5.5-haiku","object":"model","owned_by":"anthropic"},
			{"id":"inference-router","object":"model","owned_by":"digitalocean"}
		]}`))
	}))
	t.Cleanup(srv.Close)

	models, err := newClient(srv.URL+"/v1").ListLiveModels(context.Background(), keyConfig())
	require.NoError(t, err)

	assert.Equal(t, "/v1/models", gotPath)
	assert.Equal(t, "Bearer "+testKey, gotAuth)
	ids := make([]string, 0, len(models))
	for _, m := range models {
		ids = append(ids, m.ID)
	}
	assert.Equal(t, []string{"anthropic-claude-5.5-haiku", "inference-router"}, ids)
}

func TestListLiveModels_RejectedKeyFallsBackToTheCatalog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	_, err := newClient(srv.URL+"/v1").ListLiveModels(context.Background(), keyConfig())
	require.Error(t, err)
	assert.True(t, errors.Is(err, providers.ErrModelListingFailed))
}

func TestTestConnection_ProbesTheModelsEndpoint(t *testing.T) {
	tests := []struct {
		name   string
		status int
		wantOK bool
	}{
		{name: "valid key", status: http.StatusOK, wantOK: true},
		{name: "rejected key", status: http.StatusUnauthorized, wantOK: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/models", r.URL.Path)
				assert.Equal(t, "Bearer "+testKey, r.Header.Get("Authorization"))
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"object":"list","data":[]}`))
			}))
			t.Cleanup(srv.Close)

			got := newClient(srv.URL+"/v1").TestConnection(context.Background(), keyConfig())
			assert.Equal(t, tc.wantOK, got.OK)
			assert.Equal(t, tc.status, got.StatusCode)
		})
	}
}

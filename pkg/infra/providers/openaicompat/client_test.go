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

package openaicompat

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

func TestNewClient(t *testing.T) {
	assert.NotNil(t, NewClient())
}

func TestCompletionsURL(t *testing.T) {
	assert.Equal(t,
		"https://host/v1/chat/completions",
		completionsURL(providers.OpenAICompatibleOptions{BaseURL: "https://host/v1"}),
	)
	assert.Equal(t,
		"https://host/v1/chat/completions",
		completionsURL(providers.OpenAICompatibleOptions{BaseURL: "https://host/v1/"}),
		"a trailing slash on base_url is tolerated",
	)
}

func TestEmbeddingsURL(t *testing.T) {
	assert.Equal(t,
		"https://host/v1/embeddings",
		embeddingsURL(providers.OpenAICompatibleOptions{BaseURL: "https://host/v1"}),
	)
	assert.Equal(t,
		"https://host/v1/embeddings",
		embeddingsURL(providers.OpenAICompatibleOptions{BaseURL: "https://host/v1/"}),
	)
}

func TestImages_MissingBaseURL(t *testing.T) {
	c := NewClient().(providers.ImagesClient)
	_, err := c.Images(
		context.Background(),
		&providers.Config{Credentials: providers.Credentials{ApiKey: "sk-test"}},
		providers.ImagesRequest{
			Method: http.MethodPost,
			Path:   "/v1/images/generations",
			Body:   []byte(`{"model":"dall-e-3","prompt":"a cat"}`),
		},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base_url is required")
}

func TestImages_RoundTrip(t *testing.T) {
	var gotAuth, gotPath, gotHeader string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotHeader = r.Header.Get("X-Custom-Header")
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"created":1,"data":[{"b64_json":"abc"}]}`))
	}))
	t.Cleanup(srv.Close)

	c := NewClient().(providers.ImagesClient)
	result, err := c.Images(context.Background(), &providers.Config{
		Credentials: providers.Credentials{ApiKey: "sk-test"},
		Options: map[string]any{
			"base_url": srv.URL + "/v1",
			"headers":  map[string]any{"X-Custom-Header": "yes"},
		},
	}, providers.ImagesRequest{
		Method:      http.MethodPost,
		Path:        "/v1/images/generations",
		ContentType: "application/json",
		Body:        []byte(`{"model":"dall-e-3","prompt":"a cat"}`),
	})
	require.NoError(t, err)
	assert.Equal(t, "Bearer sk-test", gotAuth)
	assert.Equal(t, "/v1/images/generations", gotPath)
	assert.Equal(t, "yes", gotHeader)
	assert.Equal(t, "dall-e-3", gotBody["model"])
	assert.JSONEq(t, `{"created":1,"data":[{"b64_json":"abc"}]}`, string(result.Body))
}

func TestEmbeddings_MissingBaseURL(t *testing.T) {
	c := NewClient().(providers.EmbeddingsClient)
	_, err := c.Embeddings(
		context.Background(),
		&providers.Config{Credentials: providers.Credentials{ApiKey: "sk-test"}},
		[]byte(`{}`),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base_url is required")
}

func TestEmbeddings_RoundTrip(t *testing.T) {
	var gotAuth, gotPath, gotHeader string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotHeader = r.Header.Get("X-Custom-Header")
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"index":0,"embedding":[0.2]}]}`))
	}))
	t.Cleanup(srv.Close)

	c := NewClient().(providers.EmbeddingsClient)
	resp, err := c.Embeddings(
		context.Background(),
		&providers.Config{
			Credentials: providers.Credentials{ApiKey: "sk-test"},
			Options: map[string]any{
				"base_url": srv.URL + "/v1",
				"headers":  map[string]any{"X-Custom-Header": "custom-value"},
			},
		},
		[]byte(`{"model":"nomic-embed","input":["hi"]}`),
	)
	require.NoError(t, err)

	assert.Equal(t, "Bearer sk-test", gotAuth)
	assert.Equal(t, "/v1/embeddings", gotPath)
	assert.Equal(t, "custom-value", gotHeader)
	assert.Equal(t, "nomic-embed", gotBody["model"])
	assert.JSONEq(t, `{"object":"list","data":[{"index":0,"embedding":[0.2]}]}`, string(resp))
}

func TestCompletions_MissingBaseURL(t *testing.T) {
	_, err := NewClient().Completions(
		context.Background(),
		&providers.Config{Credentials: providers.Credentials{ApiKey: "sk-test"}},
		[]byte(`{}`),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base_url is required")
}

func TestCompletions_RoundTrip(t *testing.T) {
	var gotAuth, gotPath string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-1","object":"chat.completion"}`))
	}))
	t.Cleanup(srv.Close)

	resp, err := NewClient().Completions(
		context.Background(),
		&providers.Config{
			Credentials: providers.Credentials{ApiKey: "sk-test"},
			Options:     map[string]any{"base_url": srv.URL + "/v1"},
		},
		[]byte(`{"model":"llama-3","messages":[{"role":"user","content":"hi"}]}`),
	)
	require.NoError(t, err)

	assert.Equal(t, "Bearer sk-test", gotAuth)
	assert.Equal(t, "/v1/chat/completions", gotPath)
	assert.Equal(t, "llama-3", gotBody["model"])
	assert.JSONEq(t, `{"id":"chatcmpl-1","object":"chat.completion"}`, string(resp))
}

func TestCompletions_CustomHeaders(t *testing.T) {
	var gotHeader, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Custom-Header")
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	_, err := NewClient().Completions(
		context.Background(),
		&providers.Config{
			Credentials: providers.Credentials{ApiKey: "sk-test"},
			Options: map[string]any{
				"base_url": srv.URL + "/v1",
				"headers":  map[string]any{"X-Custom-Header": "custom-value"},
			},
		},
		[]byte(`{"model":"llama-3"}`),
	)
	require.NoError(t, err)

	assert.Equal(t, "custom-value", gotHeader)
	assert.Equal(t, "Bearer sk-test", gotAuth, "default Authorization still applied when not overridden")
}

func TestCompletions_CustomHeaderOverridesAuth(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	_, err := NewClient().Completions(
		context.Background(),
		&providers.Config{
			Credentials: providers.Credentials{ApiKey: "sk-test"},
			Options: map[string]any{
				"base_url": srv.URL,
				"headers":  map[string]any{"Authorization": "Token abc123"},
			},
		},
		[]byte(`{}`),
	)
	require.NoError(t, err)
	assert.Equal(t, "Token abc123", gotAuth, "custom headers are applied last and override defaults")
}

func TestCompletions_CustomAuthorizationWithoutAPIKey(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	_, err := NewClient().Completions(
		context.Background(),
		&providers.Config{
			Options: map[string]any{
				"base_url": srv.URL,
				"headers":  map[string]any{"Authorization": "Token abc123"},
			},
		},
		[]byte(`{}`),
	)
	require.NoError(t, err)
	assert.Equal(t, "Token abc123", gotAuth, "a custom Authorization header authenticates without a bearer api key")
}

func TestCompletions_NoCredentials(t *testing.T) {
	_, err := NewClient().Completions(
		context.Background(),
		&providers.Config{Options: map[string]any{"base_url": "https://host/v1"}},
		[]byte(`{}`),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestCompletions_InvalidBaseURL(t *testing.T) {
	_, err := NewClient().Completions(
		context.Background(),
		&providers.Config{
			Credentials: providers.Credentials{ApiKey: "sk-test"},
			Options:     map[string]any{"base_url": "host/v1"},
		},
		[]byte(`{}`),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base_url")
}

func TestCompletionsStream_RoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer sk-test", r.Header.Get("Authorization"))
		assert.Equal(t, "/v1/chat/completions", r.URL.Path)
		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n"))
		if fl != nil {
			fl.Flush()
		}
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	t.Cleanup(srv.Close)

	seq, err := NewClient().CompletionsStream(
		context.Background(),
		&providers.Config{
			Credentials: providers.Credentials{ApiKey: "sk-test"},
			Options:     map[string]any{"base_url": srv.URL + "/v1"},
		},
		[]byte(`{"model":"llama-3","stream":true}`),
	)
	require.NoError(t, err)

	var lines []string
	for line, err := range seq {
		require.NoError(t, err)
		lines = append(lines, string(line))
	}
	require.NotEmpty(t, lines)
	assert.Equal(t, `data: {"choices":[{"delta":{"content":"hi"}}]}`, lines[0])
	assert.Equal(t, `data: [DONE]`, lines[len(lines)-1])
}

func TestCompletionsStream_MissingBaseURL(t *testing.T) {
	seq, err := NewClient().CompletionsStream(
		context.Background(),
		&providers.Config{Credentials: providers.Credentials{ApiKey: "sk-test"}},
		[]byte(`{"stream":true}`),
	)
	require.Error(t, err)
	assert.Nil(t, seq)
	assert.Contains(t, err.Error(), "base_url is required")
}

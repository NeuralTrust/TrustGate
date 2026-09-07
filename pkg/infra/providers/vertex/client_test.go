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

package vertex

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewVertexClient(t *testing.T) {
	assert.NotNil(t, NewVertexClient())
}

func TestBuildVertexURL(t *testing.T) {
	opts := providers.VertexOptions{Project: "my-proj", Location: "us-central1", Version: "v1"}

	assert.Equal(t,
		"https://us-central1-aiplatform.googleapis.com/v1/projects/my-proj/locations/us-central1/publishers/google/models/gemini-2.5-flash:generateContent",
		buildVertexURL(opts, "gemini-2.5-flash", "generateContent"),
	)
	assert.Equal(t,
		"https://us-central1-aiplatform.googleapis.com/v1/projects/my-proj/locations/us-central1/publishers/google/models/gemini-2.5-flash:streamGenerateContent?alt=sse",
		buildVertexURL(opts, "gemini-2.5-flash", "streamGenerateContent"),
	)
}

func TestBuildVertexURLGlobalEndpoint(t *testing.T) {
	opts := providers.VertexOptions{Project: "my-proj", Location: "global", Version: "v1"}

	assert.Equal(t,
		"https://aiplatform.googleapis.com/v1/projects/my-proj/locations/global/publishers/google/models/gemini-2.5-flash:generateContent",
		buildVertexURL(opts, "gemini-2.5-flash", "generateContent"),
		"the global endpoint has no region prefix in the host",
	)
	assert.Equal(t,
		"https://aiplatform.googleapis.com/v1/projects/my-proj/locations/global/publishers/google/models/gemini-2.5-flash:streamGenerateContent?alt=sse",
		buildVertexURL(opts, "gemini-2.5-flash", "streamGenerateContent"),
	)
}

func TestVertexHost(t *testing.T) {
	assert.Equal(t, "aiplatform.googleapis.com", vertexHost("global"))
	assert.Equal(t, "europe-west1-aiplatform.googleapis.com", vertexHost("europe-west1"))
}

func TestResolveModel(t *testing.T) {
	tests := []struct {
		name       string
		reqBody    string
		model      string
		defaultMdl string
		allowed    []string
		wantModel  string
		wantErr    bool
	}{
		{name: "model from config", reqBody: `{}`, model: "gemini-2.5-flash", wantModel: "gemini-2.5-flash"},
		{name: "model from default", reqBody: `{}`, defaultMdl: "gemini-2.5-pro", wantModel: "gemini-2.5-pro"},
		{name: "model from body", reqBody: `{"model": "gemini-2.5-flash"}`, wantModel: "gemini-2.5-flash"},
		{name: "no model anywhere", reqBody: `{}`, wantErr: true},
		{name: "model not allowed", reqBody: `{}`, model: "gemini-2.5-flash", allowed: []string{"gemini-2.5-pro"}, wantErr: true},
		{name: "model allowed", reqBody: `{}`, model: "gemini-2.5-flash", allowed: []string{"gemini-2.5-flash"}, wantModel: "gemini-2.5-flash"},
		{name: "config priority over body", reqBody: `{"model": "body"}`, model: "config", wantModel: "config"},
		{name: "empty allowed means all allowed", reqBody: `{}`, model: "any", allowed: []string{}, wantModel: "any"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model, err := resolveModel([]byte(tt.reqBody), &providers.Config{
				Model:         tt.model,
				DefaultModel:  tt.defaultMdl,
				AllowedModels: tt.allowed,
			})
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantModel, model)
		})
	}
}

func TestResolveAction(t *testing.T) {
	assert.Equal(t, "generateContent", resolveAction(nil, false))
	assert.Equal(t, "streamGenerateContent", resolveAction(nil, true))
	assert.Equal(t, "embedContent", resolveAction(map[string]any{"action": "embedContent"}, false))
	assert.Equal(t, "countTokens", resolveAction(map[string]any{"action": "countTokens"}, true))
	assert.Equal(t, "streamGenerateContent", resolveAction(map[string]any{"action": "generateContent"}, true))
	assert.Equal(t, "generateContent", resolveAction(map[string]any{"action": ""}, false))
}

func TestIsModelAllowed(t *testing.T) {
	assert.True(t, isModelAllowed("a", []string{"a", "b"}))
	assert.False(t, isModelAllowed("c", []string{"a", "b"}))
	assert.False(t, isModelAllowed("a", []string{}))
}

func TestBuildRequestURL(t *testing.T) {
	c := &client{}

	t.Run("credentials are not needed to build the URL", func(t *testing.T) {
		cfg := &providers.Config{
			Model:   "gemini-2.5-flash",
			Options: map[string]any{"project": "p", "location": "us-central1"},
		}
		_, err := c.buildRequestURL(cfg, []byte(`{}`), false)
		require.NoError(t, err)
	})

	t.Run("missing project", func(t *testing.T) {
		cfg := &providers.Config{
			Credentials: providers.Credentials{ApiKey: "tok"},
			Model:       "m",
			Options:     map[string]any{"location": "l"},
		}
		_, err := c.buildRequestURL(cfg, []byte(`{}`), false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "project")
	})

	t.Run("global location", func(t *testing.T) {
		cfg := &providers.Config{
			Credentials: providers.Credentials{ApiKey: "tok"},
			Model:       "gemini-2.5-flash",
			Options:     map[string]any{"project": "p", "location": "global"},
		}
		url, err := c.buildRequestURL(cfg, []byte(`{}`), false)
		require.NoError(t, err)
		assert.Equal(t,
			"https://aiplatform.googleapis.com/v1/projects/p/locations/global/publishers/google/models/gemini-2.5-flash:generateContent",
			url,
		)
	})

	t.Run("location casing is normalized", func(t *testing.T) {
		cfg := &providers.Config{
			Credentials: providers.Credentials{ApiKey: "tok"},
			Model:       "gemini-2.5-flash",
			Options:     map[string]any{"project": "p", "location": " Europe-West1 "},
		}
		url, err := c.buildRequestURL(cfg, []byte(`{}`), false)
		require.NoError(t, err)
		assert.Equal(t,
			"https://europe-west1-aiplatform.googleapis.com/v1/projects/p/locations/europe-west1/publishers/google/models/gemini-2.5-flash:generateContent",
			url,
		)
	})

	t.Run("full pipeline non-streaming", func(t *testing.T) {
		cfg := &providers.Config{
			Credentials: providers.Credentials{ApiKey: "tok"},
			Model:       "gemini-2.5-flash",
			Options:     map[string]any{"project": "p", "location": "us-central1"},
		}
		url, err := c.buildRequestURL(cfg, []byte(`{}`), false)
		require.NoError(t, err)
		assert.Equal(t,
			"https://us-central1-aiplatform.googleapis.com/v1/projects/p/locations/us-central1/publishers/google/models/gemini-2.5-flash:generateContent",
			url,
		)
	})
}

func TestEmbeddingsAction(t *testing.T) {
	assert.Equal(t, embedAction, embeddingsAction([]byte(`{"content":{"parts":[{"text":"hi"}]}}`)))
	assert.Equal(t, batchEmbedAction, embeddingsAction([]byte(`{"requests":[{"content":{"parts":[{"text":"a"}]}}]}`)))
	assert.Equal(t, embedAction, embeddingsAction([]byte(`{}`)))
}

func TestBuildEmbeddingsURL(t *testing.T) {
	c := &client{}
	cfg := &providers.Config{
		Model: "text-embedding-004",
		Options: map[string]any{
			"project":  "p",
			"location": "us-central1",
		},
	}

	t.Run("single input uses embedContent and ignores chat action", func(t *testing.T) {
		cfg.Options["action"] = "generateContent"
		url, err := c.buildEmbeddingsURL(cfg, []byte(`{"content":{"parts":[{"text":"hi"}]}}`))
		require.NoError(t, err)
		assert.Equal(t,
			"https://us-central1-aiplatform.googleapis.com/v1/projects/p/locations/us-central1/publishers/google/models/text-embedding-004:embedContent",
			url,
		)
	})

	t.Run("batch uses batchEmbedContents", func(t *testing.T) {
		url, err := c.buildEmbeddingsURL(cfg, []byte(`{"requests":[{"content":{"parts":[{"text":"a"}]}}]}`))
		require.NoError(t, err)
		assert.True(t, strings.HasSuffix(url, ":batchEmbedContents"))
	})

	t.Run("optional base_url is embeddings-only", func(t *testing.T) {
		cfg := &providers.Config{
			Model: "text-embedding-004",
			Options: map[string]any{
				"project":  "p",
				"location": "us-central1",
				"base_url": "http://127.0.0.1:9/v1",
			},
		}
		url, err := c.buildEmbeddingsURL(cfg, []byte(`{"content":{"parts":[{"text":"hi"}]}}`))
		require.NoError(t, err)
		assert.Equal(t, "http://127.0.0.1:9/v1/text-embedding-004:embedContent", url)

		chatURL, err := c.buildRequestURL(cfg, []byte(`{}`), false)
		require.NoError(t, err)
		assert.Contains(t, chatURL, "aiplatform.googleapis.com")
		assert.Contains(t, chatURL, ":generateContent")
	})
}

func TestEmbeddings_RoundTrip(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"embedding":{"values":[0.1,0.2]}}`))
	}))
	t.Cleanup(srv.Close)

	c := NewVertexClient().(providers.EmbeddingsClient)
	resp, err := c.Embeddings(context.Background(), &providers.Config{
		Credentials: providers.Credentials{ApiKey: "tok"},
		Model:       "text-embedding-004",
		Options: map[string]any{
			"project":  "p",
			"location": "us-central1",
			"base_url": srv.URL,
			"action":   "generateContent",
		},
	}, []byte(`{"content":{"parts":[{"text":"hi"}]}}`))
	require.NoError(t, err)
	assert.Equal(t, "Bearer tok", gotAuth)
	assert.Equal(t, "/text-embedding-004:embedContent", gotPath)
	assert.JSONEq(t, `{"embedding":{"values":[0.1,0.2]}}`, string(resp))
}

func TestEmbeddings_MissingProject(t *testing.T) {
	c := NewVertexClient().(providers.EmbeddingsClient)
	_, err := c.Embeddings(context.Background(), &providers.Config{
		Credentials: providers.Credentials{ApiKey: "tok"},
		Model:       "text-embedding-004",
		Options:     map[string]any{"location": "us-central1"},
	}, []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project")
}

func TestReadBackendError(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Body:       io.NopCloser(strings.NewReader(`{"error":{"message":"Quota exceeded"}}`)),
		Header:     http.Header{},
	}
	var err error = readBackendError(resp)

	be, ok := registry.IsBackendError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusTooManyRequests, be.StatusCode)
	assert.Contains(t, string(be.Body), "Quota exceeded")
}

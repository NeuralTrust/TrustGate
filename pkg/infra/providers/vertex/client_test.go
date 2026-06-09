package vertex

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
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

	t.Run("missing credentials", func(t *testing.T) {
		_, err := c.buildRequestURL(&providers.Config{}, []byte(`{}`), false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bearer token")
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

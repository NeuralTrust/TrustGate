package vertex

import (
	"io"
	"net/http"
	"strings"
	"testing"

	domainUpstream "github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseOptions(t *testing.T) {
	tests := []struct {
		name     string
		opts     map[string]any
		wantOpts vertexOptions
		wantErr  bool
	}{
		{
			name: "valid options",
			opts: map[string]any{
				"project":  "my-proj",
				"location": "us-central1",
			},
			wantOpts: vertexOptions{
				Project:  "my-proj",
				Location: "us-central1",
				Version:  "v1",
			},
		},
		{
			name: "custom version",
			opts: map[string]any{
				"project":  "p",
				"location": "eu-west1",
				"version":  "v1beta1",
			},
			wantOpts: vertexOptions{
				Project:  "p",
				Location: "eu-west1",
				Version:  "v1beta1",
			},
		},
		{
			name:    "missing project",
			opts:    map[string]any{"location": "us-central1"},
			wantErr: true,
		},
		{
			name:    "missing location",
			opts:    map[string]any{"project": "p"},
			wantErr: true,
		},
		{
			name:    "nil options",
			opts:    nil,
			wantErr: true,
		},
		{
			name:    "empty options",
			opts:    map[string]any{},
			wantErr: true,
		},
		{
			name: "project wrong type",
			opts: map[string]any{
				"project":  123,
				"location": "us-central1",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseOptions(tt.opts)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantOpts, got)
		})
	}
}

func TestBuildVertexURL(t *testing.T) {
	tests := []struct {
		name    string
		opts    vertexOptions
		model   string
		action  string
		wantURL string
	}{
		{
			name: "generateContent non-streaming",
			opts: vertexOptions{
				Project:  "my-proj",
				Location: "us-central1",
				Version:  "v1",
			},
			model:   "gemini-2.5-flash",
			action:  "generateContent",
			wantURL: "https://us-central1-aiplatform.googleapis.com/v1/projects/my-proj/locations/us-central1/publishers/google/models/gemini-2.5-flash:generateContent",
		},
		{
			name: "streamGenerateContent appends alt=sse",
			opts: vertexOptions{
				Project:  "my-proj",
				Location: "us-central1",
				Version:  "v1",
			},
			model:   "gemini-2.5-flash",
			action:  "streamGenerateContent",
			wantURL: "https://us-central1-aiplatform.googleapis.com/v1/projects/my-proj/locations/us-central1/publishers/google/models/gemini-2.5-flash:streamGenerateContent?alt=sse",
		},
		{
			name: "embedContent non-streaming",
			opts: vertexOptions{
				Project:  "my-proj",
				Location: "us-central1",
				Version:  "v1",
			},
			model:   "gemini-embedding-001",
			action:  "embedContent",
			wantURL: "https://us-central1-aiplatform.googleapis.com/v1/projects/my-proj/locations/us-central1/publishers/google/models/gemini-embedding-001:embedContent",
		},
		{
			name: "predict v1beta1",
			opts: vertexOptions{
				Project:  "another-proj",
				Location: "europe-west4",
				Version:  "v1beta1",
			},
			model:   "gemini-2.5-flash",
			action:  "predict",
			wantURL: "https://europe-west4-aiplatform.googleapis.com/v1beta1/projects/another-proj/locations/europe-west4/publishers/google/models/gemini-2.5-flash:predict",
		},
		{
			name: "countTokens",
			opts: vertexOptions{
				Project:  "p",
				Location: "us-east1",
				Version:  "v1",
			},
			model:   "gemini-2.5-flash",
			action:  "countTokens",
			wantURL: "https://us-east1-aiplatform.googleapis.com/v1/projects/p/locations/us-east1/publishers/google/models/gemini-2.5-flash:countTokens",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildVertexURL(tt.opts, tt.model, tt.action)
			assert.Equal(t, tt.wantURL, got)
		})
	}
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
		{
			name:      "model from config",
			reqBody:   `{}`,
			model:     "gemini-2.5-flash",
			wantModel: "gemini-2.5-flash",
		},
		{
			name:       "model from default",
			reqBody:    `{}`,
			defaultMdl: "gemini-2.5-pro",
			wantModel:  "gemini-2.5-pro",
		},
		{
			name:      "model from body",
			reqBody:   `{"model": "gemini-2.5-flash"}`,
			wantModel: "gemini-2.5-flash",
		},
		{
			name:    "no model anywhere",
			reqBody: `{}`,
			wantErr: true,
		},
		{
			name:    "model not allowed",
			reqBody: `{}`,
			model:   "gemini-2.5-flash",
			allowed: []string{"gemini-2.5-pro"},
			wantErr: true,
		},
		{
			name:      "model allowed",
			reqBody:   `{}`,
			model:     "gemini-2.5-flash",
			allowed:   []string{"gemini-2.5-flash", "gemini-2.5-pro"},
			wantModel: "gemini-2.5-flash",
		},
		{
			name:      "config model takes priority over body",
			reqBody:   `{"model": "body-model"}`,
			model:     "config-model",
			wantModel: "config-model",
		},
		{
			name:      "empty allowed list means all allowed",
			reqBody:   `{}`,
			model:     "any-model",
			allowed:   []string{},
			wantModel: "any-model",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &providers.Config{
				Model:         tt.model,
				DefaultModel:  tt.defaultMdl,
				AllowedModels: tt.allowed,
			}
			model, err := resolveModel([]byte(tt.reqBody), config)
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
	tests := []struct {
		name       string
		options    map[string]any
		stream     bool
		wantAction string
	}{
		{
			name:       "default non-streaming",
			options:    nil,
			stream:     false,
			wantAction: "generateContent",
		},
		{
			name:       "default streaming promotes to stream action",
			options:    nil,
			stream:     true,
			wantAction: "streamGenerateContent",
		},
		{
			name:       "explicit action non-streaming",
			options:    map[string]any{"action": "embedContent"},
			stream:     false,
			wantAction: "embedContent",
		},
		{
			name:       "explicit action kept even when streaming",
			options:    map[string]any{"action": "countTokens"},
			stream:     true,
			wantAction: "countTokens",
		},
		{
			name:       "explicit generateContent promoted when streaming",
			options:    map[string]any{"action": "generateContent"},
			stream:     true,
			wantAction: "streamGenerateContent",
		},
		{
			name:       "empty action string uses default",
			options:    map[string]any{"action": ""},
			stream:     false,
			wantAction: "generateContent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveAction(tt.options, tt.stream)
			assert.Equal(t, tt.wantAction, got)
		})
	}
}

func TestReadUpstreamError(t *testing.T) {
	t.Run("returns UpstreamError with status and body", func(t *testing.T) {
		body := `{"error":{"code":429,"message":"Quota exceeded","status":"RESOURCE_EXHAUSTED"}}`
		resp := &http.Response{
			StatusCode: 429,
			Body:       io.NopCloser(strings.NewReader(body)),
		}
		ue := readUpstreamError(resp)
		assert.Equal(t, 429, ue.StatusCode)
		assert.Contains(t, string(ue.Body), "Quota exceeded")
	})

	t.Run("preserves raw body for passthrough", func(t *testing.T) {
		body := `some raw error text`
		resp := &http.Response{
			StatusCode: 500,
			Body:       io.NopCloser(strings.NewReader(body)),
		}
		ue := readUpstreamError(resp)
		assert.Equal(t, 500, ue.StatusCode)
		assert.Equal(t, body, string(ue.Body))
	})

	t.Run("satisfies IsUpstreamError", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 400,
			Body:       io.NopCloser(strings.NewReader(`{"error":"bad"}`)),
		}
		var err error = readUpstreamError(resp)
		ue, ok := domainUpstream.IsUpstreamError(err)
		require.True(t, ok)
		assert.Equal(t, 400, ue.StatusCode)
	})
}

func TestIsModelAllowed(t *testing.T) {
	assert.True(t, isModelAllowed("a", []string{"a", "b"}))
	assert.False(t, isModelAllowed("c", []string{"a", "b"}))
	assert.False(t, isModelAllowed("a", []string{}))
}

func TestBuildRequestURL(t *testing.T) {
	c := &client{}

	t.Run("missing credentials", func(t *testing.T) {
		config := &providers.Config{}
		_, err := c.buildRequestURL(config, []byte(`{}`), false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bearer token")
	})

	t.Run("missing project", func(t *testing.T) {
		config := &providers.Config{
			Credentials: providers.Credentials{ApiKey: "tok"},
			Model:       "m",
			Options:     map[string]any{"location": "l"},
		}
		_, err := c.buildRequestURL(config, []byte(`{}`), false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "project")
	})

	t.Run("full pipeline non-streaming", func(t *testing.T) {
		config := &providers.Config{
			Credentials: providers.Credentials{ApiKey: "tok"},
			Model:       "gemini-2.5-flash",
			Options:     map[string]any{"project": "p", "location": "us-central1"},
		}
		url, err := c.buildRequestURL(config, []byte(`{}`), false)
		require.NoError(t, err)
		assert.Equal(t,
			"https://us-central1-aiplatform.googleapis.com/v1/projects/p/locations/us-central1/publishers/google/models/gemini-2.5-flash:generateContent",
			url,
		)
	})

	t.Run("full pipeline streaming", func(t *testing.T) {
		config := &providers.Config{
			Credentials: providers.Credentials{ApiKey: "tok"},
			Model:       "gemini-2.5-flash",
			Options:     map[string]any{"project": "p", "location": "us-central1"},
		}
		url, err := c.buildRequestURL(config, []byte(`{}`), true)
		require.NoError(t, err)
		assert.Equal(t,
			"https://us-central1-aiplatform.googleapis.com/v1/projects/p/locations/us-central1/publishers/google/models/gemini-2.5-flash:streamGenerateContent?alt=sse",
			url,
		)
	})
}

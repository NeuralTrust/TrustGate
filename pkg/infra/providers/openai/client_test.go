package openai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func collectStreamLines(t *testing.T, seq func(func([]byte, error) bool)) []string {
	t.Helper()
	var lines []string
	for line, err := range seq {
		require.NoError(t, err)
		lines = append(lines, string(line))
	}
	return lines
}

func TestNewOpenaiClient(t *testing.T) {
	assert.NotNil(t, NewOpenaiClient())
}

func TestParseOptions(t *testing.T) {
	tests := []struct {
		name    string
		options map[string]any
		wantAPI string
	}{
		{name: "no options defaults to completions", options: nil, wantAPI: CompletionsAPI},
		{name: "explicit completions", options: map[string]any{"api": "completions"}, wantAPI: CompletionsAPI},
		{name: "responses api", options: map[string]any{"api": "responses"}, wantAPI: ResponsesAPI},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseOptions(&providers.Config{Options: tt.options})
			assert.Equal(t, tt.wantAPI, got.API)
		})
	}
}

func TestResolveURL(t *testing.T) {
	c := &client{}
	assert.Equal(t, completionsURL, c.resolveURL(&providers.Config{}))
	assert.Equal(t, responsesURL, c.resolveURL(&providers.Config{Options: map[string]any{"api": "responses"}}))

	// base_url overrides the host for OpenAI-compatible endpoints; the endpoint
	// path is appended and a trailing slash on the base is tolerated.
	assert.Equal(t,
		"http://127.0.0.1:9999/chat/completions",
		c.resolveURL(&providers.Config{Options: map[string]any{"base_url": "http://127.0.0.1:9999"}}),
	)
	assert.Equal(t,
		"https://host/v1/chat/completions",
		c.resolveURL(&providers.Config{Options: map[string]any{"base_url": "https://host/v1/"}}),
	)
	assert.Equal(t,
		"https://host/v1/responses",
		c.resolveURL(&providers.Config{Options: map[string]any{"api": "responses", "base_url": "https://host/v1"}}),
	)
}

func TestChatCompletions_MissingAPIKey(t *testing.T) {
	chat := NewChatCompletionsClient(providers.ProviderOpenAI, nil)
	_, err := chat.Completions(context.Background(), "http://example.invalid", &providers.Config{}, []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestChatCompletions_RoundTrip(t *testing.T) {
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

	chat := NewChatCompletionsClient(providers.ProviderOpenAI, nil)
	resp, err := chat.Completions(
		context.Background(),
		srv.URL+"/v1/chat/completions",
		&providers.Config{Credentials: providers.Credentials{ApiKey: "sk-test"}},
		[]byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`),
	)
	require.NoError(t, err)

	assert.Equal(t, "Bearer sk-test", gotAuth)
	assert.Equal(t, "/v1/chat/completions", gotPath)
	assert.Equal(t, "gpt-4", gotBody["model"])
	assert.JSONEq(t, `{"id":"chatcmpl-1","object":"chat.completion"}`, string(resp))
}

func TestCompletionsStream_RoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer sk-test", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n"))
		if fl != nil {
			fl.Flush()
		}
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	t.Cleanup(srv.Close)

	chat := NewChatCompletionsClient(providers.ProviderOpenAI, nil)
	seq, err := chat.CompletionsStream(
		context.Background(),
		srv.URL,
		&providers.Config{Credentials: providers.Credentials{ApiKey: "sk-test"}},
		[]byte(`{"model":"gpt-4","stream":true}`),
	)
	require.NoError(t, err)

	lines := collectStreamLines(t, seq)
	require.NotEmpty(t, lines)
	assert.Equal(t, `data: {"choices":[{"delta":{"content":"hi"}}]}`, lines[0])
	assert.Equal(t, `data: [DONE]`, lines[len(lines)-1])
}

func TestCompletionsStream_BackendErrorPassthrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "3")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"rate limited"}}`))
	}))
	t.Cleanup(srv.Close)

	chat := NewChatCompletionsClient(providers.ProviderOpenAI, nil)
	seq, err := chat.CompletionsStream(
		context.Background(),
		srv.URL,
		&providers.Config{Credentials: providers.Credentials{ApiKey: "sk-test"}},
		[]byte(`{"model":"gpt-4","stream":true}`),
	)
	require.Error(t, err)
	assert.Nil(t, seq, "no stream must be opened on a non-2xx response")

	be, ok := registry.IsBackendError(err)
	require.True(t, ok, "expected a BackendError")
	assert.Equal(t, http.StatusTooManyRequests, be.StatusCode)
	assert.Equal(t, "3", be.RetryAfter)
	assert.JSONEq(t, `{"error":{"message":"rate limited"}}`, string(be.Body))
}

func TestChatCompletions_BackendErrorPassthrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"rate limited"}}`))
	}))
	t.Cleanup(srv.Close)

	chat := NewChatCompletionsClient(providers.ProviderOpenAI, nil)
	_, err := chat.Completions(
		context.Background(),
		srv.URL,
		&providers.Config{Credentials: providers.Credentials{ApiKey: "sk-test"}},
		[]byte(`{"model":"gpt-4"}`),
	)
	require.Error(t, err)

	be, ok := registry.IsBackendError(err)
	require.True(t, ok, "expected a BackendError")
	assert.Equal(t, http.StatusTooManyRequests, be.StatusCode)
	assert.Equal(t, "7", be.RetryAfter)
	assert.JSONEq(t, `{"error":{"message":"rate limited"}}`, string(be.Body))
}

package groq

import (
	"context"
	"encoding/json"
	"iter"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/openai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// groqClientAt is a test-only wrapper that targets a custom URL so the
// OpenAI-compatible round trip can be exercised against an httptest server.
type groqClientAt struct {
	chat *openai.ChatCompletionsClient
	url  string
}

func newGroqClientAt(url string) providers.Client {
	return &groqClientAt{
		chat: openai.NewChatCompletionsClient(providers.ProviderGroq, nil),
		url:  url,
	}
}

func (c *groqClientAt) Completions(ctx context.Context, config *providers.Config, reqBody []byte) ([]byte, error) {
	return c.chat.Completions(ctx, c.url, config, reqBody, nil)
}

func (c *groqClientAt) CompletionsStream(ctx context.Context, config *providers.Config, reqBody []byte) (iter.Seq2[[]byte, error], error) {
	return c.chat.CompletionsStream(ctx, c.url, config, reqBody, nil)
}

func TestNewGroqClient(t *testing.T) {
	assert.NotNil(t, NewGroqClient())
}

func TestCompletions_MissingAPIKey(t *testing.T) {
	_, err := NewGroqClient().Completions(context.Background(), &providers.Config{}, []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestCompletions_NonStreamingRoundTrip(t *testing.T) {
	const wantModel = "llama-3.3-70b-versatile"
	var gotAuth, gotModel string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		gotAuth = r.Header.Get("Authorization")

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		gotModel, _ = body["model"].(string)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model":  wantModel,
			"x_groq": map[string]any{"usage": map[string]any{"queue_time": 0.01}},
		})
	}))
	t.Cleanup(srv.Close)

	resp, err := newGroqClientAt(srv.URL+"/chat/completions").Completions(
		context.Background(),
		&providers.Config{Credentials: providers.Credentials{ApiKey: "groq-test-key"}},
		[]byte(`{"model":"`+wantModel+`","messages":[{"role":"user","content":"hello"}]}`),
	)
	require.NoError(t, err)

	assert.Equal(t, "Bearer groq-test-key", gotAuth)
	assert.Equal(t, wantModel, gotModel)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(resp, &parsed))
	assert.Equal(t, wantModel, parsed["model"])
	assert.NotNil(t, parsed["x_groq"], "x_groq must survive verbatim passthrough")
}

func TestCompletionsStream_RoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer groq-key", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	t.Cleanup(srv.Close)

	seq, err := newGroqClientAt(srv.URL+"/chat/completions").CompletionsStream(
		context.Background(),
		&providers.Config{Credentials: providers.Credentials{ApiKey: "groq-key"}},
		[]byte(`{"model":"llama-3.3-70b-versatile","stream":true}`),
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

func TestCompletions_RateLimitRetryAfter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "2")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"rate limit exceeded"}}`))
	}))
	t.Cleanup(srv.Close)

	_, err := newGroqClientAt(srv.URL+"/chat/completions").Completions(
		context.Background(),
		&providers.Config{Credentials: providers.Credentials{ApiKey: "key"}},
		[]byte(`{"model":"llama-3.3-70b-versatile","messages":[{"role":"user","content":"hi"}]}`),
	)
	require.Error(t, err)

	be, ok := registry.IsBackendError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusTooManyRequests, be.StatusCode)
	assert.Equal(t, "2", be.RetryAfter)
}

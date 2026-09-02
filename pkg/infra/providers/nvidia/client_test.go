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

package nvidia

import (
	"context"
	"encoding/json"
	"iter"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/openai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nvidiaClientAt is a test-only wrapper that targets a custom URL so the
// OpenAI-compatible round trip can be exercised against an httptest server.
type nvidiaClientAt struct {
	chat *openai.ChatCompletionsClient
	url  string
}

func newNvidiaClientAt(url string) providers.Client {
	return &nvidiaClientAt{
		chat: openai.NewChatCompletionsClient(providers.ProviderNvidia, nil),
		url:  url,
	}
}

func (c *nvidiaClientAt) Completions(ctx context.Context, config *providers.Config, reqBody []byte) ([]byte, error) {
	return c.chat.Completions(ctx, c.url, config, reqBody, nil)
}

func (c *nvidiaClientAt) CompletionsStream(ctx context.Context, config *providers.Config, reqBody []byte) (iter.Seq2[[]byte, error], error) {
	return c.chat.CompletionsStream(ctx, c.url, config, reqBody, nil)
}

func TestNewNvidiaClient(t *testing.T) {
	assert.NotNil(t, NewNvidiaClient())
}

func TestCompletions_MissingAPIKey(t *testing.T) {
	_, err := NewNvidiaClient().Completions(context.Background(), &providers.Config{}, []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestCompletions_NonStreamingRoundTrip(t *testing.T) {
	const wantModel = "meta/llama-3.3-70b-instruct"
	var gotAuth, gotModel string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
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

	resp, err := newNvidiaClientAt(srv.URL+"/chat/completions").Completions(
		context.Background(),
		&providers.Config{Credentials: providers.Credentials{ApiKey: "nvidia-test-key"}},
		[]byte(`{"model":"`+wantModel+`","messages":[{"role":"user","content":"hello"}]}`),
	)
	require.NoError(t, err)

	assert.Equal(t, "Bearer nvidia-test-key", gotAuth)
	assert.Equal(t, wantModel, gotModel)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(resp, &parsed))
	assert.Equal(t, wantModel, parsed["model"])
	assert.NotNil(t, parsed["usage"], "usage must survive verbatim passthrough")
}

func TestCompletionsStream_RoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer nvidia-key", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	t.Cleanup(srv.Close)

	seq, err := newNvidiaClientAt(srv.URL+"/chat/completions").CompletionsStream(
		context.Background(),
		&providers.Config{Credentials: providers.Credentials{ApiKey: "nvidia-key"}},
		[]byte(`{"model":"meta/llama-3.3-70b-instruct","stream":true}`),
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

	_, err := newNvidiaClientAt(srv.URL+"/chat/completions").Completions(
		context.Background(),
		&providers.Config{Credentials: providers.Credentials{ApiKey: "key"}},
		[]byte(`{"model":"meta/llama-3.3-70b-instruct","messages":[{"role":"user","content":"hi"}]}`),
	)
	require.Error(t, err)

	be, ok := registry.IsBackendError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusTooManyRequests, be.StatusCode)
	assert.Equal(t, "2", be.RetryAfter)
}

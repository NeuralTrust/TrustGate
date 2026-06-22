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

package deepseek

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

// deepseekClientAt is a test-only wrapper that targets a custom URL so the
// OpenAI-compatible round trip can be exercised against an httptest server
// while preserving the reasoner validation guard.
type deepseekClientAt struct {
	chat *openai.ChatCompletionsClient
	url  string
}

func newDeepSeekClientAt(url string) providers.Client {
	return &deepseekClientAt{
		chat: openai.NewChatCompletionsClient(providers.ProviderDeepSeek, nil),
		url:  url,
	}
}

func (c *deepseekClientAt) Completions(ctx context.Context, config *providers.Config, reqBody []byte) ([]byte, error) {
	if err := validateRequest(reqBody); err != nil {
		return nil, err
	}
	return c.chat.Completions(ctx, c.url, config, reqBody, nil)
}

func (c *deepseekClientAt) CompletionsStream(ctx context.Context, config *providers.Config, reqBody []byte) (iter.Seq2[[]byte, error], error) {
	if err := validateRequest(reqBody); err != nil {
		return nil, err
	}
	return c.chat.CompletionsStream(ctx, c.url, config, reqBody, nil)
}

func TestNewDeepSeekClient(t *testing.T) {
	assert.NotNil(t, NewDeepSeekClient())
}

func TestCompletions_MissingAPIKey(t *testing.T) {
	_, err := NewDeepSeekClient().Completions(context.Background(), &providers.Config{}, []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestCompletions_NonStreamingRoundTrip(t *testing.T) {
	const wantModel = "deepseek-chat"
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
			"choices": []any{map[string]any{
				"message": map[string]any{
					"role":              "assistant",
					"content":           "hi",
					"reasoning_content": "let me think",
				},
			}},
		})
	}))
	t.Cleanup(srv.Close)

	resp, err := newDeepSeekClientAt(srv.URL+"/chat/completions").Completions(
		context.Background(),
		&providers.Config{Credentials: providers.Credentials{ApiKey: "deepseek-test-key"}},
		[]byte(`{"model":"`+wantModel+`","messages":[{"role":"user","content":"hello"}]}`),
	)
	require.NoError(t, err)

	assert.Equal(t, "Bearer deepseek-test-key", gotAuth)
	assert.Equal(t, wantModel, gotModel)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(resp, &parsed))
	assert.Equal(t, wantModel, parsed["model"])
}

func TestCompletionsStream_RoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer deepseek-key", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	t.Cleanup(srv.Close)

	seq, err := newDeepSeekClientAt(srv.URL+"/chat/completions").CompletionsStream(
		context.Background(),
		&providers.Config{Credentials: providers.Credentials{ApiKey: "deepseek-key"}},
		[]byte(`{"model":"deepseek-chat","stream":true}`),
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

func TestCompletions_ReasonerMaxTokensValidation(t *testing.T) {
	_, err := NewDeepSeekClient().Completions(
		context.Background(),
		&providers.Config{Credentials: providers.Credentials{ApiKey: "key"}},
		[]byte(`{"model":"deepseek-reasoner","max_tokens":70000}`),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds DeepSeek limit")
}

func TestCompletions_ReasonerWithinLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"model": "deepseek-reasoner"})
	}))
	t.Cleanup(srv.Close)

	_, err := newDeepSeekClientAt(srv.URL+"/chat/completions").Completions(
		context.Background(),
		&providers.Config{Credentials: providers.Credentials{ApiKey: "key"}},
		[]byte(`{"model":"deepseek-reasoner","max_completion_tokens":64000,"messages":[{"role":"user","content":"hi"}]}`),
	)
	require.NoError(t, err)
}

func TestCompletions_RateLimitRetryAfter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "2")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"rate limit exceeded"}}`))
	}))
	t.Cleanup(srv.Close)

	_, err := newDeepSeekClientAt(srv.URL+"/chat/completions").Completions(
		context.Background(),
		&providers.Config{Credentials: providers.Credentials{ApiKey: "key"}},
		[]byte(`{"model":"deepseek-chat","messages":[{"role":"user","content":"hi"}]}`),
	)
	require.Error(t, err)

	be, ok := registry.IsBackendError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusTooManyRequests, be.StatusCode)
	assert.Equal(t, "2", be.RetryAfter)
}

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

package openrouter

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

type openRouterClientAt struct {
	chat *openai.ChatCompletionsClient
	url  string
}

func newOpenRouterClientAt(url string) providers.Client {
	return &openRouterClientAt{
		chat: openai.NewChatCompletionsClient(providers.ProviderOpenRouter, nil),
		url:  url,
	}
}

func (c *openRouterClientAt) Completions(ctx context.Context, config *providers.Config, reqBody []byte) ([]byte, error) {
	return c.chat.Completions(ctx, c.url, config, reqBody, nil)
}

func (c *openRouterClientAt) CompletionsStream(ctx context.Context, config *providers.Config, reqBody []byte) (iter.Seq2[[]byte, error], error) {
	return c.chat.CompletionsStream(ctx, c.url, config, reqBody, nil)
}

func TestNewOpenRouterClient(t *testing.T) {
	assert.NotNil(t, NewOpenRouterClient())
}

func TestFilesURL(t *testing.T) {
	assert.Equal(t, "https://openrouter.ai/api/v1/files", providers.JoinOpenAIFilesURL(filesBaseURL, "/v1/files", nil))
	q := map[string][]string{"provider": {"openai"}}
	assert.Equal(t,
		"https://openrouter.ai/api/v1/files?provider=openai",
		providers.JoinOpenAIFilesURL(filesBaseURL, "/v1/files", q),
	)
}

func TestFiles_MissingAPIKey(t *testing.T) {
	_, err := NewOpenRouterClient().(providers.FilesClient).Files(context.Background(), &providers.Config{}, providers.FilesRequest{
		Method: http.MethodGet,
		Path:   "/v1/files",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestAudioSpeech_RoundTrip(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "audio/mpeg")
		_, _ = w.Write([]byte("mp3-bytes"))
	}))
	t.Cleanup(srv.Close)

	c := NewOpenRouterClient().(providers.AudioSpeechClient)
	result, err := c.AudioSpeech(context.Background(), &providers.Config{
		Credentials: providers.Credentials{ApiKey: "or-key"},
		Options:     map[string]any{"base_url": srv.URL + "/api/v1"},
	}, providers.AudioRequest{
		Method:      http.MethodPost,
		Path:        "/v1/audio/speech",
		ContentType: "application/json",
		Body:        []byte(`{"model":"openai/gpt-4o-mini-tts","input":"hi","voice":"alloy"}`),
	})
	require.NoError(t, err)
	assert.Equal(t, "Bearer or-key", gotAuth)
	assert.Equal(t, "/api/v1/audio/speech", gotPath)
	assert.Equal(t, []byte("mp3-bytes"), result.Body)
}

func TestAudioTranscription_RoundTrip(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"hello"}`))
	}))
	t.Cleanup(srv.Close)

	c := NewOpenRouterClient().(providers.AudioTranscriptionClient)
	result, err := c.AudioTranscription(context.Background(), &providers.Config{
		Credentials: providers.Credentials{ApiKey: "or-key"},
		Options:     map[string]any{"base_url": srv.URL + "/api/v1"},
	}, providers.AudioRequest{
		Method:      http.MethodPost,
		Path:        "/v1/audio/transcriptions",
		ContentType: "multipart/form-data; boundary=abc",
		Body:        []byte("file-bytes"),
	})
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/audio/transcriptions", gotPath)
	assert.JSONEq(t, `{"text":"hello"}`, string(result.Body))
}

func TestCompletions_MissingAPIKey(t *testing.T) {
	_, err := NewOpenRouterClient().Completions(context.Background(), &providers.Config{}, []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestCompletions_NonStreamingRoundTrip(t *testing.T) {
	const wantModel = "anthropic/claude-sonnet-4"
	var gotAuth, gotModel string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		gotAuth = r.Header.Get("Authorization")

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		gotModel, _ = body["model"].(string)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model":    wantModel,
			"provider": "Anthropic",
		})
	}))
	t.Cleanup(srv.Close)

	resp, err := newOpenRouterClientAt(srv.URL+"/chat/completions").Completions(
		context.Background(),
		&providers.Config{Credentials: providers.Credentials{ApiKey: "or-test-key"}},
		[]byte(`{"model":"`+wantModel+`","messages":[{"role":"user","content":"hello"}]}`),
	)
	require.NoError(t, err)

	assert.Equal(t, "Bearer or-test-key", gotAuth)
	assert.Equal(t, wantModel, gotModel)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(resp, &parsed))
	assert.Equal(t, wantModel, parsed["model"])
	assert.Equal(t, "Anthropic", parsed["provider"])
}

func TestCompletionsStream_RoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer or-key", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	t.Cleanup(srv.Close)

	seq, err := newOpenRouterClientAt(srv.URL+"/chat/completions").CompletionsStream(
		context.Background(),
		&providers.Config{Credentials: providers.Credentials{ApiKey: "or-key"}},
		[]byte(`{"model":"anthropic/claude-sonnet-4","stream":true}`),
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

	_, err := newOpenRouterClientAt(srv.URL+"/chat/completions").Completions(
		context.Background(),
		&providers.Config{Credentials: providers.Credentials{ApiKey: "key"}},
		[]byte(`{"model":"anthropic/claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}`),
	)
	require.Error(t, err)

	be, ok := registry.IsBackendError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusTooManyRequests, be.StatusCode)
	assert.Equal(t, "2", be.RetryAfter)
}

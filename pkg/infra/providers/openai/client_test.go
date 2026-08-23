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

package openai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
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

func TestResolveURL(t *testing.T) {
	c := &client{}

	cases := []struct {
		name    string
		options map[string]any
		want    string
	}{
		{name: "defaults to completions", options: nil, want: completionsURL},
		{name: "responses api", options: map[string]any{"api": "responses"}, want: responsesURL},
		{name: "base_url completions", options: map[string]any{"base_url": "http://127.0.0.1:9999"}, want: "http://127.0.0.1:9999/chat/completions"},
		{name: "base_url trailing slash", options: map[string]any{"base_url": "https://host/v1/"}, want: "https://host/v1/chat/completions"},
		{name: "base_url responses", options: map[string]any{"api": "responses", "base_url": "https://host/v1"}, want: "https://host/v1/responses"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.resolveURL(&providers.Config{Options: tt.options})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	t.Run("invalid api errors", func(t *testing.T) {
		_, err := c.resolveURL(&providers.Config{Options: map[string]any{"api": "chat"}})
		require.Error(t, err)
	})
}

func TestResolveEmbeddingsURL(t *testing.T) {
	c := &client{}

	cases := []struct {
		name    string
		options map[string]any
		want    string
	}{
		{name: "default host", options: nil, want: embeddingsURL},
		{name: "base_url", options: map[string]any{"base_url": "http://127.0.0.1:9999"}, want: "http://127.0.0.1:9999/embeddings"},
		{name: "base_url trailing slash", options: map[string]any{"base_url": "https://host/v1/"}, want: "https://host/v1/embeddings"},
		{name: "responses api does not change embeddings path", options: map[string]any{"api": "responses", "base_url": "https://host/v1"}, want: "https://host/v1/embeddings"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.resolveEmbeddingsURL(&providers.Config{Options: tt.options})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestResolveFilesBaseURL(t *testing.T) {
	c := &client{}

	cases := []struct {
		name    string
		options map[string]any
		want    string
	}{
		{name: "default host", options: nil, want: filesBaseURL},
		{name: "base_url", options: map[string]any{"base_url": "http://127.0.0.1:9999"}, want: "http://127.0.0.1:9999"},
		{name: "base_url trailing slash", options: map[string]any{"base_url": "https://host/v1/"}, want: "https://host/v1"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.resolveFilesBaseURL(&providers.Config{Options: tt.options})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFiles_MissingAPIKey(t *testing.T) {
	c := NewOpenaiClient().(providers.FilesClient)
	_, err := c.Files(context.Background(), &providers.Config{}, providers.FilesRequest{
		Method: http.MethodGet,
		Path:   "/v1/files",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestFiles_RoundTrip(t *testing.T) {
	var gotAuth, gotMethod, gotPath, gotQuery, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotCT = r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"file-1","object":"file"}`))
	}))
	t.Cleanup(srv.Close)

	c := NewOpenaiClient().(providers.FilesClient)
	result, err := c.Files(context.Background(), &providers.Config{
		Credentials: providers.Credentials{ApiKey: "sk-test"},
		Options:     map[string]any{"base_url": srv.URL + "/v1"},
	}, providers.FilesRequest{
		Method:      http.MethodPost,
		Path:        "/v1/files",
		Query:       nil,
		ContentType: "multipart/form-data; boundary=abc",
		Body:        []byte("file-bytes"),
	})
	require.NoError(t, err)
	assert.Equal(t, "Bearer sk-test", gotAuth)
	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "/v1/files", gotPath)
	assert.Empty(t, gotQuery)
	assert.Equal(t, "multipart/form-data; boundary=abc", gotCT)
	assert.JSONEq(t, `{"id":"file-1","object":"file"}`, string(result.Body))
	assert.Equal(t, "application/json", result.ContentType)
}

func TestFiles_ContentRoundTrip(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("pdf-bytes"))
	}))
	t.Cleanup(srv.Close)

	c := NewOpenaiClient().(providers.FilesClient)
	result, err := c.Files(context.Background(), &providers.Config{
		Credentials: providers.Credentials{ApiKey: "sk-test"},
		Options:     map[string]any{"base_url": srv.URL + "/v1"},
	}, providers.FilesRequest{
		Method: http.MethodGet,
		Path:   "/v1/files/file-1/content",
	})
	require.NoError(t, err)
	assert.Equal(t, "/v1/files/file-1/content", gotPath)
	assert.Equal(t, []byte("pdf-bytes"), result.Body)
	assert.Equal(t, "application/octet-stream", result.ContentType)
}

func TestAudioSpeech_RoundTrip(t *testing.T) {
	var gotAuth, gotMethod, gotPath, gotCT string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotCT = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "audio/mpeg")
		_, _ = w.Write([]byte("mp3-bytes"))
	}))
	t.Cleanup(srv.Close)

	c := NewOpenaiClient().(providers.AudioSpeechClient)
	result, err := c.AudioSpeech(context.Background(), &providers.Config{
		Credentials: providers.Credentials{ApiKey: "sk-test"},
		Options:     map[string]any{"base_url": srv.URL + "/v1"},
	}, providers.AudioRequest{
		Method:      http.MethodPost,
		Path:        "/v1/audio/speech",
		ContentType: "application/json",
		Body:        []byte(`{"model":"tts-1","input":"hi","voice":"alloy"}`),
	})
	require.NoError(t, err)
	assert.Equal(t, "Bearer sk-test", gotAuth)
	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "/v1/audio/speech", gotPath)
	assert.Equal(t, "application/json", gotCT)
	assert.JSONEq(t, `{"model":"tts-1","input":"hi","voice":"alloy"}`, string(gotBody))
	assert.Equal(t, []byte("mp3-bytes"), result.Body)
	assert.Equal(t, "audio/mpeg", result.ContentType)
}

func TestAudioTranscription_RoundTrip(t *testing.T) {
	var gotPath, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotCT = r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"hello"}`))
	}))
	t.Cleanup(srv.Close)

	c := NewOpenaiClient().(providers.AudioTranscriptionClient)
	result, err := c.AudioTranscription(context.Background(), &providers.Config{
		Credentials: providers.Credentials{ApiKey: "sk-test"},
		Options:     map[string]any{"base_url": srv.URL + "/v1"},
	}, providers.AudioRequest{
		Method:      http.MethodPost,
		Path:        "/v1/audio/transcriptions",
		ContentType: "multipart/form-data; boundary=abc",
		Body:        []byte("file-bytes"),
	})
	require.NoError(t, err)
	assert.Equal(t, "/v1/audio/transcriptions", gotPath)
	assert.Equal(t, "multipart/form-data; boundary=abc", gotCT)
	assert.JSONEq(t, `{"text":"hello"}`, string(result.Body))
}

func TestAudioSpeech_MissingAPIKey(t *testing.T) {
	c := NewOpenaiClient().(providers.AudioSpeechClient)
	_, err := c.AudioSpeech(context.Background(), &providers.Config{}, providers.AudioRequest{
		Method: http.MethodPost,
		Path:   "/v1/audio/speech",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestEmbeddings_MissingAPIKey(t *testing.T) {
	c := NewOpenaiClient().(providers.EmbeddingsClient)
	_, err := c.Embeddings(context.Background(), &providers.Config{}, []byte(`{"model":"text-embedding-3-small","input":"hi"}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestEmbeddings_RoundTrip(t *testing.T) {
	var gotAuth, gotPath string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"index":0,"embedding":[0.1,0.2]}]}`))
	}))
	t.Cleanup(srv.Close)

	c := NewOpenaiClient().(providers.EmbeddingsClient)
	resp, err := c.Embeddings(
		context.Background(),
		&providers.Config{
			Credentials: providers.Credentials{ApiKey: "sk-test"},
			Options:     map[string]any{"base_url": srv.URL + "/v1"},
		},
		[]byte(`{"model":"text-embedding-3-small","input":"hi"}`),
	)
	require.NoError(t, err)

	assert.Equal(t, "Bearer sk-test", gotAuth)
	assert.Equal(t, "/v1/embeddings", gotPath)
	assert.Equal(t, "text-embedding-3-small", gotBody["model"])
	assert.JSONEq(t, `{"object":"list","data":[{"index":0,"embedding":[0.1,0.2]}]}`, string(resp))
}

func TestChatCompletions_MissingAPIKey(t *testing.T) {
	chat := NewChatCompletionsClient(providers.ProviderOpenAI, nil)
	_, err := chat.Completions(context.Background(), "http://example.invalid", &providers.Config{}, []byte(`{}`), nil)
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
		nil,
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
		nil,
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
		nil,
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
		nil,
	)
	require.Error(t, err)

	be, ok := registry.IsBackendError(err)
	require.True(t, ok, "expected a BackendError")
	assert.Equal(t, http.StatusTooManyRequests, be.StatusCode)
	assert.Equal(t, "7", be.RetryAfter)
	assert.JSONEq(t, `{"error":{"message":"rate limited"}}`, string(be.Body))
}

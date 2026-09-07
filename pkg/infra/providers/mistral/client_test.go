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

package mistral

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMistralClient(t *testing.T) {
	assert.NotNil(t, NewMistralClient())
}

func TestCompletions_MissingAPIKey(t *testing.T) {
	_, err := NewMistralClient().Completions(context.Background(), &providers.Config{}, []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestEmbedURL(t *testing.T) {
	got, err := embedURL(nil)
	require.NoError(t, err)
	assert.Equal(t, embeddingsURL, got)

	got, err = embedURL(map[string]any{"base_url": "https://host/v1/"})
	require.NoError(t, err)
	assert.Equal(t, "https://host/v1/embeddings", got)

	_, err = embedURL(map[string]any{"base_url": "host/v1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base_url")
}

func TestFilesURL(t *testing.T) {
	got, err := filesURL(nil, "/v1/files", nil)
	require.NoError(t, err)
	assert.Equal(t, filesBaseURL+"/files", got)

	got, err = filesURL(map[string]any{"base_url": "https://host/v1/"}, "/v1/files/file-1", nil)
	require.NoError(t, err)
	assert.Equal(t, "https://host/v1/files/file-1", got)

	_, err = filesURL(map[string]any{"base_url": "host/v1"}, "/v1/files", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base_url")
}

func TestFiles_MissingAPIKey(t *testing.T) {
	c := NewMistralClient().(providers.FilesClient)
	_, err := c.Files(context.Background(), &providers.Config{}, providers.FilesRequest{
		Method: http.MethodGet,
		Path:   "/v1/files",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestFiles_RoundTrip(t *testing.T) {
	var gotAuth, gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotMethod = r.Method
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"file-1","object":"file","deleted":true}`))
	}))
	t.Cleanup(srv.Close)

	c := NewMistralClient().(providers.FilesClient)
	result, err := c.Files(context.Background(), &providers.Config{
		Credentials: providers.Credentials{ApiKey: "mistral-key"},
		Options:     map[string]any{"base_url": srv.URL + "/v1"},
	}, providers.FilesRequest{
		Method: http.MethodDelete,
		Path:   "/v1/files/file-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "Bearer mistral-key", gotAuth)
	assert.Equal(t, "/v1/files/file-1", gotPath)
	assert.Equal(t, http.MethodDelete, gotMethod)
	assert.JSONEq(t, `{"id":"file-1","object":"file","deleted":true}`, string(result.Body))
}

func TestAudioSpeech_UnwrapsJSONAudio(t *testing.T) {
	var gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"audio_data":"d2F2LWJ5dGVz"}`))
	}))
	t.Cleanup(srv.Close)

	c := NewMistralClient().(providers.AudioSpeechClient)
	result, err := c.AudioSpeech(context.Background(), &providers.Config{
		Credentials: providers.Credentials{ApiKey: "mistral-key"},
		Options:     map[string]any{"base_url": srv.URL + "/v1"},
	}, providers.AudioRequest{
		Method:      http.MethodPost,
		Path:        "/v1/audio/speech",
		ContentType: "application/json",
		Body:        []byte(`{"model":"voxtral-mini-tts-2603","input":"hi","voice":"alloy","response_format":"wav"}`),
	})
	require.NoError(t, err)
	assert.Equal(t, "/v1/audio/speech", gotPath)
	assert.Contains(t, gotBody, `"voice_id":"alloy"`)
	assert.Equal(t, []byte("wav-bytes"), result.Body)
	assert.Equal(t, "audio/wav", result.ContentType)
}

func TestAudioTranscription_RoundTrip(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"hello"}`))
	}))
	t.Cleanup(srv.Close)

	c := NewMistralClient().(providers.AudioTranscriptionClient)
	result, err := c.AudioTranscription(context.Background(), &providers.Config{
		Credentials: providers.Credentials{ApiKey: "mistral-key"},
		Options:     map[string]any{"base_url": srv.URL + "/v1"},
	}, providers.AudioRequest{
		Method:      http.MethodPost,
		Path:        "/v1/audio/transcriptions",
		ContentType: "multipart/form-data; boundary=abc",
		Body:        []byte("file-bytes"),
	})
	require.NoError(t, err)
	assert.Equal(t, "/v1/audio/transcriptions", gotPath)
	assert.JSONEq(t, `{"text":"hello"}`, string(result.Body))
}

func TestAudioURL(t *testing.T) {
	got, err := audioURL(nil, "/v1/audio/speech", nil)
	require.NoError(t, err)
	assert.Equal(t, filesBaseURL+"/audio/speech", got)

	got, err = audioURL(map[string]any{"base_url": "https://host/v1/"}, "/v1/audio/transcriptions", nil)
	require.NoError(t, err)
	assert.Equal(t, "https://host/v1/audio/transcriptions", got)
}

func TestEmbeddings_MissingAPIKey(t *testing.T) {
	c := NewMistralClient().(providers.EmbeddingsClient)
	_, err := c.Embeddings(context.Background(), &providers.Config{}, []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestEmbeddings_RoundTrip(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"index":0,"embedding":[0.1,0.2]}]}`))
	}))
	t.Cleanup(srv.Close)

	c := NewMistralClient().(providers.EmbeddingsClient)
	resp, err := c.Embeddings(context.Background(), &providers.Config{
		Credentials: providers.Credentials{ApiKey: "mistral-key"},
		Options:     map[string]any{"base_url": srv.URL + "/v1"},
	}, []byte(`{"model":"mistral-embed","input":["hi"]}`))
	require.NoError(t, err)

	assert.Equal(t, "Bearer mistral-key", gotAuth)
	assert.Equal(t, "/v1/embeddings", gotPath)
	assert.JSONEq(t, `{"object":"list","data":[{"index":0,"embedding":[0.1,0.2]}]}`, string(resp))
}

func TestRawPost_RoundTrip(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl-1"}`))
	}))
	t.Cleanup(srv.Close)

	c := &client{pool: providers.NewHTTPClientPool()}
	resp, err := c.rawPost(context.Background(), srv.URL, "mistral-key", []byte(`{"model":"mistral-large"}`))
	require.NoError(t, err)

	assert.Equal(t, "Bearer mistral-key", gotAuth)
	assert.JSONEq(t, `{"id":"cmpl-1"}`, string(resp))
}

func TestRawPost_BackendErrorPassthrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid key"}`))
	}))
	t.Cleanup(srv.Close)

	c := &client{pool: providers.NewHTTPClientPool()}
	_, err := c.rawPost(context.Background(), srv.URL, "bad", []byte(`{}`))
	require.Error(t, err)

	be, ok := registry.IsBackendError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, be.StatusCode)
	assert.JSONEq(t, `{"error":"invalid key"}`, string(be.Body))
}

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

package anthropic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAnthropicClient(t *testing.T) {
	assert.NotNil(t, NewAnthropicClient())
}

func TestCompletions_MissingAPIKey(t *testing.T) {
	_, err := NewAnthropicClient().Completions(context.Background(), &providers.Config{}, []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestSetHeaders(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, messagesURL, nil)
	require.NoError(t, err)

	(&client{pool: providers.NewHTTPClientPool()}).setHeaders(req, "secret-key")

	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
	assert.Equal(t, "secret-key", req.Header.Get("x-api-key"))
	assert.Equal(t, anthropicVersion, req.Header.Get("anthropic-version"))
}

func TestFilesURL(t *testing.T) {
	got, err := filesURL(nil, "/v1/files", nil)
	require.NoError(t, err)
	assert.Equal(t, filesBaseURL+"/files", got)

	got, err = filesURL(map[string]any{"base_url": "https://host/v1/"}, "/v1/files/file-1/content", nil)
	require.NoError(t, err)
	assert.Equal(t, "https://host/v1/files/file-1/content", got)

	_, err = filesURL(map[string]any{"base_url": "host/v1"}, "/v1/files", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base_url")
}

func TestFiles_MissingAPIKey(t *testing.T) {
	c := NewAnthropicClient().(providers.FilesClient)
	_, err := c.Files(context.Background(), &providers.Config{}, providers.FilesRequest{
		Method: http.MethodGet,
		Path:   "/v1/files",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestFiles_RoundTrip(t *testing.T) {
	var gotKey, gotVersion, gotPath, gotMethod, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")
		gotCT = r.Header.Get("Content-Type")
		gotPath = r.URL.Path
		gotMethod = r.Method
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"file_011CNha8iCJcU1wXNR6q4V8w","type":"file","filename":"notes.txt"}`))
	}))
	t.Cleanup(srv.Close)

	c := NewAnthropicClient().(providers.FilesClient)
	result, err := c.Files(context.Background(), &providers.Config{
		Credentials: providers.Credentials{ApiKey: "sk-ant-test"},
		Options:     map[string]any{"base_url": srv.URL + "/v1"},
	}, providers.FilesRequest{
		Method:      http.MethodPost,
		Path:        "/v1/files",
		ContentType: "multipart/form-data; boundary=----x",
		Body:        []byte("------x--"),
	})
	require.NoError(t, err)
	assert.Equal(t, "sk-ant-test", gotKey)
	assert.Equal(t, anthropicVersion, gotVersion)
	assert.Contains(t, gotCT, "multipart/form-data")
	assert.Equal(t, "/v1/files", gotPath)
	assert.Equal(t, http.MethodPost, gotMethod)
	assert.JSONEq(t, `{"id":"file_011CNha8iCJcU1wXNR6q4V8w","type":"file","filename":"notes.txt"}`, string(result.Body))
}

func TestFiles_BackendErrorPassthrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"type":"authentication_error"}}`))
	}))
	t.Cleanup(srv.Close)

	c := NewAnthropicClient().(providers.FilesClient)
	_, err := c.Files(context.Background(), &providers.Config{
		Credentials: providers.Credentials{ApiKey: "bad"},
		Options:     map[string]any{"base_url": srv.URL + "/v1"},
	}, providers.FilesRequest{
		Method: http.MethodGet,
		Path:   "/v1/files",
	})
	require.Error(t, err)

	be, ok := registry.IsBackendError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, be.StatusCode)
	assert.JSONEq(t, `{"error":{"type":"authentication_error"}}`, string(be.Body))
}

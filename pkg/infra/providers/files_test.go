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

package providers_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsFilesPath(t *testing.T) {
	t.Parallel()
	assert.True(t, providers.IsFilesPath("/v1/files"))
	assert.True(t, providers.IsFilesPath("/v1/files/file-abc"))
	assert.True(t, providers.IsFilesPath("/v1/files/file-abc/content"))
	assert.False(t, providers.IsFilesPath("/v1/files/"))
	assert.False(t, providers.IsFilesPath("/v1/files/file-abc/other"))
	assert.False(t, providers.IsFilesPath("/v1/embeddings"))
}

func TestValidateFilesMethod(t *testing.T) {
	t.Parallel()
	require.NoError(t, providers.ValidateFilesMethod("POST", "/v1/files"))
	require.NoError(t, providers.ValidateFilesMethod("GET", "/v1/files"))
	require.NoError(t, providers.ValidateFilesMethod("GET", "/v1/files/file-1"))
	require.NoError(t, providers.ValidateFilesMethod("DELETE", "/v1/files/file-1"))
	require.NoError(t, providers.ValidateFilesMethod("GET", "/v1/files/file-1/content"))
	require.Error(t, providers.ValidateFilesMethod("DELETE", "/v1/files"))
	require.Error(t, providers.ValidateFilesMethod("POST", "/v1/files/file-1"))
	require.Error(t, providers.ValidateFilesMethod("DELETE", "/v1/files/file-1/content"))
}

func TestJoinOpenAIFilesURL(t *testing.T) {
	t.Parallel()
	q := url.Values{"purpose": []string{"assistants"}}
	assert.Equal(t,
		"https://api.openai.com/v1/files?purpose=assistants",
		providers.JoinOpenAIFilesURL("https://api.openai.com/v1/", "/v1/files", q),
	)
	assert.Equal(t,
		"https://host/v1/files/file-1/content",
		providers.JoinOpenAIFilesURL("https://host/v1", "/v1/files/file-1/content", nil),
	)
}

func TestJoinAzureFilesURL(t *testing.T) {
	t.Parallel()
	q := url.Values{"purpose": []string{"fine-tune"}}
	got := providers.JoinAzureFilesURL("https://res.openai.azure.com", "/v1/files", "2024-10-21", q)
	assert.Contains(t, got, "https://res.openai.azure.com/openai/files?")
	assert.Contains(t, got, "api-version=2024-10-21")
	assert.Contains(t, got, "purpose=fine-tune")
}

func TestRestAfterConsumerSlug(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "/v1/files", providers.RestAfterConsumerSlug("/acme/v1/files"))
	assert.Equal(t, "/v1/files/file-1", providers.RestAfterConsumerSlug("/acme/v1/files/file-1/"))
	assert.Equal(t, "", providers.RestAfterConsumerSlug("/acme"))
}

func TestDoFilesHTTP_RoundTrip(t *testing.T) {
	t.Parallel()
	var gotMethod, gotAuth, gotCT string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("file-bytes"))
	}))
	t.Cleanup(srv.Close)

	result, err := providers.DoFilesHTTP(
		context.Background(),
		srv.Client(),
		http.MethodGet,
		srv.URL+"/v1/files/file-1/content",
		"text/plain",
		[]byte("ignored-for-get"),
		func(req *http.Request) {
			req.Header.Set("Authorization", "Bearer sk-test")
		},
	)
	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, gotMethod)
	assert.Equal(t, "Bearer sk-test", gotAuth)
	assert.Equal(t, "text/plain", gotCT)
	assert.Equal(t, []byte("ignored-for-get"), gotBody)
	assert.Equal(t, []byte("file-bytes"), result.Body)
	assert.Equal(t, "application/octet-stream", result.ContentType)
}

func TestDoFilesHTTP_BackendError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"message":"missing"}}`))
	}))
	t.Cleanup(srv.Close)

	_, err := providers.DoFilesHTTP(context.Background(), srv.Client(), http.MethodGet, srv.URL+"/v1/files/x", "", nil, nil)
	require.Error(t, err)
	be, ok := registry.IsBackendError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusNotFound, be.StatusCode)
}

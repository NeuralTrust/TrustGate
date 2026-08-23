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
	"bytes"
	"io"
	"mime/multipart"
	"net/url"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsImagesPath(t *testing.T) {
	t.Parallel()
	assert.True(t, providers.IsImagesPath("/v1/images/generations"))
	assert.True(t, providers.IsImagesPath("/v1/images/edits"))
	assert.True(t, providers.IsImagesPath("/v1/images/variations"))
	assert.False(t, providers.IsImagesPath("/v1/images"))
	assert.False(t, providers.IsImagesPath("/v1/images/generations/extra"))
	assert.False(t, providers.IsImagesPath("/v1/images/edits/extra"))
	assert.False(t, providers.IsImagesPath("/v1/embeddings"))
}

func TestValidateImagesMethod(t *testing.T) {
	t.Parallel()
	require.NoError(t, providers.ValidateImagesMethod("POST", "/v1/images/generations"))
	require.NoError(t, providers.ValidateImagesMethod("POST", "/v1/images/edits"))
	require.NoError(t, providers.ValidateImagesMethod("POST", "/v1/images/variations"))
	require.Error(t, providers.ValidateImagesMethod("GET", "/v1/images/generations"))
	require.Error(t, providers.ValidateImagesMethod("GET", "/v1/images/edits"))
	require.Error(t, providers.ValidateImagesMethod("POST", "/v1/images"))
}

func TestJoinOpenAIImagesURL(t *testing.T) {
	t.Parallel()
	assert.Equal(t,
		"https://api.openai.com/v1/images/generations",
		providers.JoinOpenAIImagesURL("https://api.openai.com/v1/", "/v1/images/generations", nil),
	)
	assert.Equal(t,
		"https://api.openai.com/v1/images/edits",
		providers.JoinOpenAIImagesURL("https://api.openai.com/v1/", "/v1/images/edits", nil),
	)
	assert.Equal(t,
		"https://api.openai.com/v1/images/variations",
		providers.JoinOpenAIImagesURL("https://api.openai.com/v1", "/v1/images/variations", nil),
	)
	q := url.Values{"user": []string{"alice"}}
	assert.Equal(t,
		"https://host/v1/images/generations?user=alice",
		providers.JoinOpenAIImagesURL("https://host/v1", "/v1/images/generations", q),
	)
}

func TestJoinOpenRouterImagesURL(t *testing.T) {
	t.Parallel()
	assert.Equal(t,
		"https://openrouter.ai/api/v1/images",
		providers.JoinOpenRouterImagesURL("https://openrouter.ai/api/v1", "/v1/images/generations", nil),
	)
	assert.Equal(t,
		"https://openrouter.ai/api/v1/images/edits",
		providers.JoinOpenRouterImagesURL("https://openrouter.ai/api/v1", "/v1/images/edits", nil),
	)
	assert.Equal(t,
		"https://openrouter.ai/api/v1/images/variations",
		providers.JoinOpenRouterImagesURL("https://openrouter.ai/api/v1", "/v1/images/variations", nil),
	)
	q := url.Values{"provider": []string{"openai"}}
	assert.Equal(t,
		"https://openrouter.ai/api/v1/images?provider=openai",
		providers.JoinOpenRouterImagesURL("https://openrouter.ai/api/v1/", "/v1/images/generations", q),
	)
}

func TestAzureImagesOperation(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "images/generations", providers.AzureImagesOperation("/v1/images/generations"))
	assert.Equal(t, "images/edits", providers.AzureImagesOperation("/v1/images/edits"))
	assert.Equal(t, "images/variations", providers.AzureImagesOperation("/v1/images/variations"))
	assert.Equal(t, "images/generations", providers.AzureImagesOperation("/v1/images"))
}

func TestExtractImagesModel(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "dall-e-3", providers.ExtractImagesModel("application/json", []byte(`{"model":"dall-e-3","prompt":"a cat"}`)))
	assert.Equal(t, "", providers.ExtractImagesModel("application/json", []byte(`{"prompt":"a cat"}`)))
	assert.Equal(t, "", providers.ExtractImagesModel("application/json", []byte(`not-json`)))

	ct, body := multipartImagesFixture(t, map[string]string{"prompt": "make it blue", "model": "dall-e-2"}, "cat.png", "png-bytes")
	assert.True(t, providers.IsImagesMultipart(ct))
	assert.Equal(t, "dall-e-2", providers.ExtractImagesModel(ct, body))
	assert.False(t, providers.IsImagesMultipart("application/json"))
}

func multipartImagesFixture(t *testing.T, fields map[string]string, filename, contents string) (string, []byte) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("image", filename)
	require.NoError(t, err)
	_, err = io.WriteString(part, contents)
	require.NoError(t, err)
	for name, value := range fields {
		require.NoError(t, w.WriteField(name, value))
	}
	require.NoError(t, w.Close())
	return w.FormDataContentType(), buf.Bytes()
}

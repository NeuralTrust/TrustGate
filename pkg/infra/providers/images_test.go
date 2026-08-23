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
	"net/url"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsImagesPath(t *testing.T) {
	t.Parallel()
	assert.True(t, providers.IsImagesPath("/v1/images/generations"))
	assert.False(t, providers.IsImagesPath("/v1/images"))
	assert.False(t, providers.IsImagesPath("/v1/images/edits"))
	assert.False(t, providers.IsImagesPath("/v1/images/variations"))
	assert.False(t, providers.IsImagesPath("/v1/images/generations/extra"))
	assert.False(t, providers.IsImagesPath("/v1/embeddings"))
}

func TestValidateImagesMethod(t *testing.T) {
	t.Parallel()
	require.NoError(t, providers.ValidateImagesMethod("POST", "/v1/images/generations"))
	require.Error(t, providers.ValidateImagesMethod("GET", "/v1/images/generations"))
	require.Error(t, providers.ValidateImagesMethod("POST", "/v1/images/edits"))
}

func TestJoinOpenAIImagesURL(t *testing.T) {
	t.Parallel()
	assert.Equal(t,
		"https://api.openai.com/v1/images/generations",
		providers.JoinOpenAIImagesURL("https://api.openai.com/v1/", "/v1/images/generations", nil),
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
	q := url.Values{"provider": []string{"openai"}}
	assert.Equal(t,
		"https://openrouter.ai/api/v1/images?provider=openai",
		providers.JoinOpenRouterImagesURL("https://openrouter.ai/api/v1/", "/v1/images/generations", q),
	)
}

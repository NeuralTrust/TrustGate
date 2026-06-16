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
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
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

// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package proxy

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func additionalFields(t *testing.T, body []byte) map[string]json.RawMessage {
	t.Helper()
	var raw struct {
		Fields map[string]json.RawMessage `json:"additionalModelRequestFields"`
	}
	require.NoError(t, json.Unmarshal(body, &raw))
	return raw.Fields
}

func TestPrepareAnthropicConverse(t *testing.T) {
	p := &providerInvoker{logger: slog.Default()}
	body := []byte(`{"messages":[],"additionalModelRequestFields":{"top_k":40}}`)
	ctx := context.Background()

	t.Run("claude keeps the fields", func(t *testing.T) {
		req := &infracontext.RequestContext{Body: []byte(`{"messages":[],"metadata":{}}`)}
		out, err := p.prepareAnthropicConverse(ctx, req, body, "eu.anthropic.claude-sonnet-4-5-20250929-v1:0")
		require.NoError(t, err)
		assert.Equal(t, body, out)
	})

	t.Run("another family is refused on the routed leg", func(t *testing.T) {
		_, err := p.prepareAnthropicConverse(ctx, &infracontext.RequestContext{}, body, "amazon.nova-pro-v1:0")
		require.ErrorIs(t, err, ErrInvalidRequestPayload)
		assert.Contains(t, err.Error(), "top_k")
	})

	t.Run("another family on a fallback leg loses the fields", func(t *testing.T) {
		out, err := p.prepareAnthropicConverse(ctx, &infracontext.RequestContext{FallbackLeg: true}, body, "amazon.nova-pro-v1:0")
		require.NoError(t, err)
		assert.Nil(t, additionalFields(t, out))
	})
}

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
	body := []byte(`{"messages":[
		{"role":"user","content":[{"text":"q"}]},
		{"role":"assistant","content":[{"reasoningContent":{"reasoningText":{"text":"t","signature":"s"}}},{"text":"a"}]},
		{"role":"user","content":[{"text":"q2"}]}],
		"additionalModelRequestFields":{"top_k":40,"thinking":{"type":"adaptive"},"output_config":{"effort":"high"}}}`)
	betas := map[string][]string{"anthropic-beta": {"claude-code-20250219,interleaved-thinking-2025-05-14,oauth-2025-04-20"}}
	forward := map[string]any{"reasoning": "forward"}
	const claude = "eu.anthropic.claude-sonnet-4-5-20250929-v1:0"
	ctx := context.Background()

	t.Run("a registry that forwards reasoning sends it and the betas bedrock takes", func(t *testing.T) {
		got, err := p.prepareAnthropicConverse(ctx, &infracontext.RequestContext{Headers: betas}, forward, body, claude)
		require.NoError(t, err)
		assert.Equal(t, body, got.body)
		assert.Equal(t, "interleaved-thinking-2025-05-14", got.betas)
		assert.True(t, got.signedReasoning)
	})

	t.Run("by default reasoning and its history stay behind", func(t *testing.T) {
		got, err := p.prepareAnthropicConverse(ctx, &infracontext.RequestContext{Headers: betas}, nil, body, claude)
		require.NoError(t, err)
		assert.Empty(t, got.betas)
		assert.False(t, got.signedReasoning)
		assert.Equal(t, map[string]json.RawMessage{"top_k": json.RawMessage(`40`)}, additionalFields(t, got.body))
		assert.NotContains(t, string(got.body), "reasoningContent")
	})

	t.Run("a model the ID hides gets reasoning but no betas", func(t *testing.T) {
		got, err := p.prepareAnthropicConverse(ctx, &infracontext.RequestContext{Headers: betas}, forward, body,
			"arn:aws:bedrock:eu-west-1:1:application-inference-profile/x")
		require.NoError(t, err)
		assert.Empty(t, got.betas)
		assert.Equal(t, body, got.body)
	})

	t.Run("another family is refused on the routed leg", func(t *testing.T) {
		_, err := p.prepareAnthropicConverse(ctx, &infracontext.RequestContext{}, forward, body, "amazon.nova-pro-v1:0")
		require.ErrorIs(t, err, ErrInvalidRequestPayload)
		assert.Contains(t, err.Error(), "thinking")
	})

	t.Run("another family on a fallback leg loses the fields and the history", func(t *testing.T) {
		got, err := p.prepareAnthropicConverse(ctx, &infracontext.RequestContext{FallbackLeg: true, Headers: betas}, forward, body, "amazon.nova-pro-v1:0")
		require.NoError(t, err)
		assert.Empty(t, got.betas)
		assert.Nil(t, additionalFields(t, got.body))
		assert.NotContains(t, string(got.body), "reasoningContent")
	})
}

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

package tokenratelimit

import (
	"testing"

	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A native Bedrock InvokeModel answer reports its token counts in headers, so
// the invoker records them on the request and the budget must read them there
// on the buffered leg too, not only on a stream.
func TestExtractUsage_PrefersTheUsageTheInvokerObserved(t *testing.T) {
	t.Parallel()
	p := New(nil, adapter.NewRegistry(), nil)
	// A Mistral prompt-style answer: its body carries no usage at all.
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"outputs":[{"text":"Bonjour","stop_reason":"stop"}]}`)}

	t.Run("without the observed usage the body gives nothing", func(t *testing.T) {
		t.Parallel()
		req := &infracontext.RequestContext{SourceFormat: "bedrock", BedrockNative: &infracontext.BedrockNativeTarget{Op: "invoke"}}
		assert.Nil(t, p.extractUsage(req, resp))
	})

	t.Run("an empty usage entry on a call that is not native does not hide the body", func(t *testing.T) {
		t.Parallel()
		openai := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"id":"x","model":"gpt","choices":[{"message":{"role":"assistant","content":"hi"}}],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}`)}
		req := &infracontext.RequestContext{
			SourceFormat: "openai",
			Metadata:     map[string]interface{}{adapter.MetadataUsageKey: (*adapter.CanonicalUsage)(nil)},
		}
		got := p.extractUsage(req, openai)
		require.NotNil(t, got)
		assert.Equal(t, 6, got.TotalTokens)
	})

	t.Run("the observed usage is used on the buffered leg", func(t *testing.T) {
		t.Parallel()
		observed := &adapter.CanonicalUsage{InputTokens: 21, OutputTokens: 9, TotalTokens: 30}
		req := &infracontext.RequestContext{
			SourceFormat: "bedrock",
			Metadata:     map[string]interface{}{adapter.MetadataUsageKey: observed},
		}
		got := p.extractUsage(req, resp)
		require.NotNil(t, got)
		assert.Equal(t, 30, got.TotalTokens)
	})

	t.Run("the streamed leg still reads it", func(t *testing.T) {
		t.Parallel()
		observed := &adapter.CanonicalUsage{InputTokens: 2, OutputTokens: 1, TotalTokens: 3}
		req := &infracontext.RequestContext{Metadata: map[string]interface{}{adapter.MetadataUsageKey: observed}}
		got := p.extractUsage(req, &infracontext.ResponseContext{Streaming: true})
		require.NotNil(t, got)
		assert.Equal(t, 3, got.TotalTokens)
	})
}

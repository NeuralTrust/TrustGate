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

package promptcompression

import (
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
)

// The verbose JSON in each body would normally trigger compression; every
// case here must pass through untouched because re-encoding would drop
// content the canonical model does not represent.

func TestExecuteSkipsLossyShapes(t *testing.T) {
	t.Parallel()
	verboseJSON := `{\n  \"a\":   1,\n  \"b\":   2\n}`
	tests := []struct {
		name     string
		provider string
		body     string
	}{
		{
			name:     "multimodal image_url parts are never flattened",
			provider: openAIProvider,
			body: `{"model":"gpt-4o","messages":[{"role":"user","content":[` +
				`{"type":"text","text":"` + verboseJSON + `"},` +
				`{"type":"image_url","image_url":{"url":"https://example.com/x.png"}}]}]}`,
		},
		{
			name:     "anthropic cache_control annotations are preserved",
			provider: "anthropic",
			body: `{"model":"claude-3","system":"sys","messages":[{"role":"user","content":[` +
				`{"type":"text","text":"` + verboseJSON + `","cache_control":{"type":"ephemeral"}}]}],"max_tokens":100}`,
		},
		{
			name:     "unknown message fields are preserved",
			provider: openAIProvider,
			body:     `{"model":"gpt-4o","messages":[{"role":"user","name":"bob","content":"` + verboseJSON + `"}]}`,
		},
		{
			name:     "unmodeled top-level fields are preserved",
			provider: openAIProvider,
			body:     `{"model":"gpt-4o","seed":42,"messages":[{"role":"user","content":"` + verboseJSON + `"}]}`,
		},
		{
			name:     "unsupported wire format is never touched",
			provider: "gemini",
			body:     `{"contents":[{"role":"user","parts":[{"text":"` + verboseJSON + `"}]}]}`,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := New(adapter.NewRegistry(), nil)
			in := execInput(policy.StagePreRequest, policy.ModeEnforce, defaultSettings(), reqCtx(tt.provider, "", []byte(tt.body)), newEvent())
			res, err := p.Execute(context.Background(), in)
			assertPassThrough(t, res, err)
		})
	}
}

func TestRoundTripSafe(t *testing.T) {
	t.Parallel()
	assert.True(t, roundTripSafe([]byte(`{"messages":[{"role":"user","content":"hi"}]}`)))
	assert.True(t, roundTripSafe([]byte(`{"messages":[{"role":"assistant","content":null,"tool_calls":[{"id":"1","type":"function","function":{"name":"f","arguments":"{}"}}]}]}`)))
	assert.True(t, roundTripSafe([]byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)))
	assert.True(t, roundTripSafe([]byte(`{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"1","name":"ls","input":{}}]}]}`)))

	assert.False(t, roundTripSafe([]byte(`{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"u"}}]}]}`)))
	assert.False(t, roundTripSafe([]byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi","cache_control":{"type":"ephemeral"}}]}]}`)))
	assert.False(t, roundTripSafe([]byte(`{"messages":[{"role":"user","name":"bob","content":"hi"}]}`)))
	assert.False(t, roundTripSafe([]byte(`{"messages":[{"role":"assistant","tool_calls":[{"id":"1","custom":true}]}]}`)))
	assert.False(t, roundTripSafe([]byte(`not json`)))
}

func TestKeepsTopLevelFields(t *testing.T) {
	t.Parallel()
	original := []byte(`{"model":"m","seed":42,"messages":[]}`)
	assert.False(t, keepsTopLevelFields(original, []byte(`{"model":"m","messages":[]}`)), "dropped seed must be detected")
	assert.True(t, keepsTopLevelFields(original, []byte(`{"model":"m","seed":42,"messages":[]}`)))
	assert.True(t, keepsTopLevelFields([]byte(`{"model":"m","tool_choice":null}`), []byte(`{"model":"m"}`)), "null fields may be omitted")
}

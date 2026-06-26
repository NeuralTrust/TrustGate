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

package openaimoderation

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func TestJoinRequestText(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		req  *adapter.CanonicalRequest
		want string
	}{
		{name: "nil request", req: nil, want: ""},
		{name: "empty request", req: &adapter.CanonicalRequest{}, want: ""},
		{
			name: "system and messages joined",
			req: &adapter.CanonicalRequest{
				System: "you are helpful",
				Messages: []adapter.CanonicalMessage{
					{Role: "user", Content: "first"},
					{Role: "assistant", Content: "second"},
				},
			},
			want: "you are helpful\nfirst\nsecond",
		},
		{
			name: "blank parts skipped",
			req: &adapter.CanonicalRequest{
				System: "  ",
				Messages: []adapter.CanonicalMessage{
					{Role: "user", Content: ""},
					{Role: "user", Content: "kept"},
					{Role: "user", Content: "   "},
				},
			},
			want: "kept",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, joinRequestText(tt.req))
		})
	}
}

func TestResponseText(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "", responseText(nil))
	assert.Equal(t, "", responseText(&adapter.CanonicalResponse{}))
	assert.Equal(t, "answer", responseText(&adapter.CanonicalResponse{Content: "answer"}))
}

func TestJoinRequestTextFromDecodedProviders(t *testing.T) {
	t.Parallel()
	registry := adapter.NewRegistry()
	tests := []struct {
		name     string
		provider string
		body     string
	}{
		{
			name:     "openai",
			provider: "openai",
			body:     `{"model":"gpt-4o","messages":[{"role":"system","content":"sys text"},{"role":"user","content":"user text"}]}`,
		},
		{
			name:     "anthropic",
			provider: "anthropic",
			body:     `{"model":"claude-3","system":"sys text","max_tokens":16,"messages":[{"role":"user","content":"user text"}]}`,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			format, err := adapter.ResolveAgentFormat(tt.provider, "", nil)
			require.NoError(t, err)
			creq, err := registry.DecodeRequestFor([]byte(tt.body), format)
			require.NoError(t, err)
			text := joinRequestText(creq)
			assert.Contains(t, text, "sys text")
			assert.Contains(t, text, "user text")
		})
	}
}

func TestJoinRequestTextEmptyDecoded(t *testing.T) {
	t.Parallel()
	registry := adapter.NewRegistry()
	format, err := adapter.ResolveAgentFormat("openai", "", nil)
	require.NoError(t, err)
	creq, err := registry.DecodeRequestFor([]byte(`{"model":"gpt-4o","messages":[]}`), format)
	require.NoError(t, err)
	assert.Equal(t, "", joinRequestText(creq))
}

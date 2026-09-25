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

package toolallowlist

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlugin_Execute_KeepsToolCacheMarkers(t *testing.T) {
	t.Parallel()
	const (
		toolA = `{"name":"a","input_schema":{"type":"object","properties":{"z":{},"y":{}}}}`
		toolB = `{"name":"b","input_schema":{"type":"object"}}`
		toolC = `{"name":"c","input_schema":{"type":"object"},"cache_control":{"type":"ephemeral","ttl":"1h"}}`
	)
	body := func(tools string) string {
		return `{"model":"claude-sonnet-4-5","max_tokens":100,"system":[{"type":"text","text":"s","cache_control":{"type":"ephemeral","ttl":"1h"}}],` +
			`"tools":[` + tools + `],"tool_choice":{"type":"auto"},"messages":[{"role":"user","content":"hi"}]}`
	}

	t.Run("allowlist removes an unmarked tool", func(t *testing.T) {
		t.Parallel()
		res, err := run(New(adapter.NewRegistry()), policy.ModeEnforce, map[string]any{"allow_tools": []any{"a", "c"}}, reqFor("anthropic", body(toolA+","+toolB+","+toolC)))
		require.NoError(t, err)
		assert.Equal(t, body(toolA+","+toolC), string(res.RequestBody))
	})

	t.Run("marked tool removed moves the marker to the last kept tool", func(t *testing.T) {
		t.Parallel()
		res, err := run(New(adapter.NewRegistry()), policy.ModeEnforce, map[string]any{"allow_tools": []any{"a", "b"}}, reqFor("anthropic", body(toolA+","+toolB+","+toolC)))
		require.NoError(t, err)
		decoded, err := adapter.NewRegistry().DecodeRequestFor(res.RequestBody, adapter.FormatAnthropic)
		require.NoError(t, err)
		require.Len(t, decoded.Tools, 2)
		assert.Equal(t, []string{"a", "b"}, []string{decoded.Tools[0].Name, decoded.Tools[1].Name})
		assert.Nil(t, decoded.Tools[0].Cache)
		require.NotNil(t, decoded.Tools[1].Cache)
		assert.Equal(t, adapter.CacheTTL1h, decoded.Tools[1].Cache.TTL)
		assert.Contains(t, string(res.RequestBody), `"tools":[`+toolA+`,`)
		require.NotNil(t, decoded.SystemCache)
		assert.Equal(t, adapter.CacheTTL1h, decoded.SystemCache.TTL)
	})

	t.Run("openai chat keeps strict and the other keys", func(t *testing.T) {
		t.Parallel()
		in := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":[` +
			`{"type":"function","function":{"name":"lookup_clause","strict":true,"parameters":{"type":"object"}}},` +
			`{"type":"function","function":{"name":"shred_archive","parameters":{"type":"object"}}}],"tool_choice":"none","prompt_cache_key":"k","n":1}`
		res, err := run(New(adapter.NewRegistry()), policy.ModeEnforce, map[string]any{"allow_tools": []any{"lookup_*"}}, reqFor("openai", in))
		require.NoError(t, err)
		assert.Equal(t, `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":[`+
			`{"type":"function","function":{"name":"lookup_clause","strict":true,"parameters":{"type":"object"}}}],"tool_choice":"none","prompt_cache_key":"k","n":1}`, string(res.RequestBody))
	})
}

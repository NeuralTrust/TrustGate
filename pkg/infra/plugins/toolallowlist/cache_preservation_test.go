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

func TestPlugin_Execute_DropsToolsTheCanonicalDoesNotModel(t *testing.T) {
	t.Parallel()
	body := `{"model":"gpt-5","input":"hi","tools":[{"type":"function","name":"ok_a"},{"type":"function","name":"bad_b"},` +
		`{"type":"mcp","server_label":"x","server_url":"https://x.example/mcp"},{"type":"web_search"}]}`
	cases := []struct {
		name  string
		allow []any
		want  string
	}{
		{name: "patterns never reach them", allow: []any{"ok_*", "*"}, want: `{"model":"gpt-5","input":"hi","tools":[{"type":"function","name":"ok_a"}]}`},
		{name: "an exact type keeps one", allow: []any{"ok_*", "web_search"}, want: `{"model":"gpt-5","input":"hi","tools":[{"type":"function","name":"ok_a"},{"type":"web_search"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			settings := map[string]any{"allow_tools": tc.allow, "deny_tools": []any{"bad_*"}}
			res, err := run(New(adapter.NewRegistry()), policy.ModeEnforce, settings, reqFor("openai_responses", body))
			require.NoError(t, err)
			assert.Equal(t, tc.want, string(res.RequestBody))
		})
	}
}

func TestPlugin_Execute_EvaluatesUnmodelledToolsOnTheirOwn(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		format string
		allow  []any
		body   string
		want   string
	}{
		{
			name:   "a refused mcp tool goes though every function is allowed",
			format: "openai_responses",
			allow:  []any{"ok_*"},
			body:   `{"model":"gpt-5","input":"hi","tools":[{"type":"function","name":"ok_a"},{"type":"mcp","server_label":"x","server_url":"https://x.example/mcp"}]}`,
			want:   `{"model":"gpt-5","input":"hi","tools":[{"type":"function","name":"ok_a"}]}`,
		},
		{
			name:   "only unmodelled tools",
			format: "openai_responses",
			allow:  []any{"web_search"},
			body:   `{"model":"gpt-5","input":"hi","tools":[{"type":"web_search"},{"type":"mcp","server_label":"x","server_url":"https://x.example/mcp"}]}`,
			want:   `{"model":"gpt-5","input":"hi","tools":[{"type":"web_search"}]}`,
		},
		{
			name:   "a kind that is not a built-in is refused even when named",
			format: "openai_responses",
			allow:  []any{"ok_*", "mcp_toolset"},
			body:   `{"model":"gpt-5","input":"hi","tools":[{"type":"function","name":"ok_a"},{"type":"mcp_toolset","server":"x"}]}`,
			want:   `{"model":"gpt-5","input":"hi","tools":[{"type":"function","name":"ok_a"}]}`,
		},
		{
			name:   "a built-in sharing a function's name",
			format: "openai_responses",
			allow:  []any{"ok_*"},
			body:   `{"model":"gpt-5","input":"hi","tools":[{"type":"function","name":"ok_a"},{"type":"mcp","name":"ok_a","server_url":"https://x.example/mcp"}]}`,
			want:   `{"model":"gpt-5","input":"hi","tools":[{"type":"function","name":"ok_a"}]}`,
		},
		{
			name:   "gemini keeps an allowed built-in beside its declarations",
			format: "google",
			allow:  []any{"ok_*", "googleSearch"},
			body:   `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"ok_a"},{"name":"bad_b"}]},{"googleSearch":{}},{"codeExecution":{}}]}`,
			want:   `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"ok_a"}]},{"googleSearch":{}}]}`,
		},
		{
			name:   "bedrock system tool",
			format: "bedrock",
			allow:  []any{"ok_*"},
			body:   `{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[{"toolSpec":{"name":"ok_a","inputSchema":{"json":{"type":"object"}}}},{"systemTool":{"name":"nova_grounding"}}]}}`,
			want:   `{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[{"toolSpec":{"name":"ok_a","inputSchema":{"json":{"type":"object"}}}}]}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, err := run(New(adapter.NewRegistry()), policy.ModeEnforce, map[string]any{"allow_tools": tc.allow}, reqFor(tc.format, tc.body))
			require.NoError(t, err)
			assert.Equal(t, tc.want, string(res.RequestBody))
		})
	}

	t.Run("nothing left is rejected", func(t *testing.T) {
		t.Parallel()
		body := `{"model":"gpt-5","input":"hi","tools":[{"type":"mcp","server_label":"x","server_url":"https://x.example/mcp"}]}`
		res, err := run(New(adapter.NewRegistry()), policy.ModeEnforce, map[string]any{"allow_tools": []any{"*"}}, reqFor("openai_responses", body))
		require.NoError(t, err)
		assert.True(t, res.StopUpstream)
	})
	t.Run("allowed built-ins pass untouched", func(t *testing.T) {
		t.Parallel()
		body := `{"model":"gpt-5","input":"hi","tools":[{"type":"function","name":"ok_a"},{"type":"web_search"}]}`
		res, err := run(New(adapter.NewRegistry()), policy.ModeEnforce, map[string]any{"allow_tools": []any{"ok_*", "web_search"}}, reqFor("openai_responses", body))
		require.NoError(t, err)
		assert.Nil(t, res.RequestBody)
	})
}

func TestIsBuiltinTool(t *testing.T) {
	t.Parallel()
	reg := adapter.NewRegistry()
	for format, kinds := range map[adapter.Format]map[string]bool{
		adapter.FormatOpenAIResponses: {"mcp": true, "web_search_preview": true, "function": false, "mcp_toolset": false, "": false},
		adapter.FormatOpenAI:          {"mcp": false, "web_search": false},
		adapter.FormatAnthropic:       {"web_search_20250305": true, "code_execution_20250825": true, "bash_20250124": true, "text_editor_20250728": true, "bash": false, "bash_latest": false, "mcp_servers": true},
		adapter.FormatGemini:          {"googleSearch": true, "url_context": true, "functionDeclarations": false},
		adapter.FormatBedrock:         {"systemTool:nova_grounding": true, "systemTool": false, "systemTool:": false, "toolSpec": false},
	} {
		ad, err := reg.GetAdapter(format)
		require.NoError(t, err)
		for kind, want := range kinds {
			assert.Equal(t, want, isBuiltinTool(ad, kind), "%s %q", format, kind)
		}
	}
}

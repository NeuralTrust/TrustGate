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
	"fmt"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const evilMCP = `{"type":"mcp","server_label":"x","server_url":"https://evil.example/mcp"}`

func TestPlugin_Execute_NeverForwardsAnAmbiguousBody(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, format, body string
	}{
		{"a repeated model", "openai_responses", `{"model":"gpt-5","input":"hi","tools":[` + evilMCP + `],"model":"gpt-5"}`},
		{"a case variant of tools", "openai_responses", `{"model":"gpt-5","input":"hi","tools":[` + evilMCP + `],"Tools":[]}`},
		{"a case variant of tools first", "openai_responses", `{"model":"gpt-5","input":"hi","Tools":[],"tools":[` + evilMCP + `]}`},
		{"bedrock toolConfig and toolconfig", "bedrock", `{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[{"systemTool":{"name":"nova_grounding"}}]},"toolconfig":null}`},
		{"bedrock toolConfig.Tools", "bedrock", `{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[{"systemTool":{"name":"nova_grounding"}}],"Tools":[]}}`},
		{"gemini TOOLS", "google", `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"googleSearch":{}}],"TOOLS":null}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, err := run(New(adapter.NewRegistry()), policy.ModeEnforce, map[string]any{"allow_tools": []any{"ok"}}, reqFor(tc.format, tc.body))
			require.NoError(t, err)
			require.NotNil(t, res)
			assert.True(t, res.StopUpstream, "want a refusal, got %s", res.RequestBody)
		})
	}

	t.Run("allowed tools in an ambiguous body are re-encoded", func(t *testing.T) {
		t.Parallel()
		body := `{"model":"gpt-5","input":"hi","tools":[{"type":"function","name":"ok"}],"Input":"hi"}`
		res, err := run(New(adapter.NewRegistry()), policy.ModeEnforce, map[string]any{"allow_tools": []any{"ok"}}, reqFor("openai_responses", body))
		require.NoError(t, err)
		require.NotEmpty(t, res.RequestBody)
		assert.False(t, adapter.HasAmbiguousKeys(adapter.FormatOpenAIResponses, res.RequestBody), string(res.RequestBody))
		assert.Contains(t, string(res.RequestBody), `"name":"ok"`)
	})
	t.Run("observe leaves it alone", func(t *testing.T) {
		t.Parallel()
		body := `{"model":"gpt-5","input":"hi","tools":[{"type":"function","name":"ok"}],"Input":"hi"}`
		res, err := run(New(adapter.NewRegistry()), policy.ModeObserve, map[string]any{"allow_tools": []any{"ok"}}, reqFor("openai_responses", body))
		require.NoError(t, err)
		assert.Nil(t, res.RequestBody)
	})
}

func TestPlugin_Execute_UnmodelledToolRules(t *testing.T) {
	t.Parallel()
	const anthropic = `{"model":"c","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"tools":[`
	const webSearch = `{"type":"web_search_20250305","name":"web_search","max_uses":5}`
	const fn = `{"name":"f","input_schema":{"type":"object"}}`
	cases := []struct {
		name, format, body string
		allow, deny        []any
		want               string
	}{
		{
			name: "deny-only keeps a built-in no pattern names", format: "openai_responses",
			body: `{"model":"gpt-5","input":"hi","tools":[{"type":"web_search"},{"type":"function","name":"f"},{"type":"function","name":"evil"}]}`,
			deny: []any{"evil"},
			want: `{"model":"gpt-5","input":"hi","tools":[{"type":"web_search"},{"type":"function","name":"f"}]}`,
		},
		{
			name: "deny-only matches a built-in by kind", format: "openai_responses",
			body: `{"model":"gpt-5","input":"hi","tools":[{"type":"web_search"},{"type":"function","name":"f"}]}`,
			deny: []any{"web_*"},
			want: `{"model":"gpt-5","input":"hi","tools":[{"type":"function","name":"f"}]}`,
		},
		{
			name: "deny-only matches a built-in by name", format: "openai_responses",
			body: `{"model":"gpt-5","input":"hi","tools":[{"type":"mcp","name":"shell","server_url":"https://x"},{"type":"function","name":"f"}]}`,
			deny: []any{"shell"},
			want: `{"model":"gpt-5","input":"hi","tools":[{"type":"function","name":"f"}]}`,
		},
		{
			name: "anthropic server tool allowed by its type", format: "anthropic",
			body:  anthropic + webSearch + `,` + fn + `]}`,
			allow: []any{"web_search_20250305"},
			want:  anthropic + webSearch + `]}`,
		},
		{
			name: "anthropic server tool denied by its type", format: "anthropic",
			body: anthropic + webSearch + `,` + fn + `]}`,
			deny: []any{"web_search_*"},
			want: anthropic + fn + `]}`,
		},
		{
			name: "gemini snake case declarations are filtered", format: "google",
			body:  `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"function_declarations":[{"name":"f"},{"name":"evil"}]}]}`,
			allow: []any{"f"},
			want:  `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"f"}]}]}`,
		},
		{
			name: "gemini mixed tool object is split", format: "google",
			body:  `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"f"}],"googleSearch":{},"codeExecution":{}}]}`,
			allow: []any{"f", "googleSearch"},
			want:  `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"f"}]},{"googleSearch":{}}]}`,
		},
		{
			name: "gemini built-in denied under its other spelling", format: "google",
			body: `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"f"}]},{"codeExecution":{}}]}`,
			deny: []any{"code_execution"},
			want: `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"f"}]}]}`,
		},
		{
			name: "gemini snake case built-in denied by camel case", format: "google",
			body: `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"f"}]},{"google_search":{}}]}`,
			deny: []any{"googleSearch"},
			want: `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"f"}]}]}`,
		},
		{
			name: "gemini built-in allowed under its other spelling", format: "google",
			body:  `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"f"},{"name":"evil"}]},{"url_context":{}}]}`,
			allow: []any{"f", "urlContext"},
			want:  `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"f"}]},{"url_context":{}}]}`,
		},
		{
			name: "chat legacy functions are judged by name", format: "openai",
			body:  `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"functions":[{"name":"f","parameters":{"type":"object"}},{"name":"evil"}],"function_call":{"name":"evil"}}`,
			allow: []any{"f"},
			want:  `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"functions":[{"name":"f","parameters":{"type":"object"}}]}`,
		},
		{
			name: "anthropic mcp servers need an exact allow", format: "anthropic",
			body:  anthropic + fn + `],"mcp_servers":[{"type":"url","url":"https://evil.example","name":"e"}]}`,
			allow: []any{"f"},
			want:  anthropic + fn + `]}`,
		},
		{
			name: "anthropic mcp servers kept when allowed", format: "anthropic",
			body:  anthropic + fn + `],"mcp_servers":[{"type":"url","url":"https://x.example","name":"e"}]}`,
			allow: []any{"f", "mcp_servers"},
			want:  "",
		},
		{
			name: "a type key in other case", format: "openai_responses",
			body:  `{"model":"gpt-5","input":"hi","tools":[{"type":"function","name":"f"},{"Type":"mcp","server_url":"https://evil"}]}`,
			allow: []any{"f"},
			want:  `{"model":"gpt-5","input":"hi","tools":[{"type":"function","name":"f"}]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			settings := map[string]any{}
			if tc.allow != nil {
				settings["allow_tools"] = tc.allow
			}
			if tc.deny != nil {
				settings["deny_tools"] = tc.deny
			}
			res, err := run(New(adapter.NewRegistry()), policy.ModeEnforce, settings, reqFor(tc.format, tc.body))
			require.NoError(t, err)
			require.False(t, res.StopUpstream, string(res.Body))
			assert.Equal(t, tc.want, string(res.RequestBody))
		})
	}
}

func TestPlugin_Execute_RefusesOnlyBuiltinsAllowToolsDoesNotName(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		`{"model":"gpt-5","input":"hi","tools":[{"type":"web_search"}]}`,
		`{"model":"gpt-5","input":"hi","tools":[{"type":"mcp","name":"f","server_url":"https://evil"}]}`,
		`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"functions":[{"name":"evil"}]}`,
	} {
		format := "openai_responses"
		if strings.Contains(body, "functions") {
			format = "openai"
		}
		res, err := run(New(adapter.NewRegistry()), policy.ModeEnforce, map[string]any{"allow_tools": []any{"f"}}, reqFor(format, body))
		require.NoError(t, err)
		assert.True(t, res.StopUpstream, body)
	}
}

func TestPlugin_Execute_EmptyAfterFilterRemovesBedrockToolConfig(t *testing.T) {
	t.Parallel()
	body := `{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[{"toolSpec":{"name":"evil","inputSchema":{"json":{"type":"object"}}}}],"toolChoice":{"auto":{}}}}`
	for _, onEmpty := range []string{onEmptyStripField, onEmptyPassThrough} {
		res, err := run(New(adapter.NewRegistry()), policy.ModeEnforce, map[string]any{"allow_tools": []any{"f"}, "on_empty_after_filter": onEmpty}, reqFor("bedrock", body))
		require.NoError(t, err)
		assert.Equal(t, `{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`, string(res.RequestBody), onEmpty)
	}
}

func TestPlugin_Execute_CountsAnUnnamedServerToolOnce(t *testing.T) {
	t.Parallel()
	body := `{"model":"c","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"web_search_20250305"},{"name":"f","input_schema":{"type":"object"}}]}`
	p := New(adapter.NewRegistry())
	res, err := run(p, policy.ModeEnforce, map[string]any{"allow_tools": []any{"f"}}, reqFor("anthropic", body))
	require.NoError(t, err)
	assert.Equal(t, `{"model":"c","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"tools":[{"name":"f","input_schema":{"type":"object"}}]}`, string(res.RequestBody))

	ad, err := adapter.NewRegistry().GetAdapter(adapter.FormatAnthropic)
	require.NoError(t, err)
	canonical, err := ad.DecodeRequest([]byte(body))
	require.NoError(t, err)
	cfg, err := parseConfig(map[string]any{"allow_tools": []any{"f"}})
	require.NoError(t, err)
	kept, removed, keptCount, removedCount := newToolFilter(ad, adapter.FormatAnthropic, []byte(body), canonical, cfg).split()
	assert.Equal(t, []string{"f"}, kept)
	assert.Equal(t, []string{"web_search_20250305"}, removed)
	assert.Equal(t, 1, keptCount)
	assert.Equal(t, 1, removedCount)
}

func TestPlugin_Execute_RewritesAToolChoiceNamingARemovedTool(t *testing.T) {
	t.Parallel()
	body := `{"model":"c","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"tools":[{"name":"f","input_schema":{"type":"object"}},{"name":"evil","input_schema":{"type":"object"}}],"tool_choice":{"type":"tool","name":"evil"}}`
	res, err := run(New(adapter.NewRegistry()), policy.ModeEnforce, map[string]any{"allow_tools": []any{"f"}}, reqFor("anthropic", body))
	require.NoError(t, err)
	assert.Equal(t, `{"model":"c","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"tools":[{"name":"f","input_schema":{"type":"object"}}],"tool_choice":{"type":"auto"}}`, string(res.RequestBody))
}

func TestPlugin_Execute_ForwardsOnlyTheToolsItJudged(t *testing.T) {
	t.Parallel()
	const (
		chatFn  = `{"type":"function","function":{"name":"%s","parameters":{"type":"object"}}}`
		respFn  = `{"type":"function","name":"%s","parameters":{"type":"object"}}`
		antFn   = `{"name":"%s","input_schema":{"type":"object"}}`
		chat    = `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],`
		resp    = `{"model":"gpt-5","input":"hi",`
		ant     = `{"model":"c","max_tokens":10,"messages":[{"role":"user","content":"hi"}],`
		bedrock = `{"messages":[{"role":"user","content":[{"text":"hi"}]}],`
		gemini  = `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],`
	)
	tool := func(shape, name string) string { return fmt.Sprintf(shape, name) }
	cases := []struct{ name, format, body string }{
		{"chat tools then TOOLS", "openai", chat + `"tools":[` + tool(chatFn, "rm_rf") + `],"TOOLS":[` + tool(chatFn, "get_weather") + `]}`},
		{"chat repeated tools", "openai", chat + `"tools":[` + tool(chatFn, "rm_rf") + `],"tools":[` + tool(chatFn, "get_weather") + `]}`},
		{"chat function Name", "openai", chat + `"tools":[{"type":"function","function":{"name":"rm_rf","Name":"get_weather","parameters":{"type":"object"}}}]}`},
		{"responses tools then Tools", "openai_responses", resp + `"tools":[` + tool(respFn, "rm_rf") + `],"Tools":[` + tool(respFn, "get_weather") + `]}`},
		{"anthropic tools then Tools", "anthropic", ant + `"tools":[` + tool(antFn, "rm_rf") + `],"Tools":[` + tool(antFn, "get_weather") + `]}`},
		{"bedrock toolConfig then toolconfig", "bedrock", bedrock + `"toolConfig":{"tools":[{"toolSpec":{"name":"rm_rf","inputSchema":{"json":{"type":"object"}}}}]},"toolconfig":{"tools":[{"toolSpec":{"name":"get_weather","inputSchema":{"json":{"type":"object"}}}}]}}`},
		{"gemini tools then Tools", "google", gemini + `"tools":[{"functionDeclarations":[{"name":"rm_rf"}]}],"Tools":[{"functionDeclarations":[{"name":"get_weather"}]}]}`},
		{"chat legacy functions beside tools", "openai", chat + `"tools":[` + tool(chatFn, "get_weather") + `],"functions":[{"name":"rm_rf","parameters":{"type":"object"}}],"function_call":{"name":"rm_rf"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, err := run(New(adapter.NewRegistry()), policy.ModeEnforce, map[string]any{"allow_tools": []any{"get_weather"}}, reqFor(tc.format, tc.body))
			require.NoError(t, err)
			require.False(t, res.StopUpstream, string(res.Body))
			require.NotEmpty(t, res.RequestBody, "the body the plugin judged must be the one sent")
			assert.NotContains(t, string(res.RequestBody), "rm_rf")
			assert.Contains(t, string(res.RequestBody), "get_weather")
			assert.False(t, adapter.HasAmbiguousKeys(adapter.Format(tc.format), res.RequestBody), string(res.RequestBody))
		})
	}

	t.Run("chat legacy functions alone", func(t *testing.T) {
		t.Parallel()
		body := chat + `"functions":[{"name":"rm_rf","parameters":{"type":"object"}}]}`
		res, err := run(New(adapter.NewRegistry()), policy.ModeEnforce, map[string]any{"allow_tools": []any{"get_weather"}}, reqFor("openai", body))
		require.NoError(t, err)
		assert.True(t, res.StopUpstream)
		assert.Contains(t, string(res.Body), "functions:rm_rf")
	})
}

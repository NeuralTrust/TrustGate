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

func TestPlugin_Execute_KeepsToolChoicesConsistent(t *testing.T) {
	t.Parallel()
	const (
		responses = `{"model":"gpt-5","input":"hi","tools":[{"type":"function","name":"f","parameters":{"type":"object"}},{"type":"function","name":"g","parameters":{"type":"object"}}`
		kept      = `{"model":"gpt-5","input":"hi","tools":[{"type":"function","name":"f","parameters":{"type":"object"}}]`
		gemini    = `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"f"},{"name":"g"}]}]`
		geminiF   = `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"f"}]}]`
	)
	cases := []struct {
		name, format, body string
		allow              []any
		want               string
	}{
		{
			name: "responses function choice for a removed tool", format: "openai_responses",
			body:  `{"model":"gpt-5","input":"hi","store":false,"reasoning":{"effort":"high","summary":"auto"},"tools":[{"type":"function","name":"f","parameters":{"type":"object"}},{"type":"function","name":"g","parameters":{"type":"object"}}],"tool_choice":{"type":"function","name":"g"}}`,
			allow: []any{"f"},
			want:  `{"model":"gpt-5","input":"hi","store":false,"reasoning":{"effort":"high","summary":"auto"},"tools":[{"type":"function","name":"f","parameters":{"type":"object"}}],"tool_choice":"auto"}`,
		},
		{
			name: "responses function choice for a kept tool", format: "openai_responses",
			body:  responses + `],"tool_choice":{"type":"function","name":"f"}}`,
			allow: []any{"f"},
			want:  kept + `,"tool_choice":{"type":"function","name":"f"}}`,
		},
		{
			name: "responses allowed_tools with only removed tools", format: "openai_responses",
			body:  responses + `],"tool_choice":{"type":"allowed_tools","mode":"required","tools":[{"type":"function","name":"g"}]}}`,
			allow: []any{"f"},
			want:  kept + `,"tool_choice":"auto"}`,
		},
		{
			name: "responses allowed_tools keeps the tools that stay", format: "openai_responses",
			body:  responses + `,{"type":"web_search_preview"}],"tool_choice":{"type":"allowed_tools","mode":"required","tools":[{"type":"function","name":"g"},{"type":"function","name":"f"},{"type":"web_search_preview"}]}}`,
			allow: []any{"f", "web_search_preview"},
			want:  kept[:len(kept)-1] + `,{"type":"web_search_preview"}],"tool_choice":{"type":"allowed_tools","mode":"required","tools":[{"type":"function","name":"f"},{"type":"web_search_preview"}]}}`,
		},
		{
			name: "responses built-in choice for a removed built-in", format: "openai_responses",
			body:  responses + `,{"type":"web_search_preview"}],"tool_choice":{"type":"web_search_preview"}}`,
			allow: []any{"f"},
			want:  kept + `,"tool_choice":"auto"}`,
		},
		{
			name: "gemini allowedFunctionNames with only removed names", format: "google",
			body:  gemini + `,"toolConfig":{"functionCallingConfig":{"mode":"ANY","allowedFunctionNames":["g"]}}}`,
			allow: []any{"f"},
			want:  geminiF + `,"toolConfig":{"functionCallingConfig":{"mode":"AUTO"}}}`,
		},
		{
			name: "gemini allowedFunctionNames keeps the names that stay", format: "google",
			body:  gemini + `,"toolConfig":{"functionCallingConfig":{"mode":"ANY","allowedFunctionNames":["g","f"]}}}`,
			allow: []any{"f"},
			want:  geminiF + `,"toolConfig":{"functionCallingConfig":{"mode":"ANY","allowedFunctionNames":["f"]}}}`,
		},
		{
			name: "gemini snake_case config with no mode", format: "google",
			body:  gemini + `,"tool_config":{"function_calling_config":{"allowed_function_names":["g"]}}}`,
			allow: []any{"f"},
			want:  geminiF + `,"tool_config":{"function_calling_config":{"mode":"AUTO"}}}`,
		},
		{
			name: "gemini forced mode once no declaration stays", format: "google",
			body:  `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"g"}]},{"googleSearch":{}}],"toolConfig":{"functionCallingConfig":{"mode":"ANY"}}}`,
			allow: []any{"googleSearch"},
			want:  `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"googleSearch":{}}],"toolConfig":{"functionCallingConfig":{"mode":"AUTO"}}}`,
		},
		{
			name: "gemini forced mode while a declaration stays", format: "google",
			body:  gemini + `,"toolConfig":{"functionCallingConfig":{"mode":"VALIDATED"}}}`,
			allow: []any{"f"},
			want:  geminiF + `,"toolConfig":{"functionCallingConfig":{"mode":"VALIDATED"}}}`,
		},
		{
			name: "chat function_call goes with the last legacy function", format: "openai",
			body:  `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object"}}}],"functions":[{"name":"g","parameters":{"type":"object"}}],"function_call":"auto"}`,
			allow: []any{"f"},
			want:  `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object"}}}]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, err := run(New(adapter.NewRegistry()), policy.ModeEnforce, map[string]any{"allow_tools": tc.allow}, reqFor(tc.format, tc.body))
			require.NoError(t, err)
			require.False(t, res.StopUpstream, string(res.Body))
			assert.Equal(t, tc.want, string(res.RequestBody))
		})
	}
}

func TestPlugin_Execute_EmptyAfterFilterKeepsBedrockToolHistoryValid(t *testing.T) {
	t.Parallel()
	const messages = `{"messages":[{"role":"user","content":[{"text":"hi"}]},{"role":"assistant","content":[{"toolUse":{"toolUseId":"1","name":"g","input":{}}}]},{"role":"user","content":[{"toolResult":{"toolUseId":"1","content":[{"text":"x"}]}}]}]`
	body := messages + `,"toolConfig":{"tools":[{"toolSpec":{"name":"g","inputSchema":{"json":{"type":"object"}}}}],"toolChoice":{"tool":{"name":"g"}}}}`
	for _, onEmpty := range []string{onEmptyStripField, onEmptyPassThrough} {
		res, err := run(New(adapter.NewRegistry()), policy.ModeEnforce, map[string]any{"allow_tools": []any{"f"}, "on_empty_after_filter": onEmpty}, reqFor("bedrock", body))
		require.NoError(t, err)
		want := messages + `,"toolConfig":{"tools":[{"toolSpec":{"name":"no_tools_available","description":"No tools are available for this request. Do not call this tool.","inputSchema":{"json":{"properties":{},"type":"object"}}}}]}}`
		assert.Equal(t, want, string(res.RequestBody), onEmpty)
	}
}

func TestPlugin_Execute_KeepsAnMCPToolsetWithItsServer(t *testing.T) {
	t.Parallel()
	const (
		head    = `{"model":"c","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"tools":[`
		fn      = `{"name":"f","input_schema":{"type":"object"}}`
		toolset = `{"type":"mcp_toolset","mcp_server_name":"a"}`
		servers = `"mcp_servers":[{"type":"url","url":"https://a","name":"a"}]`
		bare    = head + fn + `]}`
	)
	body := head + fn + `,` + toolset + `],` + servers + `}`
	cases := []struct {
		name        string
		allow, deny []any
		want        string
	}{
		{"deny-only keeps the pair", nil, []any{"zzz"}, ""},
		{"allow naming both kinds keeps the pair", []any{"f", "mcp_servers", "mcp_toolset"}, nil, ""},
		{"allow naming only the servers drops the pair", []any{"f", "mcp_servers"}, nil, bare},
		{"allow naming only the toolset drops the pair", []any{"f", "mcp_toolset"}, nil, bare},
		{"denying the server name drops the pair", nil, []any{"a"}, bare},
		{"denying the toolset kind drops the pair", nil, []any{"mcp_toolset"}, bare},
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
			res, err := run(New(adapter.NewRegistry()), policy.ModeEnforce, settings, reqFor("anthropic", body))
			require.NoError(t, err)
			require.False(t, res.StopUpstream, string(res.Body))
			assert.Equal(t, tc.want, string(res.RequestBody))
		})
	}

	t.Run("a toolset with no server name is refused", func(t *testing.T) {
		t.Parallel()
		body := head + fn + `,{"type":"mcp_toolset"}]}`
		res, err := run(New(adapter.NewRegistry()), policy.ModeEnforce, map[string]any{"deny_tools": []any{"zzz"}}, reqFor("anthropic", body))
		require.NoError(t, err)
		assert.Equal(t, bare, string(res.RequestBody))
	})
	t.Run("the event labels the toolset by its server", func(t *testing.T) {
		t.Parallel()
		ad, err := adapter.NewRegistry().GetAdapter(adapter.FormatAnthropic)
		require.NoError(t, err)
		canonical, err := ad.DecodeRequest([]byte(body))
		require.NoError(t, err)
		cfg, err := parseConfig(map[string]any{"allow_tools": []any{"f", "mcp_servers"}})
		require.NoError(t, err)
		kept, removed, _, _ := newToolFilter(ad, []byte(body), canonical, cfg).split()
		assert.Equal(t, []string{"f"}, kept)
		assert.ElementsMatch(t, []string{"mcp_toolset:a", "mcp_servers:a"}, removed)
	})
}

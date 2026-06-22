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
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func openaiBody(names ...string) string {
	tools := make([]string, 0, len(names))
	for _, n := range names {
		tools = append(tools, fmt.Sprintf(`{"type":"function","function":{"name":%q,"parameters":{"type":"object"}}}`, n))
	}
	return fmt.Sprintf(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":[%s],"tool_choice":"auto","parallel_tool_calls":true}`, strings.Join(tools, ","))
}

func anthropicBody(names ...string) string {
	tools := make([]string, 0, len(names))
	for _, n := range names {
		tools = append(tools, fmt.Sprintf(`{"name":%q,"input_schema":{"type":"object"}}`, n))
	}
	return fmt.Sprintf(`{"model":"claude-3-5-sonnet","max_tokens":100,"messages":[{"role":"user","content":"hi"}],"tools":[%s]}`, strings.Join(tools, ","))
}

func reqFor(format, body string) *infracontext.RequestContext {
	return &infracontext.RequestContext{
		Body:         []byte(body),
		SourceFormat: format,
		Provider:     format,
	}
}

func run(p *Plugin, mode policy.Mode, settings map[string]any, req *infracontext.RequestContext) (*appplugins.Result, error) {
	return p.Execute(context.Background(), appplugins.ExecInput{
		Stage:   policy.StagePreRequest,
		Mode:    mode,
		Config:  policy.PluginConfig{ID: "ta-1", Slug: PluginName, Name: PluginName, Settings: settings},
		Request: req,
		Event:   metrics.NewEventContext(nil),
	})
}

func bodyMap(t *testing.T, raw []byte) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &m))
	return m
}

func openaiNames(t *testing.T, raw []byte) []string {
	t.Helper()
	var body struct {
		Tools []struct {
			Function struct {
				Name string `json:"name"`
			} `json:"function"`
		} `json:"tools"`
	}
	require.NoError(t, json.Unmarshal(raw, &body))
	names := make([]string, 0, len(body.Tools))
	for _, tl := range body.Tools {
		names = append(names, tl.Function.Name)
	}
	return names
}

func anthropicNames(t *testing.T, raw []byte) []string {
	t.Helper()
	var body struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	require.NoError(t, json.Unmarshal(raw, &body))
	names := make([]string, 0, len(body.Tools))
	for _, tl := range body.Tools {
		names = append(names, tl.Name)
	}
	return names
}

func TestPlugin_StagesModesName(t *testing.T) {
	p := New(adapter.NewRegistry())
	assert.Equal(t, PluginName, p.Name())
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, p.MandatoryStages())
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, p.SupportedStages())
	assert.Equal(t, []policy.Mode{policy.ModeEnforce, policy.ModeObserve}, p.SupportedModes())
	var _ appplugins.Plugin = p
}

func TestPlugin_ValidateConfig(t *testing.T) {
	p := New(adapter.NewRegistry())
	require.NoError(t, p.ValidateConfig(map[string]any{"allow_tools": []string{"search_*"}}))
	require.Error(t, p.ValidateConfig(map[string]any{}))
}

func TestPlugin_Execute(t *testing.T) {
	tests := []struct {
		name     string
		mode     policy.Mode
		settings map[string]any
		req      *infracontext.RequestContext
		check    func(t *testing.T, res *appplugins.Result, err error)
	}{
		{
			name:     "openai allow-only keeps matches",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"search_*", "calculate"}},
			req:      reqFor("openai", openaiBody("search_web", "calculate", "delete_db")),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				assert.False(t, res.StopUpstream)
				require.NotNil(t, res.RequestBody)
				assert.Equal(t, []string{"search_web", "calculate"}, openaiNames(t, res.RequestBody))
			},
		},
		{
			name:     "openai deny-only removes matches",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"deny_tools": []string{"delete_*"}},
			req:      reqFor("openai", openaiBody("search_web", "delete_db", "delete_file")),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				require.NotNil(t, res.RequestBody)
				assert.Equal(t, []string{"search_web"}, openaiNames(t, res.RequestBody))
			},
		},
		{
			name:     "allow then deny precedence removes allowed",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"search_*"}, "deny_tools": []string{"search_internal"}},
			req:      reqFor("openai", openaiBody("search_web", "search_internal", "calculate")),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				require.NotNil(t, res.RequestBody)
				assert.Equal(t, []string{"search_web"}, openaiNames(t, res.RequestBody))
			},
		},
		{
			name:     "character-class and single-char globs",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"deny_tools": []string{"admin_?", "db_[rw]*"}},
			req:      reqFor("openai", openaiBody("admin_x", "db_read", "report")),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				require.NotNil(t, res.RequestBody)
				assert.Equal(t, []string{"report"}, openaiNames(t, res.RequestBody))
			},
		},
		{
			name:     "partial strip preserves tool_choice and parallel_tool_calls",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"deny_tools": []string{"delete_*"}},
			req:      reqFor("openai", openaiBody("search_web", "delete_db")),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				require.NotNil(t, res.RequestBody)
				assert.Equal(t, []string{"search_web"}, openaiNames(t, res.RequestBody))
				m := bodyMap(t, res.RequestBody)
				assert.JSONEq(t, `"auto"`, string(m["tool_choice"]))
				assert.JSONEq(t, `true`, string(m["parallel_tool_calls"]))
			},
		},
		{
			name:     "allow-only removes unnamed tools",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"search_*"}},
			req:      reqFor("openai", `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"search_web","parameters":{"type":"object"}}},{"type":"function","function":{"parameters":{"type":"object"}}}],"tool_choice":"auto"}`),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				require.NotNil(t, res.RequestBody)
				assert.Equal(t, []string{"search_web"}, openaiNames(t, res.RequestBody))
			},
		},
		{
			name:     "no-change pass is byte-stable",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"*"}},
			req:      reqFor("openai", openaiBody("search_web", "calculate")),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				assert.Nil(t, res.RequestBody)
				assert.False(t, res.StopUpstream)
				assert.Equal(t, 200, res.StatusCode)
			},
		},
		{
			name:     "empty after filter rejects with no_tools_allowed body",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"search_*"}},
			req:      reqFor("openai", openaiBody("delete_db", "calculate")),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				require.NotNil(t, res)
				assert.True(t, res.StopUpstream)
				assert.Equal(t, 403, res.StatusCode)
				assert.Equal(t, []string{"application/json"}, res.Headers["Content-Type"])
				assert.JSONEq(t, `{"error":{"type":"no_tools_allowed","requested":["delete_db","calculate"],"allowed_after_filter":[]}}`, string(res.Body))
				assert.Nil(t, res.RequestBody)
			},
		},
		{
			name:     "empty after filter strip_tools_field drops three keys",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"search_*"}, "on_empty_after_filter": "strip_tools_field"},
			req:      reqFor("openai", openaiBody("delete_db")),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				require.NotNil(t, res.RequestBody)
				assert.False(t, res.StopUpstream)
				m := bodyMap(t, res.RequestBody)
				_, hasTools := m["tools"]
				_, hasChoice := m["tool_choice"]
				_, hasParallel := m["parallel_tool_calls"]
				assert.False(t, hasTools)
				assert.False(t, hasChoice)
				assert.False(t, hasParallel)
				assert.Contains(t, m, "model")
				assert.Contains(t, m, "messages")
			},
		},
		{
			name:     "empty after filter pass_through_empty keeps empty array",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"search_*"}, "on_empty_after_filter": "pass_through_empty"},
			req:      reqFor("openai", openaiBody("delete_db")),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				require.NotNil(t, res.RequestBody)
				m := bodyMap(t, res.RequestBody)
				assert.JSONEq(t, `[]`, string(m["tools"]))
				_, hasChoice := m["tool_choice"]
				_, hasParallel := m["parallel_tool_calls"]
				assert.False(t, hasChoice)
				assert.False(t, hasParallel)
			},
		},
		{
			name:     "observe never rejects",
			mode:     policy.ModeObserve,
			settings: map[string]any{"allow_tools": []string{"search_*"}},
			req:      reqFor("openai", openaiBody("delete_db")),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				assert.Equal(t, 200, res.StatusCode)
				assert.False(t, res.StopUpstream)
				assert.Nil(t, res.RequestBody)
			},
		},
		{
			name:     "observe never strips",
			mode:     policy.ModeObserve,
			settings: map[string]any{"deny_tools": []string{"delete_*"}},
			req:      reqFor("openai", openaiBody("search_web", "delete_db")),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				assert.Equal(t, 200, res.StatusCode)
				assert.Nil(t, res.RequestBody)
			},
		},
		{
			name:     "anthropic allow keeps matches",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"get_weather"}},
			req:      reqFor("anthropic", anthropicBody("get_weather", "delete_db")),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				require.NotNil(t, res.RequestBody)
				assert.Equal(t, []string{"get_weather"}, anthropicNames(t, res.RequestBody))
			},
		},
		{
			name:     "anthropic deny removes matches",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"deny_tools": []string{"delete_*"}},
			req:      reqFor("anthropic", anthropicBody("search_web", "delete_db")),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				require.NotNil(t, res.RequestBody)
				assert.Equal(t, []string{"search_web"}, anthropicNames(t, res.RequestBody))
			},
		},
		{
			name:     "anthropic reject empty",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"search_*"}},
			req:      reqFor("anthropic", anthropicBody("delete_db")),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				assert.True(t, res.StopUpstream)
				assert.Equal(t, 403, res.StatusCode)
				assert.JSONEq(t, `{"error":{"type":"no_tools_allowed","requested":["delete_db"],"allowed_after_filter":[]}}`, string(res.Body))
			},
		},
		{
			name:     "no-op empty body",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"search_*"}},
			req:      reqFor("openai", ""),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				assert.Equal(t, 200, res.StatusCode)
				assert.Nil(t, res.RequestBody)
				assert.False(t, res.StopUpstream)
			},
		},
		{
			name:     "no-op no tools present",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"search_*"}},
			req:      reqFor("openai", `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				assert.Equal(t, 200, res.StatusCode)
				assert.Nil(t, res.RequestBody)
				assert.False(t, res.StopUpstream)
			},
		},
		{
			name:     "no-op unresolved format",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"search_*"}},
			req:      reqFor("", openaiBody("delete_db")),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				assert.Equal(t, 200, res.StatusCode)
				assert.Nil(t, res.RequestBody)
				assert.False(t, res.StopUpstream)
			},
		},
		{
			name:     "no-op undecodable body",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"search_*"}},
			req:      reqFor("openai", `{"messages":123}`),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				assert.Equal(t, 200, res.StatusCode)
				assert.Nil(t, res.RequestBody)
				assert.False(t, res.StopUpstream)
			},
		},
		{
			name:     "nil request is no-op",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"search_*"}},
			req:      nil,
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				require.NotNil(t, res)
				assert.Equal(t, 200, res.StatusCode)
				assert.Nil(t, res.RequestBody)
			},
		},
		{
			name:     "bad config returns error",
			mode:     policy.ModeEnforce,
			settings: map[string]any{},
			req:      reqFor("openai", openaiBody("search_web")),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.Error(t, err)
				assert.Nil(t, res)
			},
		},
	}

	p := New(adapter.NewRegistry())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res, err := run(p, tt.mode, tt.settings, tt.req)
			tt.check(t, res, err)
		})
	}
}

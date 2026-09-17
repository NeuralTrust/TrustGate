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
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
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

func geminiBody(names ...string) string {
	decls := make([]string, 0, len(names))
	for _, n := range names {
		decls = append(decls, fmt.Sprintf(`{"name":%q,"parameters":{"type":"object"}}`, n))
	}
	return fmt.Sprintf(`{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[%s]}],"toolConfig":{"functionCallingConfig":{"mode":"ANY"}}}`, strings.Join(decls, ","))
}

func geminiNames(t *testing.T, raw []byte) []string {
	t.Helper()
	var body struct {
		Tools []struct {
			FunctionDeclarations []struct {
				Name string `json:"name"`
			} `json:"functionDeclarations"`
		} `json:"tools"`
	}
	require.NoError(t, json.Unmarshal(raw, &body))
	names := make([]string, 0)
	for _, group := range body.Tools {
		for _, d := range group.FunctionDeclarations {
			names = append(names, d.Name)
		}
	}
	return names
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
	assert.ElementsMatch(t, []appplugins.Protocol{appplugins.ProtocolLLM, appplugins.ProtocolMCP}, p.SupportedProtocols())
	var _ appplugins.Plugin = p
}

func mcpReq(native, exposed string) *infracontext.RequestContext {
	req := &infracontext.RequestContext{
		MCP:        true,
		RegistryID: "reg-1",
		MCPTool:    native,
		Body:       []byte(fmt.Sprintf(`{"name":%q,"arguments":{"q":"x"}}`, exposed)),
		Metadata: map[string]interface{}{
			infracontext.MetadataMCPRegistryID:  "reg-1",
			infracontext.MetadataMCPExposedTool: exposed,
		},
	}
	if native != "" {
		req.Metadata[infracontext.MetadataMCPTool] = native
	}
	return req
}

func spanEvent() (*metrics.EventContext, *trace.Span) {
	span := trace.New("", trace.Metadata{}).StartSpan(trace.SpanPlugin, PluginName)
	return metrics.NewEventContext(span), span
}

func runMCP(p *Plugin, stage policy.Stage, mode policy.Mode, settings map[string]any, req *infracontext.RequestContext) (*appplugins.Result, *trace.Span, error) {
	event, span := spanEvent()
	res, err := p.Execute(context.Background(), appplugins.ExecInput{
		Stage:   stage,
		Mode:    mode,
		Config:  policy.PluginConfig{ID: "ta-1", Slug: PluginName, Name: PluginName, Settings: settings},
		Request: req,
		Event:   event,
	})
	return res, span, err
}

func extrasOf(t *testing.T, span *trace.Span) ToolAllowlistData {
	t.Helper()
	data, ok := span.PluginAttrsCopy().Extras.(ToolAllowlistData)
	require.True(t, ok, "extras = %#v, want ToolAllowlistData", span.PluginAttrsCopy().Extras)
	return data
}

func requireDenied(t *testing.T, res *appplugins.Result, err error, tool string) {
	t.Helper()
	require.NoError(t, err)
	assert.True(t, res.StopUpstream)
	assert.Equal(t, 403, res.StatusCode)
	assert.Nil(t, res.RequestBody)
	assert.JSONEq(t,
		fmt.Sprintf(`{"error":{"type":"tool_denied","requested":[%q],"allowed_after_filter":[]}}`, tool),
		string(res.Body))
}

func requireAllowed(t *testing.T, res *appplugins.Result, err error) {
	t.Helper()
	require.NoError(t, err)
	assert.False(t, res.StopUpstream)
	assert.Equal(t, 200, res.StatusCode)
	assert.Nil(t, res.RequestBody)
	assert.Nil(t, res.Body)
}

func TestPlugin_ExecuteMCP(t *testing.T) {
	const federated = "mcp_ab12cd34_run_query_9f8e7d6c"
	tests := []struct {
		name     string
		stage    policy.Stage
		mode     policy.Mode
		settings map[string]any
		req      *infracontext.RequestContext
		check    func(t *testing.T, res *appplugins.Result, span *trace.Span, err error)
	}{
		{
			name:     "deny everything refuses the call",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"deny_tools": []string{"*"}},
			req:      mcpReq("run_query", "run_query"),
			check: func(t *testing.T, res *appplugins.Result, span *trace.Span, err error) {
				requireDenied(t, res, err, "run_query")
				data := extrasOf(t, span)
				assert.Equal(t, actionRejected, data.Action)
				assert.Equal(t, []string{"run_query"}, data.ToolsRequested)
				assert.Equal(t, []string{"run_query"}, data.ToolsRemoved)
				assert.Equal(t, []string{}, data.ToolsAllowed)
				assert.Empty(t, data.OnEmpty)
				assert.Equal(t, "block", data.Decision)
			},
		},
		{
			name:     "allow by prefix permits a match",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"run_*"}},
			req:      mcpReq("run_query", "run_query"),
			check: func(t *testing.T, res *appplugins.Result, span *trace.Span, err error) {
				requireAllowed(t, res, err)
				data := extrasOf(t, span)
				assert.Equal(t, actionAllowed, data.Action)
				assert.Equal(t, []string{"run_query"}, data.ToolsAllowed)
				assert.Equal(t, []string{}, data.ToolsRemoved)
				assert.Empty(t, span.PluginAttrsCopy().Decision)
			},
		},
		{
			name:     "allow by prefix refuses a non-match",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"run_*"}},
			req:      mcpReq("delete_table", "delete_table"),
			check: func(t *testing.T, res *appplugins.Result, span *trace.Span, err error) {
				requireDenied(t, res, err, "delete_table")
			},
		},
		{
			name:     "deny wins over allow",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"run_query"}, "deny_tools": []string{"run_query"}},
			req:      mcpReq("run_query", "run_query"),
			check: func(t *testing.T, res *appplugins.Result, span *trace.Span, err error) {
				requireDenied(t, res, err, "run_query")
			},
		},
		{
			name:     "character-class and single-char globs",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"deny_tools": []string{"admin_?", "db_[rw]*"}},
			req:      mcpReq("db_read", "db_read"),
			check: func(t *testing.T, res *appplugins.Result, span *trace.Span, err error) {
				requireDenied(t, res, err, "db_read")
			},
		},
		{
			name:     "slash in the tool name matches literally",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"deny_tools": []string{"fs/*"}},
			req:      mcpReq("fs/delete", "fs/delete"),
			check: func(t *testing.T, res *appplugins.Result, span *trace.Span, err error) {
				requireDenied(t, res, err, "fs/delete")
			},
		},
		{
			name:     "federated consumer is judged on the native name",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"deny_tools": []string{"run_query"}},
			req:      mcpReq("run_query", federated),
			check: func(t *testing.T, res *appplugins.Result, span *trace.Span, err error) {
				requireDenied(t, res, err, "run_query")
			},
		},
		{
			name:     "the exposed name in the body is never matched",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"deny_tools": []string{federated}},
			req:      mcpReq("run_query", federated),
			check: func(t *testing.T, res *appplugins.Result, span *trace.Span, err error) {
				requireAllowed(t, res, err)
			},
		},
		{
			name:     "missing native tool metadata is a no-op",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"deny_tools": []string{"*"}},
			req:      mcpReq("", "run_query"),
			check: func(t *testing.T, res *appplugins.Result, span *trace.Span, err error) {
				requireAllowed(t, res, err)
				assert.Nil(t, span.PluginAttrsCopy().Extras)
				assert.Empty(t, span.PluginAttrsCopy().Decision)
			},
		},
		{
			// Metadata is merged back out of the isolated requests of a parallel
			// batch and shared across a sequential one, so a plugin ordered ahead
			// of this one can rewrite MetadataMCPTool. The decision must follow
			// the binding the dispatcher fixed, or that plugin could wave through
			// a tool the allowlist denies.
			name:     "a rewritten mcp.tool metadata key never changes the decision",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"deny_tools": []string{"delete_table"}},
			req: func() *infracontext.RequestContext {
				req := mcpReq("delete_table", "delete_table")
				req.Metadata[infracontext.MetadataMCPTool] = "run_query"
				return req
			}(),
			check: func(t *testing.T, res *appplugins.Result, span *trace.Span, err error) {
				requireDenied(t, res, err, "delete_table")
			},
		},
		{
			name:     "metadata alone cannot gate a call the dispatcher never bound",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"deny_tools": []string{"*"}},
			req: func() *infracontext.RequestContext {
				req := mcpReq("", "run_query")
				req.Metadata[infracontext.MetadataMCPTool] = "run_query"
				return req
			}(),
			check: func(t *testing.T, res *appplugins.Result, span *trace.Span, err error) {
				requireAllowed(t, res, err)
				assert.Nil(t, span.PluginAttrsCopy().Extras)
			},
		},
		{
			name:     "no metadata map at all is a no-op",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"deny_tools": []string{"*"}},
			req:      &infracontext.RequestContext{MCP: true, Body: []byte(`{"name":"run_query"}`)},
			check: func(t *testing.T, res *appplugins.Result, span *trace.Span, err error) {
				requireAllowed(t, res, err)
				assert.Nil(t, span.PluginAttrsCopy().Extras)
			},
		},
		{
			name:     "observe records the denial without blocking",
			mode:     policy.ModeObserve,
			settings: map[string]any{"deny_tools": []string{"*"}},
			req:      mcpReq("run_query", "run_query"),
			check: func(t *testing.T, res *appplugins.Result, span *trace.Span, err error) {
				requireAllowed(t, res, err)
				data := extrasOf(t, span)
				assert.Equal(t, actionRejected, data.Action)
				assert.Equal(t, []string{"run_query"}, data.ToolsRemoved)
				assert.Equal(t, "observe", data.Decision)
				assert.Equal(t, "observe", span.PluginAttrsCopy().Decision)
			},
		},
		{
			name:     "on_empty_after_filter has no effect on MCP",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"deny_tools": []string{"*"}, "on_empty_after_filter": "pass_through_empty"},
			req:      mcpReq("run_query", "run_query"),
			check: func(t *testing.T, res *appplugins.Result, span *trace.Span, err error) {
				requireDenied(t, res, err, "run_query")
				assert.Empty(t, extrasOf(t, span).OnEmpty)
			},
		},
		{
			name:     "stages other than PreRequest pass through",
			stage:    policy.StagePreResponse,
			mode:     policy.ModeEnforce,
			settings: map[string]any{"deny_tools": []string{"*"}},
			req:      mcpReq("run_query", "run_query"),
			check: func(t *testing.T, res *appplugins.Result, span *trace.Span, err error) {
				requireAllowed(t, res, err)
				assert.Nil(t, span.PluginAttrsCopy().Extras)
			},
		},
		{
			name:     "bad config returns error",
			mode:     policy.ModeEnforce,
			settings: map[string]any{},
			req:      mcpReq("run_query", "run_query"),
			check: func(t *testing.T, res *appplugins.Result, span *trace.Span, err error) {
				require.Error(t, err)
				assert.Nil(t, res)
			},
		},
	}

	p := New(adapter.NewRegistry())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			stage := tt.stage
			if stage == "" {
				stage = policy.StagePreRequest
			}
			res, span, err := runMCP(p, stage, tt.mode, tt.settings, tt.req)
			tt.check(t, res, span, err)
		})
	}
}

func TestPlugin_ExecuteMCP_WithoutAdapterRegistry(t *testing.T) {
	res, _, err := runMCP(New(nil), policy.StagePreRequest, policy.ModeEnforce,
		map[string]any{"deny_tools": []string{"*"}}, mcpReq("run_query", "run_query"))
	requireDenied(t, res, err, "run_query")
}

func TestPlugin_ExecuteMCP_WithoutEvent(t *testing.T) {
	p := New(adapter.NewRegistry())
	res, err := p.Execute(context.Background(), appplugins.ExecInput{
		Stage:   policy.StagePreRequest,
		Mode:    policy.ModeEnforce,
		Config:  policy.PluginConfig{ID: "ta-1", Slug: PluginName, Name: PluginName, Settings: map[string]any{"deny_tools": []string{"*"}}},
		Request: mcpReq("run_query", "run_query"),
	})
	requireDenied(t, res, err, "run_query")
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
			name:     "capitalised Tools key rejects in enforce",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"search_*"}},
			req:      reqFor("openai", `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"Tools":[{"type":"function","function":{"name":"evil"}}]}`),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				assert.True(t, res.StopUpstream)
				assert.Equal(t, 400, res.StatusCode)
				assert.JSONEq(t, `{"error":{"type":"invalid_tools_field","requested":[],"allowed_after_filter":[]}}`, string(res.Body))
				assert.Nil(t, res.RequestBody)
			},
		},
		{
			name:     "duplicate tools keys with mixed case reject even when all allowed",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"search_*"}},
			req:      reqFor("openai", `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"evil"}}],"Tools":[{"type":"function","function":{"name":"search_web"}}]}`),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				assert.True(t, res.StopUpstream)
				assert.Equal(t, 400, res.StatusCode)
			},
		},
		{
			name:     "capitalised Tools key passes through in observe",
			mode:     policy.ModeObserve,
			settings: map[string]any{"allow_tools": []string{"search_*"}},
			req:      reqFor("openai", `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"Tools":[{"type":"function","function":{"name":"evil"}}]}`),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				assert.False(t, res.StopUpstream)
				assert.Equal(t, 200, res.StatusCode)
				assert.Nil(t, res.RequestBody)
			},
		},
		{
			name:     "null body is a no-op",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"search_*"}},
			req:      reqFor("openai", `null`),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				assert.Equal(t, 200, res.StatusCode)
				assert.Nil(t, res.RequestBody)
				assert.False(t, res.StopUpstream)
			},
		},
		{
			name:     "undecodable body with tools key rejects in enforce",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"search_*"}},
			req:      reqFor("openai", `{"messages":123,"tools":[{"type":"function","function":{"name":"delete_db"}}]}`),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				assert.True(t, res.StopUpstream)
				assert.Equal(t, 400, res.StatusCode)
				assert.JSONEq(t, `{"error":{"type":"invalid_tools_field","requested":[],"allowed_after_filter":[]}}`, string(res.Body))
			},
		},
		{
			name:     "undecodable body with toolConfig key rejects in enforce",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"search_*"}},
			req:      reqFor("openai", `{"messages":123,"toolConfig":{"functionCallingConfig":{"mode":"ANY"}}}`),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				assert.True(t, res.StopUpstream)
				assert.Equal(t, 400, res.StatusCode)
			},
		},
		{
			name:     "truncated body with tools key rejects in enforce",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"search_*"}},
			req:      reqFor("openai", `{"tools":[{"type":"function","function":{"name":"delete_db"}}],"messages":[`),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				assert.True(t, res.StopUpstream)
				assert.Equal(t, 400, res.StatusCode)
			},
		},
		{
			name:     "undecodable body with tools key passes through in observe",
			mode:     policy.ModeObserve,
			settings: map[string]any{"allow_tools": []string{"search_*"}},
			req:      reqFor("openai", `{"messages":123,"tools":[{"type":"function","function":{"name":"delete_db"}}]}`),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				assert.False(t, res.StopUpstream)
				assert.Equal(t, 200, res.StatusCode)
				assert.Nil(t, res.RequestBody)
			},
		},
		{
			name:     "empty tools array is a no-op",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"search_*"}},
			req:      reqFor("openai", `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":[]}`),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				assert.Equal(t, 200, res.StatusCode)
				assert.Nil(t, res.RequestBody)
				assert.False(t, res.StopUpstream)
			},
		},
		{
			name:     "NUL byte in tool name never matches slash pattern",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"github/*"}},
			req:      reqFor("openai", `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"github/rm"}},{"type":"function","function":{"name":"github\u0000rm_rf"}}]}`),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				require.NotNil(t, res.RequestBody)
				assert.Equal(t, []string{"github/rm"}, openaiNames(t, res.RequestBody))
			},
		},
		{
			name:     "control characters in tool name are removed under deny-only",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"deny_tools": []string{"delete_*"}},
			req:      reqFor("openai", `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"search_web"}},{"type":"function","function":{"name":"sea\u0007rch"}}]}`),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				require.NotNil(t, res.RequestBody)
				assert.Equal(t, []string{"search_web"}, openaiNames(t, res.RequestBody))
			},
		},
		{
			name:     "exact duplicate tools keys reject in enforce",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"search_*"}},
			req:      reqFor("openai", `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"search_web"}}],"tools":[{"type":"function","function":{"name":"evil"}}]}`),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				assert.True(t, res.StopUpstream)
				assert.Equal(t, 400, res.StatusCode)
			},
		},
		{
			name:     "unresolvable adapter with tools key rejects in enforce",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"search_*"}},
			req:      reqFor("openai_files", openaiBody("delete_db")),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				assert.True(t, res.StopUpstream)
				assert.Equal(t, 400, res.StatusCode)
			},
		},
		{
			name:     "gemini partial strip preserves toolConfig",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"deny_tools": []string{"delete_*"}},
			req:      reqFor("google", geminiBody("search_web", "delete_db")),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				require.NotNil(t, res.RequestBody)
				assert.Equal(t, []string{"search_web"}, geminiNames(t, res.RequestBody))
				m := bodyMap(t, res.RequestBody)
				assert.JSONEq(t, `{"functionCallingConfig":{"mode":"ANY"}}`, string(m["toolConfig"]))
			},
		},
		{
			name:     "gemini strip_tools_field drops toolConfig",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"search_*"}, "on_empty_after_filter": "strip_tools_field"},
			req:      reqFor("google", geminiBody("delete_db")),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				require.NotNil(t, res.RequestBody)
				m := bodyMap(t, res.RequestBody)
				_, hasTools := m["tools"]
				_, hasToolConfig := m["toolConfig"]
				assert.False(t, hasTools)
				assert.False(t, hasToolConfig)
				assert.Contains(t, m, "contents")
			},
		},
		{
			name:     "non-ascii printable tool name is kept",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allow_tools": []string{"b*"}},
			req:      reqFor("openai", openaiBody("búsqueda_web", "delete_db")),
			check: func(t *testing.T, res *appplugins.Result, err error) {
				require.NoError(t, err)
				require.NotNil(t, res.RequestBody)
				assert.Equal(t, []string{"búsqueda_web"}, openaiNames(t, res.RequestBody))
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

func TestGraftChangedFields(t *testing.T) {
	full := []byte(`{"model":"gpt-4o","tools":[{"name":"a"},{"name":"b"}],"tool_choice":"auto"}`)
	stripped := []byte(`{"model":"gpt-4o","tools":[{"name":"a"}],"tool_choice":"auto"}`)
	tests := []struct {
		name     string
		original string
		check    func(t *testing.T, out []byte, err error)
	}{
		{
			name:     "null original returns error instead of panicking",
			original: `null`,
			check: func(t *testing.T, out []byte, err error) {
				require.ErrorIs(t, err, errNullBody)
				assert.Nil(t, out)
			},
		},
		{
			name:     "case variant of grafted key is dropped",
			original: `{"model":"gpt-4o","Tools":[{"name":"a"},{"name":"b"}],"tool_choice":"auto","extra":1}`,
			check: func(t *testing.T, out []byte, err error) {
				require.NoError(t, err)
				m := bodyMap(t, out)
				_, hasVariant := m["Tools"]
				assert.False(t, hasVariant)
				assert.JSONEq(t, `[{"name":"a"}]`, string(m["tools"]))
				assert.JSONEq(t, `1`, string(m["extra"]))
			},
		},
		{
			name:     "case variant of untouched key is preserved",
			original: `{"model":"gpt-4o","tools":[{"name":"a"},{"name":"b"}],"Tool_Choice":"auto"}`,
			check: func(t *testing.T, out []byte, err error) {
				require.NoError(t, err)
				m := bodyMap(t, out)
				assert.JSONEq(t, `"auto"`, string(m["Tool_Choice"]))
				assert.JSONEq(t, `[{"name":"a"}]`, string(m["tools"]))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, err := graftChangedFields([]byte(tt.original), full, stripped)
			tt.check(t, out, err)
		})
	}
}

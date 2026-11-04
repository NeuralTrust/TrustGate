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

package metrics

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
)

func buildLLMPreview(t *testing.T, body string) string {
	t.Helper()
	rt := trace.New("trace-preview", trace.Metadata{GatewayID: "gw-1"})
	req := &infracontext.RequestContext{
		GatewayID: "gw-1",
		Method:    http.MethodPost,
		Path:      "/v1/chat/completions",
		Headers:   map[string][]string{"Content-Type": {"application/json"}},
		Body:      []byte(body),
	}
	resp := &infracontext.ResponseContext{StatusCode: http.StatusOK}
	start := time.UnixMilli(1_000_000)
	evt := newBuilder(appcatalog.Pricing{}).Build(context.Background(), rt, req, resp, start, start.Add(time.Second))
	return evt.Request.Preview
}

func TestBuilder_LLMPreviewIsTheLastUserTurn(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("palabra ", 60)
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "openai single turn",
			body: `{"model":"gpt-4o","messages":[{"role":"system","content":"be terse"},{"role":"user","content":"hello there"}]}`,
			want: "hello there",
		},
		{
			name: "openai multi turn keeps the turn this request adds",
			body: `{"model":"gpt-4o","messages":[{"role":"user","content":"first"},{"role":"assistant","content":"ok"},{"role":"user","content":"second"}]}`,
			want: "second",
		},
		{
			name: "anthropic content blocks",
			body: `{"model":"claude-sonnet-5-5","max_tokens":10,"system":"x","messages":[{"role":"user","content":[{"type":"text","text":"summarise this"}]}]}`,
			want: "summarise this",
		},
		{
			name: "anthropic agent loop skips the tool result turn",
			body: `{"model":"claude-sonnet-5-5","max_tokens":10,"messages":[` +
				`{"role":"user","content":[{"type":"text","text":"fix the failing test"}]},` +
				`{"role":"assistant","content":[{"type":"tool_use","id":"tu_1","name":"bash","input":{"command":"go test ./..."}}]},` +
				`{"role":"user","content":[{"type":"tool_result","tool_use_id":"tu_1","content":"FAIL pkg/app 0.1s"}]}]}`,
			want: "fix the failing test",
		},
		{
			name: "openai tool message is not the prompt",
			body: `{"model":"gpt-4o","messages":[{"role":"user","content":"what is the weather"},` +
				`{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"weather","arguments":"{}"}}]},` +
				`{"role":"tool","tool_call_id":"c1","content":"sunny, 21C"}]}`,
			want: "what is the weather",
		},
		{
			name: "responses api string input",
			body: `{"model":"gpt-4.1","input":"draft a reply to the customer"}`,
			want: "draft a reply to the customer",
		},
		{
			name: "whitespace collapses",
			body: `{"model":"gpt-4o","messages":[{"role":"user","content":"  line one\n\n\tline two  "}]}`,
			want: "line one line two",
		},
		{
			name: "long prompt is cut and marked",
			body: `{"model":"gpt-4o","messages":[{"role":"user","content":"` + long + `"}]}`,
			want: strings.TrimSpace(string([]rune(strings.TrimSpace(long))[:maxPreviewRunes])) + previewEllipsis,
		},
		{
			name: "no user turn",
			body: `{"model":"gpt-4o","messages":[{"role":"system","content":"only system"}]}`,
			want: "",
		},
		{
			name: "not json",
			body: `not a body`,
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, buildLLMPreview(t, tc.body))
		})
	}
}

func TestBuilder_MCPPreviewIsToolAndFirstStringArgument(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		method string
		tool   string
		body   string
		want   string
	}{
		{
			name:   "first string argument in client order",
			method: "tools/call",
			tool:   "search_issues",
			body:   `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_issues","arguments":{"query":"login bug","limit":5}}}`,
			want:   "search_issues(login bug)",
		},
		{
			name:   "non string arguments are skipped",
			method: "tools/call",
			tool:   "get_issue",
			body:   `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_issue","arguments":{"limit":5,"filter":{"a":"b"},"id":"ENG-1"}}}`,
			want:   "get_issue(ENG-1)",
		},
		{
			name:   "credential arguments are skipped",
			method: "tools/call",
			tool:   "fetch",
			body:   `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch","arguments":{"api_key":"sk-123","url":"https://example.com"}}}`,
			want:   "fetch(https://example.com)",
		},
		{
			name:   "no arguments names the tool alone",
			method: "tools/call",
			tool:   "list_projects",
			body:   `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_projects"}}`,
			want:   "list_projects",
		},
		{
			name:   "a long argument keeps the closing parenthesis",
			method: "tools/call",
			tool:   "search",
			body:   `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{"query":"` + strings.Repeat("a", 300) + `"}}}`,
			want:   "search(" + strings.Repeat("a", maxPreviewRunes-len("search()")) + previewEllipsis + ")",
		},
		{
			name:   "other methods have no preview",
			method: "tools/list",
			body:   `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
			want:   "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rt := trace.New("trace-mcp-preview", trace.Metadata{GatewayID: "gw-1", Kind: events.KindMCP})
			_ = rt.AddSpan(mcpSpan(tc.method, &trace.MCPAttrs{
				Method:         tc.method,
				Tool:           tc.tool,
				UpstreamStatus: http.StatusOK,
			}, 10*time.Millisecond))
			req := &infracontext.RequestContext{
				GatewayID: "gw-1",
				Method:    http.MethodPost,
				Path:      "/mcp",
				Headers:   map[string][]string{"Content-Type": {"application/json"}},
				Body:      []byte(tc.body),
			}
			resp := &infracontext.ResponseContext{StatusCode: http.StatusOK}
			start := time.UnixMilli(2_000_000)

			evt := newBuilder(appcatalog.Pricing{}).Build(context.Background(), rt, req, resp, start, start.Add(time.Second))

			assert.Equal(t, tc.want, evt.Request.Preview)
		})
	}
}

func TestTruncatePreview_CutsOnRunes(t *testing.T) {
	t.Parallel()
	got := truncatePreview(strings.Repeat("ñ", maxPreviewRunes+10))

	assert.True(t, utf8.ValidString(got))
	assert.Equal(t, maxPreviewRunes+utf8.RuneCountInString(previewEllipsis), utf8.RuneCountInString(got))
}

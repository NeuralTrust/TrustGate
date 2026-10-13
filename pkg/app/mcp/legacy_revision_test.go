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

package mcp

import (
	"context"
	"encoding/json"
	"testing"

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
)

func decodeTool(t *testing.T, raw string) Tool {
	t.Helper()
	var tool Tool
	if err := json.Unmarshal([]byte(raw), &tool); err != nil {
		t.Fatalf("decode tool: %v", err)
	}
	return tool
}

func encodedFields(t *testing.T, v any) map[string]json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("decode fields: %v", err)
	}
	return fields
}

func TestWithObjectOutputSchema(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		schema   string
		wantKept bool
	}{
		{name: "object root", schema: `{"type":"object","properties":{"id":{"type":"string"}}}`, wantKept: true},
		{name: "nullable object", schema: `{"type":["null","object"],"properties":{"id":{"type":"string"}}}`},
		{name: "nullable array", schema: `{"type":["null","array"],"items":{"type":"string"}}`},
		{name: "array root", schema: `{"type":"array","items":{"type":"string"}}`},
		{name: "missing type", schema: `{"anyOf":[{"type":"object"},{"type":"null"}]}`},
		{name: "null schema", schema: `null`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			original := decodeTool(t, `{"name":"list_branches","description":"d","inputSchema":{"type":"object"},"outputSchema":`+tt.schema+`}`)

			got, dropped := withObjectOutputSchema(original)

			if dropped == tt.wantKept {
				t.Fatalf("dropped = %v, want %v", dropped, !tt.wantKept)
			}
			fields := encodedFields(t, got)
			if _, kept := fields["outputSchema"]; kept != tt.wantKept {
				t.Fatalf("outputSchema kept = %v, want %v (tool %s)", kept, tt.wantKept, fields)
			}
			for _, key := range []string{"name", "description", "inputSchema"} {
				if _, ok := fields[key]; !ok {
					t.Fatalf("%s lost from tool %s", key, fields)
				}
			}
			if _, ok := encodedFields(t, original)["outputSchema"]; !ok {
				t.Fatal("the original tool was modified")
			}
		})
	}
}

func TestWithObjectOutputSchema_NoSchemaIsUntouched(t *testing.T) {
	t.Parallel()
	original := decodeTool(t, `{"name":"ping","inputSchema":{"type":"object"}}`)

	if _, dropped := withObjectOutputSchema(original); dropped {
		t.Fatal("a tool without outputSchema was reported as downgraded")
	}
}

func TestWithObjectStructuredContent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		result string
		want   string
	}{
		{
			name:   "object kept verbatim",
			result: `{"content":[{"type":"text","text":"{\"id\":1}"}],"structuredContent":{"id":1}}`,
			want:   `{"content":[{"type":"text","text":"{\"id\":1}"}],"structuredContent":{"id":1}}`,
		},
		{
			name:   "no structured content kept verbatim",
			result: `{"content":[]}`,
			want:   `{"content":[]}`,
		},
		{
			name:   "array dropped, content kept",
			result: `{"content":[{"type":"text","text":"[\"main\"]"}],"structuredContent":["main"]}`,
			want:   `{"content":[{"type":"text","text":"[\"main\"]"}]}`,
		},
		{
			name:   "array moved into text when content is empty",
			result: `{"content":[],"structuredContent":["main","dev"]}`,
			want:   `{"content":[{"text":"[\"main\",\"dev\"]","type":"text"}]}`,
		},
		{
			name:   "array moved into text when content is missing",
			result: `{"structuredContent":["main"],"isError":false}`,
			want:   `{"content":[{"text":"[\"main\"]","type":"text"}],"isError":false}`,
		},
		{
			name:   "null dropped, empty content stays empty",
			result: `{"content":null,"structuredContent":null}`,
			want:   `{"content":[]}`,
		},
		{
			name:   "string moved into text",
			result: `{"structuredContent":"done"}`,
			want:   `{"content":[{"text":"\"done\"","type":"text"}]}`,
		},
		{
			name:   "not an object relayed as is",
			result: `[1,2]`,
			want:   `[1,2]`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := withObjectStructuredContent(json.RawMessage(tt.result))
			if string(got) != tt.want {
				t.Fatalf("result = %s, want %s", got, tt.want)
			}
		})
	}
}

var clientRevisions = []struct {
	name        string
	revision    string
	typedOutput bool
}{
	{name: "no header", revision: ""},
	{name: "2025-06-18", revision: "2025-06-18"},
	{name: "2025-11-25", revision: "2025-11-25"},
	{name: "2026-07-28", revision: "2026-07-28", typedOutput: true},
}

func TestComposer_ListTools_OutputSchemaFollowsClientRevision(t *testing.T) {
	t.Parallel()
	for _, rev := range clientRevisions {
		t.Run(rev.name, func(t *testing.T) {
			t.Parallel()
			reg := mcpRegistry(t, "github", "https://a.example.com/mcp")
			dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
				"https://a.example.com/mcp": {tools: []Tool{
					decodeTool(t, `{"name":"list_branches","inputSchema":{"type":"object"},"outputSchema":{"type":["null","array"]}}`),
					decodeTool(t, `{"name":"get_me","inputSchema":{"type":"object"},"outputSchema":{"type":"object"}}`),
				}},
			}}
			c := newTestComposer(dialer)
			ctx := WithClientRevision(context.Background(), rev.revision)

			got, err := c.ListTools(ctx, routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, reg))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != 2 {
				t.Fatalf("tools = %v, want both tools listed", toolNames(got))
			}
			if _, ok := encodedFields(t, got[0])["outputSchema"]; ok != rev.typedOutput {
				t.Fatalf("list_branches outputSchema present = %v, want %v", ok, rev.typedOutput)
			}
			if _, ok := encodedFields(t, got[1])["outputSchema"]; !ok {
				t.Fatalf("get_me lost its object outputSchema")
			}
		})
	}
}

func TestComposer_Invoke_StructuredContentFollowsClientRevision(t *testing.T) {
	t.Parallel()
	const upstreamResult = `{"content":[{"type":"text","text":"[\"main\"]"}],"structuredContent":["main"]}`
	for _, rev := range clientRevisions {
		t.Run(rev.name, func(t *testing.T) {
			t.Parallel()
			reg := mcpRegistry(t, "github", "https://a.example.com/mcp")
			up := &fakeUpstream{tools: tools("list_branches"), result: json.RawMessage(upstreamResult)}
			c := newTestComposer(&fakeDialer{upstreams: map[string]*fakeUpstream{"https://a.example.com/mcp": up}})
			ctx := WithClientRevision(context.Background(), rev.revision)
			rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, reg)

			res, err := resolveAndInvoke(ctx, c, rc, namedFor(reg, "list_branches"), nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			want := `{"content":[{"type":"text","text":"[\"main\"]"}]}`
			if rev.typedOutput {
				want = upstreamResult
			}
			if string(res) != want {
				t.Fatalf("result = %s, want %s", res, want)
			}
		})
	}
}

func TestClientAcceptsTypedOutput_NoRevisionIsOlder(t *testing.T) {
	t.Parallel()
	if ClientAcceptsTypedOutput(context.Background()) {
		t.Fatal("a request without a recorded revision was treated as 2026-07-28")
	}
}

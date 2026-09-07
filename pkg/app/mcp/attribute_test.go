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
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func TestAttributeTool_StampsRegistryOnTitleAndDescription(t *testing.T) {
	t.Parallel()
	src := mustDecodeTool(t, `{
		"name":"list_meetings",
		"title":"List Meetings",
		"description":"List upcoming meetings",
		"annotations":{"title":"List Meetings","readOnlyHint":true}
	}`)
	originalTitle := stringField(src.payload, "title")
	originalDesc := stringField(src.payload, "description")

	got := attributeTool(src, mcpRegistry(t, "Granola", "https://granola.example/mcp"))
	fields := mustToolFields(t, got)
	if fields["name"] != "list_meetings" {
		t.Fatalf("name = %q, want list_meetings (RPC name is not rewritten here)", fields["name"])
	}
	if fields["title"] != "Granola: List Meetings" {
		t.Fatalf("title = %q, want Granola: List Meetings", fields["title"])
	}
	if fields["description"] != "[Granola] List upcoming meetings" {
		t.Fatalf("description = %q", fields["description"])
	}
	ann, _ := fields["annotations"].(map[string]any)
	if ann["title"] != "Granola: List Meetings" {
		t.Fatalf("annotations.title = %#v", ann["title"])
	}
	if ann["readOnlyHint"] != true {
		t.Fatalf("readOnlyHint was dropped: %#v", ann["readOnlyHint"])
	}
	if stringField(src.payload, "title") != originalTitle || stringField(src.payload, "description") != originalDesc {
		t.Fatal("attributeTool must clone the payload so discovery cache is not rewritten")
	}
}

func TestAttributeTool_SetsTitleWhenUpstreamOmitsIt(t *testing.T) {
	t.Parallel()
	src := mustDecodeTool(t, `{
		"name":"get_draft",
		"description":"Retrieves a specific draft email from the authenticated user's Gmail account"
	}`)
	got := attributeTool(src, mcpRegistry(t, "Gmail", "https://gmail.example/mcp"))
	fields := mustToolFields(t, got)
	if fields["title"] != "Gmail: get_draft" {
		t.Fatalf("title = %q, want Gmail: get_draft so hosts that prefer title over description show the server", fields["title"])
	}
	if fields["description"] != "[Gmail] Retrieves a specific draft email from the authenticated user's Gmail account" {
		t.Fatalf("description = %q", fields["description"])
	}
}

func TestAttributeTool_UsesCatalogCodeLeafWhenNameLooksQualified(t *testing.T) {
	t.Parallel()
	reg, err := registrydomain.NewMCPRegistry(
		ids.New[ids.GatewayKind](),
		"com.google.workspace/gmail",
		"",
		&registrydomain.MCPTarget{URL: "https://gmail.example/mcp", Code: "com.google.workspace/gmail"},
	)
	if err != nil {
		t.Fatalf("build registry: %v", err)
	}
	got := attributeTool(Tool{Name: "search_threads"}, reg)
	fields := mustToolFields(t, got)
	if fields["title"] != "gmail: search_threads" {
		t.Fatalf("title = %q, want the catalog code leaf, not the reverse-DNS path", fields["title"])
	}
}

func TestAttributeTool_DoesNotDoublePrefix(t *testing.T) {
	t.Parallel()
	src := mustDecodeTool(t, `{"name":"search","title":"Granola: Search","description":"[Granola] Search notes"}`)
	got := attributeTool(src, mcpRegistry(t, "Granola", "https://granola.example/mcp"))
	fields := mustToolFields(t, got)
	if fields["title"] != "Granola: Search" {
		t.Fatalf("title = %q", fields["title"])
	}
	if fields["description"] != "[Granola] Search notes" {
		t.Fatalf("description = %q", fields["description"])
	}
}

func TestAttributePrompt_StampsRegistryOnTitle(t *testing.T) {
	t.Parallel()
	var p Prompt
	if err := json.Unmarshal([]byte(`{"name":"summarize","title":"Summarize","description":"Summarize a thread"}`), &p); err != nil {
		t.Fatalf("decode prompt: %v", err)
	}
	got := attributePrompt(p, mcpRegistry(t, "GitHub", "https://github.example/mcp"))
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("decode fields: %v", err)
	}
	if fields["title"] != "GitHub: Summarize" {
		t.Fatalf("title = %q", fields["title"])
	}
	if fields["description"] != "[GitHub] Summarize a thread" {
		t.Fatalf("description = %q", fields["description"])
	}
}

func TestComposer_ListTools_AttributesEachUpstream(t *testing.T) {
	t.Parallel()
	granola := mcpRegistry(t, "Granola", "https://granola.example/mcp")
	gmail := mcpRegistry(t, "Gmail", "https://gmail.example/mcp")
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://granola.example/mcp": {tools: []Tool{mustDecodeTool(t, `{"name":"list_meetings","title":"List Meetings"}`)}},
		"https://gmail.example/mcp":   {tools: []Tool{mustDecodeTool(t, `{"name":"get_draft","description":"Retrieves a draft"}`)}},
	}}
	c := newTestComposer(dialer)

	got, err := c.ListTools(context.Background(), routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, granola, gmail))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("tools = %v, want 2", toolNames(got))
	}
	if got[0].Name != "list_meetings" || mustToolFields(t, got[0])["title"] != "Granola: List Meetings" {
		t.Fatalf("granola tool = name %q title %#v", got[0].Name, mustToolFields(t, got[0])["title"])
	}
	gmailFields := mustToolFields(t, got[1])
	if got[1].Name != "get_draft" || gmailFields["title"] != "Gmail: get_draft" {
		t.Fatalf("gmail tool = name %q title %#v", got[1].Name, gmailFields["title"])
	}
}

func mustDecodeTool(t *testing.T, raw string) Tool {
	t.Helper()
	var tool Tool
	if err := json.Unmarshal([]byte(raw), &tool); err != nil {
		t.Fatalf("decode tool: %v", err)
	}
	return tool
}

func mustToolFields(t *testing.T, tool Tool) map[string]any {
	t.Helper()
	raw, err := json.Marshal(tool)
	if err != nil {
		t.Fatalf("marshal tool: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("decode fields: %v", err)
	}
	return fields
}

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
	"log/slog"
	"strings"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type fakeSurfaceInventory struct {
	inventory *ToolInventory
	err       error
	calls     int
}

func (f *fakeSurfaceInventory) ToolInventory(context.Context, *appconsumer.RoutableConsumer) (*ToolInventory, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.inventory, nil
}

// twoServerInventory: one server serving, one waiting for the user's account.
func twoServerInventory() *ToolInventory {
	return &ToolInventory{Servers: []InventoryServer{
		{
			Name:  "linear",
			Code:  "app.linear/mcp",
			State: InventoryStateReady,
			Tools: []InventoryEntry{
				{Name: "search_issues", Description: "Search Linear issues", Callable: true},
				{Name: "create_issue", Callable: true},
			},
		},
		{
			Name:     "Notion",
			Code:     "com.notion/mcp",
			State:    InventoryStateNeedsConnect,
			Provider: "com.notion/mcp",
			Cause:    ConsentCauseRegisteredClientLost,
		},
	}}
}

func notionCatalog() fakeCatalog {
	return fakeCatalog{servers: []catalogdomain.MCPServer{{
		Code:        "com.notion/mcp",
		DisplayName: "Notion",
		Tools: []catalogdomain.MCPTool{
			{Name: "query_database", Description: "Query a Notion database"},
			{Name: "create_page"},
		},
	}}}
}

func callInventory(t *testing.T, tool InventoryTool, arguments string) map[string]any {
	t.Helper()
	var raw json.RawMessage
	if arguments != "" {
		raw = json.RawMessage(arguments)
	}
	res, err := tool.Call(
		context.Background(),
		routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}),
		InventoryToolName,
		raw,
	)
	if err != nil {
		t.Fatalf("call %s: %v", InventoryToolName, err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(res, &decoded); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	return decoded
}

func structuredServers(t *testing.T, result map[string]any) []map[string]any {
	t.Helper()
	structured, ok := result["structuredContent"].(map[string]any)
	if !ok {
		t.Fatalf("result has no structuredContent: %v", result)
	}
	raw, ok := structured["servers"].([]any)
	if !ok {
		t.Fatalf("structuredContent has no servers: %v", structured)
	}
	out := make([]map[string]any, 0, len(raw))
	for _, entry := range raw {
		server, ok := entry.(map[string]any)
		if !ok {
			t.Fatalf("server entry is not an object: %v", entry)
		}
		out = append(out, server)
	}
	return out
}

func resultText(t *testing.T, result map[string]any) string {
	t.Helper()
	content, ok := result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("result has no content: %v", result)
	}
	block, ok := content[0].(map[string]any)
	if !ok {
		t.Fatalf("content block is not an object: %v", content[0])
	}
	text, _ := block["text"].(string)
	return text
}

func TestInventoryTool_ListsEveryServerAndItsState(t *testing.T) {
	t.Parallel()
	tool, err := NewInventoryTool(&fakeSurfaceInventory{inventory: twoServerInventory()}, nil)
	if err != nil {
		t.Fatalf("new inventory tool: %v", err)
	}

	servers := structuredServers(t, callInventory(t, tool, ""))
	if len(servers) != 2 {
		t.Fatalf("servers = %d, want both", len(servers))
	}
	if servers[0]["state"] != InventoryStateReady || servers[0]["name"] != "linear" {
		t.Fatalf("first server = %v, want the ready one", servers[0])
	}
	if servers[1]["state"] != InventoryStateNeedsConnect {
		t.Fatalf("second server = %v, want %q", servers[1], InventoryStateNeedsConnect)
	}
	// A pending server is only actionable if the caller is told what to call, so
	// the connection meta-tool for its account comes back with it.
	if got := servers[1]["connect_tool"]; got != ConnectToolName("com.notion/mcp") {
		t.Fatalf("connect_tool = %v, want %q", got, ConnectToolName("com.notion/mcp"))
	}
	// And why it is not serving: a client that is not told invents a reason,
	// and it invents "the session expired" whatever happened.
	if got := servers[1]["cause"]; got != ConsentCauseRegisteredClientLost {
		t.Fatalf("cause = %v, want the condition behind needs_connect", got)
	}
	if servers[0]["cause"] != nil {
		t.Fatalf("a ready server has no cause, got %v", servers[0]["cause"])
	}
}

// The text body carries it too: many clients hand only the text to the model.
func TestInventoryTool_TextBodyNamesWhyAServerIsNotConnected(t *testing.T) {
	t.Parallel()
	tool, err := NewInventoryTool(&fakeSurfaceInventory{inventory: twoServerInventory()}, nil)
	if err != nil {
		t.Fatalf("new inventory tool: %v", err)
	}
	text := resultText(t, callInventory(t, tool, ""))
	if !strings.Contains(text, ConsentCauseRegisteredClientLost) {
		t.Fatalf("text body must name the cause, got: %s", text)
	}
}

// The catalog knows what an unconnected server advertises, and that is the
// answer to "what am I missing?" — marked uncallable, since it is not reachable.
func TestInventoryTool_NamesThePendingServersToolsFromTheCatalog(t *testing.T) {
	t.Parallel()
	tool, err := NewInventoryTool(&fakeSurfaceInventory{inventory: twoServerInventory()}, notionCatalog())
	if err != nil {
		t.Fatalf("new inventory tool: %v", err)
	}

	result := callInventory(t, tool, "")
	servers := structuredServers(t, result)
	pending := servers[1]
	tools, ok := pending["tools"].([]any)
	if !ok || len(tools) != 2 {
		t.Fatalf("pending tools = %v, want the catalog's two", pending["tools"])
	}
	for _, entry := range tools {
		tool, _ := entry.(map[string]any)
		if tool["callable"] != false {
			t.Fatalf("tool %v must not be advertised as callable: its server is not connected", tool)
		}
	}
	structured, _ := result["structuredContent"].(map[string]any)
	if structured["callable_tools"] != float64(2) || structured["pending_tools"] != float64(2) {
		t.Fatalf("counts = %v, want 2 callable and 2 pending", structured)
	}
}

// Many MCP clients hand the model only the text block, so the text — not just
// structuredContent — has to carry every server, its state and its tools.
func TestInventoryTool_PutsEveryServerInTheTextBody(t *testing.T) {
	t.Parallel()
	tool, err := NewInventoryTool(&fakeSurfaceInventory{inventory: twoServerInventory()}, notionCatalog())
	if err != nil {
		t.Fatalf("new inventory tool: %v", err)
	}

	text := resultText(t, callInventory(t, tool, ""))
	for _, want := range []string{
		"linear", "search_issues", "create_issue",
		"Notion", "not connected", "query_database",
		ConnectToolName("com.notion/mcp"),
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("text does not mention %q:\n%s", want, text)
		}
	}
}

func TestInventoryTool_NarrowsToOneServer(t *testing.T) {
	t.Parallel()
	tool, err := NewInventoryTool(&fakeSurfaceInventory{inventory: twoServerInventory()}, notionCatalog())
	if err != nil {
		t.Fatalf("new inventory tool: %v", err)
	}

	servers := structuredServers(t, callInventory(t, tool, `{"server":"notion"}`))
	if len(servers) != 1 || servers[0]["name"] != "Notion" {
		t.Fatalf("servers = %v, want only Notion", servers)
	}
}

func TestInventoryTool_SaysSoWhenNothingMatches(t *testing.T) {
	t.Parallel()
	tool, err := NewInventoryTool(&fakeSurfaceInventory{inventory: twoServerInventory()}, nil)
	if err != nil {
		t.Fatalf("new inventory tool: %v", err)
	}

	result := callInventory(t, tool, `{"server":"salesforce"}`)
	if servers := structuredServers(t, result); len(servers) != 0 {
		t.Fatalf("servers = %v, want none", servers)
	}
	if text := resultText(t, result); !strings.Contains(text, "salesforce") {
		t.Fatalf("text = %q, want it to name what was searched for", text)
	}
}

// A consumer with no MCP server bound has nothing to inventory, and a tool that
// can only ever answer "nothing" is noise in every client's tool list.
func TestInventoryTool_OffersItselfOnlyWhereThereIsAServerToList(t *testing.T) {
	t.Parallel()
	tool, err := NewInventoryTool(&fakeSurfaceInventory{inventory: &ToolInventory{}}, nil)
	if err != nil {
		t.Fatalf("new inventory tool: %v", err)
	}
	consumer := &consumerdomain.Consumer{Type: consumerdomain.TypeMCP}

	if defs := tool.Definitions(context.Background(), routable(consumer)); len(defs) != 0 {
		t.Fatalf("definitions = %v, want none for a consumer with no MCP server", defs)
	}

	reg := mcpRegistry(t, "linear", "https://linear.example.com/mcp")
	defs := tool.Definitions(context.Background(), routable(consumer, reg))
	if len(defs) != 1 || defs[0].Name != InventoryToolName {
		t.Fatalf("definitions = %v, want just %s", defs, InventoryToolName)
	}
}

func TestInventoryTool_HandlesOnlyItsOwnName(t *testing.T) {
	t.Parallel()
	tool, err := NewInventoryTool(&fakeSurfaceInventory{inventory: &ToolInventory{}}, nil)
	if err != nil {
		t.Fatalf("new inventory tool: %v", err)
	}

	if !tool.Handles(InventoryToolName) {
		t.Fatalf("%s must be handled here", InventoryToolName)
	}
	for _, name := range []string{StoreSearchToolName, ConnectToolName("notion"), "search_issues"} {
		if tool.Handles(name) {
			t.Fatalf("%q belongs to another handler", name)
		}
	}
}

// A toolkit governs a server whether or not that server answered. Describing an
// unconnected one from the catalog therefore has to stop at what policy allows:
// promising a tool the gateway would refuse is worse than saying nothing about
// it, and the inventory is read as a promise.
func TestInventoryTool_TrimsThePreviewToWhatPolicyAllows(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gatewayID, "Notion", "",
		&registrydomain.MCPTarget{URL: "https://notion.example.com/mcp", Code: "com.notion/mcp"})
	if err != nil {
		t.Fatalf("build registry: %v", err)
	}
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://notion.example.com/mcp": {tools: tools("query_database", "create_page")},
	}}
	creds := &fakeCreds{err: &ConsentRequiredError{Provider: "com.notion/mcp", Ticket: "tk", Path: "/p/mcp"}}
	consumer := &consumerdomain.Consumer{
		Type:      consumerdomain.TypeMCP,
		GatewayID: gatewayID,
		MCP: &consumerdomain.MCPPolicy{Toolkit: consumerdomain.Toolkit{
			{RegistryID: reg.ID, Tool: "query_database"},
		}},
	}
	c := NewComposer(dialer, creds, newMapCache(), slog.New(slog.DiscardHandler))
	inv, err := c.ToolInventory(context.Background(), routable(consumer, reg))
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}

	tool, err := NewInventoryTool(&fakeSurfaceInventory{inventory: inv}, notionCatalog())
	if err != nil {
		t.Fatalf("new inventory tool: %v", err)
	}
	servers := structuredServers(t, callInventory(t, tool, ""))
	if len(servers) != 1 {
		t.Fatalf("servers = %v, want the one pending server", servers)
	}
	listed, ok := servers[0]["tools"].([]any)
	if !ok || len(listed) != 1 {
		t.Fatalf("tools = %v, want only the tool the toolkit allows", servers[0]["tools"])
	}
	entry, _ := listed[0].(map[string]any)
	if entry["name"] != "query_database" {
		t.Fatalf("tool = %v, want query_database: create_page is not this consumer's to call", entry)
	}
}

// The reported problem: asked "what do I have in TrustGate?", a client read
// tools/list, found the gateway's own four tools there — they have to be listed
// to be callable — and reported them to the user as tools they have. The
// inventory's answer closes that door explicitly, in the text body, which is
// the part a client hands the model.
func TestInventoryTool_SaysTheGatewaysOwnToolsAreNotTheAnswer(t *testing.T) {
	t.Parallel()
	tool, err := NewInventoryTool(&fakeSurfaceInventory{inventory: twoServerInventory()}, nil)
	if err != nil {
		t.Fatalf("new inventory tool: %v", err)
	}

	text := resultText(t, callInventory(t, tool, ""))
	if !strings.Contains(text, "That is the whole list") {
		t.Fatalf("the answer must claim to be complete:\n%s", text)
	}
	if !strings.Contains(text, StoreToolNamePrefix) || !strings.Contains(text, InventoryToolName) {
		t.Fatalf("the answer must name the tools to leave out:\n%s", text)
	}
}

// An empty inventory is where the temptation is strongest — the client has
// nothing else to report, so it reaches for the gateway's own tools.
func TestInventoryTool_SaysItEvenWhenTheUserHasNothing(t *testing.T) {
	t.Parallel()
	tool, err := NewInventoryTool(&fakeSurfaceInventory{inventory: &ToolInventory{}}, nil)
	if err != nil {
		t.Fatalf("new inventory tool: %v", err)
	}

	text := resultText(t, callInventory(t, tool, ""))
	if !strings.Contains(text, "no MCP servers") {
		t.Fatalf("expected an empty answer:\n%s", text)
	}
	if !strings.Contains(text, "leave them out of the answer") {
		t.Fatalf("an empty answer still has to say what not to add:\n%s", text)
	}
}

// The definition itself says it, since a client reads descriptions when it
// decides what to call and what to report.
func TestInventoryTool_DefinitionSaysWhatIsNotIncluded(t *testing.T) {
	t.Parallel()
	tool, err := NewInventoryTool(&fakeSurfaceInventory{inventory: &ToolInventory{}}, nil)
	if err != nil {
		t.Fatalf("new inventory tool: %v", err)
	}
	reg := mcpRegistry(t, "linear", "https://linear.example.com/mcp")
	defs := tool.Definitions(context.Background(), routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, reg))
	if len(defs) != 1 {
		t.Fatalf("definitions = %v, want one", defs)
	}

	description := toolDescription(t, defs[0])
	if !strings.Contains(description, "not tools the user has") {
		t.Fatalf("the description must disown the gateway's own tools:\n%s", description)
	}
}

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
	"errors"
	"log/slog"
	"strings"
	"testing"

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
)

func inventoryByName(inv *ToolInventory, name string) *InventoryServer {
	for i := range inv.Servers {
		if inv.Servers[i].Name == name {
			return &inv.Servers[i]
		}
	}
	return nil
}

func inventoryToolNames(server *InventoryServer) []string {
	out := make([]string, 0, len(server.Tools))
	for _, tool := range server.Tools {
		out = append(out, tool.Name)
	}
	return out
}

// The whole point of the inventory: a server the user has but has not connected
// is part of the answer, where ListTools can only leave it out.
func TestComposer_ToolInventory_ReportsThePendingServerListToolsOmits(t *testing.T) {
	t.Parallel()
	regLinked := mcpRegistry(t, "linear", "https://linear.example.com/mcp")
	regPending := mcpRegistry(t, "notion", "https://notion.example.com/mcp")
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://linear.example.com/mcp": {tools: tools("search", "create_issue")},
		"https://notion.example.com/mcp": {tools: tools("query")},
	}}
	creds := &fakeCreds{errByURL: map[string]error{
		"https://notion.example.com/mcp": &ConsentRequiredError{Provider: "com.notion/mcp", Ticket: "tk", Path: "/p/mcp"},
	}}
	c := NewComposer(dialer, creds, newMapCache(), slog.New(slog.DiscardHandler))
	rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, regLinked, regPending)

	listed, err := c.ListTools(context.Background(), rc)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if names := toolNames(listed); len(names) != 2 {
		t.Fatalf("tools/list = %v, want only the linked server's two tools", names)
	}

	inv, err := c.ToolInventory(context.Background(), rc)
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	if len(inv.Servers) != 2 {
		t.Fatalf("servers = %d, want both the linked and the pending one", len(inv.Servers))
	}
	linked := inventoryByName(inv, "linear")
	if linked == nil || linked.State != InventoryStateReady {
		t.Fatalf("linear = %+v, want state %q", linked, InventoryStateReady)
	}
	if names := inventoryToolNames(linked); len(names) != 2 || names[0] != "search" || names[1] != "create_issue" {
		t.Fatalf("linear tools = %v, want [search create_issue]", names)
	}
	pending := inventoryByName(inv, "notion")
	if pending == nil || pending.State != InventoryStateNeedsConnect {
		t.Fatalf("notion = %+v, want state %q", pending, InventoryStateNeedsConnect)
	}
	if pending.Provider != "com.notion/mcp" {
		t.Fatalf("notion provider = %q, want the account the user must connect", pending.Provider)
	}
	if len(pending.Tools) != 0 {
		t.Fatalf("notion tools = %v, want none: nothing was discovered from an unconnected server",
			inventoryToolNames(pending))
	}
}

// A caller told a name the gateway does not answer to is worse off than one told
// nothing, so the inventory has to resolve names exactly as tools/list does —
// including the qualification two servers offering one name forces.
func TestComposer_ToolInventory_UsesTheSameExposedNamesAsListTools(t *testing.T) {
	t.Parallel()
	regA := mcpRegistry(t, "github", "https://a.example.com/mcp")
	regB := mcpRegistry(t, "slack", "https://b.example.com/mcp")
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://a.example.com/mcp": {tools: tools("search")},
		"https://b.example.com/mcp": {tools: tools("search")},
	}}
	c := newTestComposer(dialer)
	rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, regA, regB)

	listed, err := c.ListTools(context.Background(), rc)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	inv, err := c.ToolInventory(context.Background(), rc)
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	exposed := map[string]struct{}{}
	for _, name := range toolNames(listed) {
		exposed[name] = struct{}{}
	}
	if len(exposed) != 2 {
		t.Fatalf("tools/list = %v, want two distinct names", toolNames(listed))
	}
	for _, server := range inv.Servers {
		for _, tool := range server.Tools {
			if _, ok := exposed[tool.Name]; !ok {
				t.Fatalf("inventory offers %q, which tools/list does not expose (%v)", tool.Name, toolNames(listed))
			}
			if !tool.Callable {
				t.Fatalf("tool %q came from a reachable server, so it must be marked callable", tool.Name)
			}
		}
	}
}

// The upstream's own failure text names hosts and transports the caller can do
// nothing with; it belongs in the log, and the state is what the caller acts on.
func TestComposer_ToolInventory_KeepsTheUpstreamFailureOutOfTheAnswer(t *testing.T) {
	t.Parallel()
	reg := mcpRegistry(t, "github", "https://a.example.com/mcp")
	dialer := &fakeDialer{dialErr: map[string]error{
		"https://a.example.com/mcp": errors.New("dial tcp 10.1.2.3:443: connect: connection refused"),
	}}
	c := newTestComposer(dialer)

	inv, err := c.ToolInventory(context.Background(),
		routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, reg))
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	if len(inv.Servers) != 1 || inv.Servers[0].State != InventoryStateUnavailable {
		t.Fatalf("servers = %+v, want one %q", inv.Servers, InventoryStateUnavailable)
	}
	if strings.Contains(inv.Servers[0].Provider, "10.1.2.3") {
		t.Fatal("the inventory must not hand the upstream's dial error to the caller")
	}
}

// A tool policy removed is not a tool that is missing: naming it stops a caller
// hunting for something an administrator took away on purpose.
func TestComposer_ToolInventory_NamesWhatThePolicyTurnedAway(t *testing.T) {
	t.Parallel()
	reg := mcpRegistry(t, "github", "https://a.example.com/mcp")
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://a.example.com/mcp": {tools: tools("create_issue", "delete_repo")},
	}}
	c := newTestComposer(dialer)
	consumer := &consumerdomain.Consumer{
		Type: consumerdomain.TypeMCP,
		MCP: &consumerdomain.MCPPolicy{Toolkit: consumerdomain.Toolkit{
			{RegistryID: reg.ID, Tool: "create_issue"},
		}},
	}

	inv, err := c.ToolInventory(context.Background(), routable(consumer, reg))
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	server := inventoryByName(inv, "github")
	if server == nil {
		t.Fatal("github missing from the inventory")
	}
	if names := inventoryToolNames(server); len(names) != 1 || names[0] != "create_issue" {
		t.Fatalf("tools = %v, want only the allowed one", names)
	}
	if len(server.Denied) != 1 || server.Denied[0] != "delete_repo" {
		t.Fatalf("denied = %v, want [delete_repo]", server.Denied)
	}
}

// An empty inventory is an answer ("you have nothing"), not a failure — unlike
// tools/list, which rejects a consumer with no MCP server bound.
func TestComposer_ToolInventory_AnswersEmptyForAConsumerWithNoServer(t *testing.T) {
	t.Parallel()
	c := newTestComposer(&fakeDialer{})
	rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP})

	if _, err := c.ListTools(context.Background(), rc); !errors.Is(err, ErrNoMCPRegistries) {
		t.Fatalf("list tools error = %v, want %v", err, ErrNoMCPRegistries)
	}
	inv, err := c.ToolInventory(context.Background(), rc)
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	if len(inv.Servers) != 0 {
		t.Fatalf("servers = %+v, want none", inv.Servers)
	}
}

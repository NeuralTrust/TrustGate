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
	"errors"
	"fmt"
	"strings"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
)

const (
	// InventoryToolName is the gateway-implemented meta-tool that lists every
	// tool the calling user has, server by server, including the servers that
	// are serving nothing yet and why.
	InventoryToolName = "trustgate_list_tools"

	// maxInventoryDescription keeps one inventory line short. A caller wanting a
	// tool's full description gets it from tools/list once the tool is callable.
	maxInventoryDescription = 200
)

// GatewayToolDisclaimer is appended to every gateway-implemented tool's
// description. The gateway's own tools have to appear in tools/list for a
// client to be able to call them, so a client asked "what tools do I have?"
// sees them next to the user's and reports them as capabilities the user has —
// which they are not: they are how the user's surface is managed. Saying so in
// the description is the only lever there is; MCP has no way to mark a tool as
// plumbing rather than capability.
const GatewayToolDisclaimer = " This is one of the gateway's own tools, not one of the user's: leave it out when telling the user which tools or servers they have (" +
	InventoryToolName + " answers that)."

// inventoryClosingNote ends the inventory's answer. Without it a client that has
// just read tools/list tends to append the gateway's own tools to the list it
// reports, as though the user had those too.
const inventoryClosingNote = "\n\nThat is the whole list. The gateway's own " + InventoryToolName +
	" and " + StoreToolNamePrefix + "* tools are how this surface is managed, not tools the user has, so leave them out of the answer."

// ErrInventoryToolUnavailable is returned when the inventory meta-tool cannot
// serve a request (no composed surface behind it, or an unknown tool name).
var ErrInventoryToolUnavailable = errors.New("mcp: tool inventory unavailable")

// SurfaceInventory is the read side of the caller's composed MCP surface, one
// entry per bound server. Composer satisfies it.
type SurfaceInventory interface {
	ToolInventory(ctx context.Context, rc *appconsumer.RoutableConsumer) (*ToolInventory, error)
}

// InventoryTool implements the inventory meta-tool. It mirrors StoreTool's shape
// (its Call takes arguments, since a caller may narrow to one server).
type InventoryTool interface {
	Definitions(ctx context.Context, rc *appconsumer.RoutableConsumer) []Tool
	Handles(name string) bool
	Call(ctx context.Context, rc *appconsumer.RoutableConsumer, name string, arguments json.RawMessage) (json.RawMessage, error)
}

type inventoryTool struct {
	surface SurfaceInventory
	catalog MCPServerCatalog
}

// NewInventoryTool wires the inventory meta-tool. With a catalog it can also
// name the tools of a server that is not serving yet — the catalog carries a
// snapshot of what each server advertises — which is what makes an unconnected
// server's entry worth reading. Without one such a server is still listed, just
// without its tools.
func NewInventoryTool(surface SurfaceInventory, catalog MCPServerCatalog) (InventoryTool, error) {
	if surface == nil {
		return nil, ErrInventoryToolUnavailable
	}
	return &inventoryTool{surface: surface, catalog: catalog}, nil
}

func (t *inventoryTool) Handles(name string) bool {
	return name == InventoryToolName
}

// Definitions offers the inventory to every consumer that has an MCP server
// bound. Even a fully connected surface benefits — tools/list flattens every
// server into one list, so it never says which server a tool came from, nor
// which of the user's servers contributed nothing — and on an incomplete
// surface it is the only way to see what is missing and what would fix it.
func (t *inventoryTool) Definitions(_ context.Context, rc *appconsumer.RoutableConsumer) []Tool {
	if t == nil || t.surface == nil || rc == nil || rc.Consumer == nil {
		return nil
	}
	if len(mcpRegistries(rc)) == 0 {
		return nil
	}
	def, err := inventoryDefinition()
	if err != nil {
		return nil
	}
	return []Tool{def}
}

// inventoryArgs is the meta-tool's input: an optional narrowing to one server.
type inventoryArgs struct {
	Server string `json:"server,omitempty"`
}

func (t *inventoryTool) Call(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	name string,
	arguments json.RawMessage,
) (json.RawMessage, error) {
	if t == nil || t.surface == nil || rc == nil || rc.Consumer == nil {
		return nil, ErrInventoryToolUnavailable
	}
	if !t.Handles(name) {
		return nil, fmt.Errorf("%w: unknown tool %q", ErrInventoryToolUnavailable, name)
	}
	var args inventoryArgs
	if len(arguments) > 0 {
		if err := json.Unmarshal(arguments, &args); err != nil {
			return nil, fmt.Errorf("%w: decode arguments: %w", ErrInventoryToolUnavailable, err)
		}
	}
	inventory, err := t.surface.ToolInventory(ctx, rc)
	if err != nil {
		return nil, err
	}
	filter := strings.ToLower(strings.TrimSpace(args.Server))
	previews := t.catalogTools()

	servers := make([]map[string]any, 0, len(inventory.Servers))
	callable, pending := 0, 0
	for _, server := range inventory.Servers {
		if !matchesServerFilter(server, filter) {
			continue
		}
		entry := map[string]any{
			"name":  server.Name,
			"state": server.State,
		}
		if server.Code != "" {
			entry["code"] = server.Code
		}
		if server.Provider != "" {
			entry["provider"] = server.Provider
			// The connection meta-tool for this provider, so a caller can chain
			// straight into it. It is the name that tool derives from the same
			// provider; where two providers reduce to one slug the tool list is
			// authoritative.
			entry["connect_tool"] = ConnectToolName(server.Provider)
		}
		tools := server.Tools
		if len(tools) == 0 && notServing(server.State) {
			// The server never answered, so the catalog's snapshot of what it
			// advertises is what tells the user what they are missing. A server
			// that did answer and still offered nothing is not described from
			// outside: policy removed its tools on purpose.
			tools = previewTools(previews, server)
		}
		listed := make([]map[string]any, 0, len(tools))
		for _, tool := range tools {
			listed = append(listed, inventoryEntryJSON(tool))
			if tool.Callable {
				callable++
			} else {
				pending++
			}
		}
		entry["tools"] = listed
		entry["tool_count"] = len(listed)
		if len(server.Denied) > 0 {
			entry["denied_tools"] = server.Denied
		}
		servers = append(servers, entry)
	}

	return marshalToolResult(inventorySummary(servers, callable, pending, filter), map[string]any{
		"servers":        servers,
		"total_servers":  len(servers),
		"callable_tools": callable,
		"pending_tools":  pending,
	})
}

func inventoryEntryJSON(tool InventoryEntry) map[string]any {
	out := map[string]any{"name": tool.Name, "callable": tool.Callable}
	if title := strings.TrimSpace(tool.Title); title != "" {
		out["title"] = title
	}
	if desc := truncateDescription(tool.Description); desc != "" {
		out["description"] = desc
	}
	return out
}

// catalogTools indexes the catalog's advertised-tool snapshots by code, so a
// server that is not serving can still be described.
func (t *inventoryTool) catalogTools() map[string][]catalogdomain.MCPTool {
	if t.catalog == nil {
		return nil
	}
	entries := t.catalog.ListMCPServers()
	out := make(map[string][]catalogdomain.MCPTool, len(entries))
	for _, entry := range entries {
		if len(entry.Tools) == 0 {
			continue
		}
		out[entry.Code] = entry.Tools
	}
	return out
}

// notServing reports whether a server never answered discovery, so nothing is
// known about its tools from the server itself.
func notServing(state string) bool {
	return state == InventoryStateNeedsConnect || state == InventoryStateUnavailable
}

func previewTools(previews map[string][]catalogdomain.MCPTool, server InventoryServer) []InventoryEntry {
	if server.Code == "" || len(previews) == 0 {
		return nil
	}
	snapshot, ok := previews[server.Code]
	if !ok {
		return nil
	}
	out := make([]InventoryEntry, 0, len(snapshot))
	for _, tool := range snapshot {
		// The consumer's toolkit applies to a server whether or not it answered:
		// promising a tool policy would refuse is worse than saying nothing.
		if !server.Permits(tool.Name) {
			continue
		}
		out = append(out, InventoryEntry{Name: tool.Name, Description: tool.Description})
	}
	return out
}

func matchesServerFilter(server InventoryServer, filter string) bool {
	if filter == "" {
		return true
	}
	return strings.Contains(strings.ToLower(server.Name), filter) ||
		strings.Contains(strings.ToLower(server.Code), filter)
}

func truncateDescription(desc string) string {
	desc = strings.TrimSpace(desc)
	if len(desc) <= maxInventoryDescription {
		return desc
	}
	runes := []rune(desc)
	if len(runes) <= maxInventoryDescription {
		return desc
	}
	return strings.TrimSpace(string(runes[:maxInventoryDescription])) + "…"
}

// inventorySummary writes the answer the model reads. Many MCP clients surface
// only the text, so every server, its state and its tool names go in the body —
// not just in structuredContent — along with what to do about a server that is
// serving nothing.
func inventorySummary(servers []map[string]any, callable, pending int, filter string) string {
	var b strings.Builder
	if len(servers) == 0 {
		if filter != "" {
			fmt.Fprintf(&b, "No MCP server matching %q is available to you.", filter)
			b.WriteString(inventoryClosingNote)
			return b.String()
		}
		return "You have no MCP servers available." + inventoryClosingNote
	}
	fmt.Fprintf(&b, "You have %d MCP server(s): %d tool(s) callable now", len(servers), callable)
	if pending > 0 {
		fmt.Fprintf(&b, " and %d more waiting on a server that is not ready", pending)
	}
	b.WriteString(".")
	for _, server := range servers {
		fmt.Fprintf(&b, "\n\n• %s", displayString(server["name"]))
		if code := displayString(server["code"]); code != "" {
			fmt.Fprintf(&b, " (%s)", code)
		}
		fmt.Fprintf(&b, " — %s", inventoryStateText(server))
		names := toolNameList(server["tools"])
		if len(names) > 0 {
			fmt.Fprintf(&b, "\n  tools: %s", strings.Join(names, ", "))
		}
		if denied, ok := server["denied_tools"].([]string); ok && len(denied) > 0 {
			fmt.Fprintf(&b, "\n  blocked by policy: %s", strings.Join(denied, ", "))
		}
	}
	b.WriteString(inventoryClosingNote)
	return b.String()
}

func inventoryStateText(server map[string]any) string {
	switch displayString(server["state"]) {
	case InventoryStateReady:
		return "ready"
	case InventoryStateNeedsConnect:
		text := "not connected: its tools cannot be called until the user connects their account"
		if connect := displayString(server["connect_tool"]); connect != "" {
			text += ", which " + connect + " gives them a link for"
		}
		return text
	case InventoryStateUnavailable:
		return "unavailable: the gateway could not reach it, so its tools cannot be called right now"
	case InventoryStateNoTools:
		return "no tools available to this connection"
	default:
		return "unknown state"
	}
}

func toolNameList(raw any) []string {
	tools, ok := raw.([]map[string]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(tools))
	for _, tool := range tools {
		name := displayString(tool["name"])
		if name == "" {
			continue
		}
		out = append(out, name)
	}
	return out
}

func displayString(raw any) string {
	s, ok := raw.(string)
	if !ok {
		return ""
	}
	return s
}

func inventoryDefinition() (Tool, error) {
	raw, err := json.Marshal(map[string]any{
		"name":  InventoryToolName,
		"title": "List the tools this user has",
		"description": "List every tool the current user has through this gateway, grouped by the MCP server that serves it, with each server's state. " +
			"Call this when you need to know what the user can do beyond the tools currently in your list — the standard tool list only carries the tools of servers that are connected and reachable, so it is silent about a server the user has but has not connected yet, or one that is down. " +
			"Each server comes back as ready, needs_connect (its tools are named but not callable until the user connects their account), unavailable, or no_tools, and a needs_connect server names the connect tool that gives the user a link. " +
			"Use it to answer \"what can you do?\", to find out why an expected tool is missing, and to tell the user which of their servers needs attention. " +
			"What it returns is the whole answer: the gateway's own trustgate_* tools — this one, the Store's, the connect ones — are how that surface is managed, not tools the user has, so do not add them to it.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"server": map[string]any{
					"type":        "string",
					"description": "Narrow the answer to servers whose name or catalog code contains this text. Omit to list every server the user has.",
				},
			},
			"additionalProperties": false,
		},
		"annotations": map[string]any{
			"readOnlyHint":    true,
			"destructiveHint": false,
			"idempotentHint":  true,
			"openWorldHint":   false,
		},
	})
	if err != nil {
		return Tool{}, err
	}
	var def Tool
	if err := json.Unmarshal(raw, &def); err != nil {
		return Tool{}, err
	}
	return def, nil
}

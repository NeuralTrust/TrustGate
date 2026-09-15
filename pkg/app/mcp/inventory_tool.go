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
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
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
	offers  StoreOfferReader
}

// InventoryToolOption tunes NewInventoryTool.
type InventoryToolOption func(*inventoryTool)

// WithInventoryStoreOffer lets the inventory close the other half of the
// question. Asked what they have, a user is really asking what they can do
// here, and the servers they are entitled to install are part of that answer —
// invisible until now, because nothing lists them next to what is already
// bound.
func WithInventoryStoreOffer(r StoreOfferReader) InventoryToolOption {
	return func(t *inventoryTool) { t.offers = r }
}

// NewInventoryTool wires the inventory meta-tool. With a catalog it can also
// name the tools of a server that is not serving yet — the catalog carries a
// snapshot of what each server advertises — which is what makes an unconnected
// server's entry worth reading. Without one such a server is still listed, just
// without its tools.
func NewInventoryTool(surface SurfaceInventory, catalog MCPServerCatalog, opts ...InventoryToolOption) (InventoryTool, error) {
	if surface == nil {
		return nil, ErrInventoryToolUnavailable
	}
	t := &inventoryTool{surface: surface, catalog: catalog}
	for _, opt := range opts {
		if opt != nil {
			opt(t)
		}
	}
	return t, nil
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
		if server.Cause != "" {
			// The condition behind needs_connect. Without it a client can only
			// guess at the cause, and it guesses "the session expired" whatever
			// happened.
			entry["cause"] = server.Cause
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

	installable, offerMode := t.installable(ctx, rc, servers, filter)

	structured := map[string]any{
		"servers":        servers,
		"total_servers":  len(servers),
		"callable_tools": callable,
		"pending_tools":  pending,
	}
	if offerMode != "" {
		structured["store_mode"] = offerMode
	}
	if len(installable) > 0 {
		structured["installable"] = installable
	}
	return marshalToolResult(
		inventorySummary(servers, callable, pending, filter, installable, offerMode),
		structured,
	)
}

// installable is what the user could add to the surface they just asked about:
// the catalog entries the Store lets them install outright, minus the ones
// already bound. A server they would have to file a request for is left out —
// it is not theirs yet, and listing it as if it were is how a client ends up
// promising a tool nobody can call.
func (t *inventoryTool) installable(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	bound []map[string]any,
	filter string,
) ([]map[string]any, string) {
	if t.offers == nil {
		return nil, ""
	}
	offer, err := t.offers.StoreOffer(ctx, rc)
	if err != nil {
		// The surface is the answer; what could be added to it is not worth
		// failing the whole call for.
		return nil, ""
	}
	if !offer.Bounded {
		return nil, offer.Mode
	}
	have := make(map[string]struct{}, len(bound))
	for _, server := range bound {
		if code := displayString(server["code"]); code != "" {
			have[code] = struct{}{}
		}
	}
	out := make([]map[string]any, 0, len(offer.Servers))
	for _, entry := range offer.Servers {
		if _, bound := have[entry.Code]; bound {
			continue
		}
		if !matchesCatalogFilter(entry, filter) {
			continue
		}
		listed := map[string]any{
			"code":          entry.Code,
			"name":          displayName(entry),
			"requires_auth": entry.RequiresAuth,
			// The tool that adds it, so a caller can act on the answer rather
			// than describe it.
			"install_tool": StoreInstallToolName,
		}
		if desc := truncateDescription(entry.Description); desc != "" {
			listed["description"] = desc
		}
		out = append(out, listed)
	}
	return out, offer.Mode
}

// displayName is the catalog entry's name as a person reads it.
func displayName(entry catalogdomain.MCPServer) string {
	if name := strings.TrimSpace(entry.DisplayName); name != "" {
		return name
	}
	return entry.Code
}

func matchesCatalogFilter(entry catalogdomain.MCPServer, filter string) bool {
	if filter == "" {
		return true
	}
	return strings.Contains(strings.ToLower(entry.DisplayName), filter) ||
		strings.Contains(strings.ToLower(entry.Code), filter) ||
		strings.Contains(strings.ToLower(entry.Vendor), filter)
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
func inventorySummary(
	servers []map[string]any,
	callable, pending int,
	filter string,
	installable []map[string]any,
	storeMode string,
) string {
	var b strings.Builder
	if len(servers) == 0 {
		if filter != "" {
			fmt.Fprintf(&b, "No MCP server matching %q is on your surface.", filter)
		} else {
			b.WriteString("You have no MCP servers on your surface.")
		}
		writeInstallable(&b, installable, storeMode)
		b.WriteString(inventoryClosingNote)
		return b.String()
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
	writeInstallable(&b, installable, storeMode)
	b.WriteString(inventoryClosingNote)
	return b.String()
}

// writeInstallable names the servers the user may add but has not. A client
// that only reads the text would otherwise report the surface as everything
// available to them, when the Store is holding more of it a tool call away.
func writeInstallable(b *strings.Builder, installable []map[string]any, storeMode string) {
	if len(installable) > 0 {
		fmt.Fprintf(b, "\n\nYou can also add %d server(s) from the Store, with %s:", len(installable), StoreInstallToolName)
		for _, entry := range installable {
			fmt.Fprintf(b, "\n• %s (%s)", displayString(entry["name"]), displayString(entry["code"]))
			if desc := displayString(entry["description"]); desc != "" {
				fmt.Fprintf(b, " — %s", desc)
			}
		}
		// Said plainly, because the list sits next to servers the user does
		// have: a client that blurs the two starts answering "yes" to a
		// capability nobody can call yet.
		b.WriteString("\nThose are not on their surface yet — offer to add one; none of its tools can be called until it is added.")
		return
	}
	// Open access makes the whole catalog installable, so the list would be the
	// catalog. Naming the search tool is the useful form of that answer.
	if storeMode == gatewaydomain.StoreModeOpen {
		fmt.Fprintf(b, "\n\nThe Store is open to you: any server in the catalog can be added, and %s finds one by name or purpose.", StoreSearchToolName)
	}
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
		if cause := displayString(server["cause"]); cause != "" {
			text += " (" + cause + ")"
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
		"description": "List every tool the current user has through this gateway, grouped by the MCP server that serves it, with each server's state, and the servers they may add but have not. " +
			"Call this when you need to know what the user can do beyond the tools currently in your list — the standard tool list only carries the tools of servers that are connected and reachable, so it is silent about a server the user has but has not connected yet, or one that is down. " +
			"Each server comes back as ready, needs_connect (its tools are named but not callable until the user connects their account), unavailable, or no_tools, and a needs_connect server names the connect tool that gives the user a link. " +
			"The `installable` list is separate: those servers are not on the user's surface at all, but the Store lets them add each one with " + StoreInstallToolName + " — offer them rather than reporting their tools as available. " +
			"Use it to answer \"what can you do?\", to find out why an expected tool is missing, and to tell the user which of their servers needs attention or what they could add. " +
			"What it returns is the whole answer: the gateway's own trustgate_* tools — this one, the Store's, the connect ones — are how that surface is managed, not tools the user has, so do not add them to it.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"server": map[string]any{
					"type":        "string",
					"description": "Narrow the answer to servers whose name or catalog code contains this text, on the user's surface and in what they may add. Omit to list every server the user has.",
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

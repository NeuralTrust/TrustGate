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
	"strings"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// The state an inventoried MCP server is in for the calling principal.
const (
	// InventoryStateReady: the server answered and its tools are callable now.
	InventoryStateReady = "ready"
	// InventoryStateNeedsConnect: the server is bound but waiting for this
	// principal to connect their account, so it serves nothing yet.
	InventoryStateNeedsConnect = "needs_connect"
	// InventoryStateUnavailable: the gateway could not reach the server.
	InventoryStateUnavailable = "unavailable"
	// InventoryStateNoTools: the server answered but offers this consumer no
	// tools — it has none, or the consumer's toolkit allows none of them.
	InventoryStateNoTools = "no_tools"
)

// ToolInventory is the calling principal's whole MCP surface, server by server:
// what each bound server serves right now and, for the ones serving nothing,
// why. tools/list can only show the tools of servers that answered, so it is
// silent about exactly the servers a user needs to act on; this is the view that
// is not.
type ToolInventory struct {
	Servers []InventoryServer
}

// InventoryServer is one bound MCP server as the principal has it.
type InventoryServer struct {
	// Name is the server's name on this gateway (the registry's), which is what
	// qualifies its tools when two servers offer the same tool name.
	Name string
	// Code is the catalog code the server was installed from, empty for a
	// registry an admin wired by hand. It is what the Store meta-tools take.
	Code string
	// Provider names the upstream account a server awaiting consent needs.
	Provider string
	// Cause is why a needs_connect server is not serving, as one of the
	// ConsentCause codes. Empty for every other state. It is what keeps a
	// client from having to guess ("the session expired") when the gateway
	// already knows.
	Cause string
	State string
	Tools []InventoryEntry
	// Denied are the server's tool names this consumer's toolkit turns away.
	// Listing them keeps a caller from hunting for a tool policy has removed.
	Denied []string

	// policy is what the consumer's toolkit permits on this server. A server
	// that served nothing has no Tools to read, and describing it from elsewhere
	// (the catalog) must not name tools this consumer could never call — so the
	// permission travels with the entry. The zero value permits everything,
	// which keeps a hand-built InventoryServer unrestricted.
	policy toolPolicy
}

// Permits reports whether this consumer's toolkit lets it use the server's own
// tool by that name. It is what trims an outside description of a server that
// is not serving — the catalog's snapshot of its tools — to the part of it the
// consumer could actually call.
func (s InventoryServer) Permits(tool string) bool {
	return s.policy.permits(tool)
}

// InventoryEntry is one tool in the inventory. Callable entries carry the
// exposed name tools/call takes; the rest are the server's own names, which may
// be qualified once the server serves them.
type InventoryEntry struct {
	Name        string
	Title       string
	Description string
	Callable    bool
}

// ToolInventory reports every bound MCP server's contribution to this
// principal's surface. It never fails on an upstream: a server that cannot be
// reached or is awaiting consent is part of the answer, not an error.
func (c *composer) ToolInventory(ctx context.Context, rc *appconsumer.RoutableConsumer) (*ToolInventory, error) {
	registries := mcpRegistries(rc)
	if len(registries) == 0 {
		return &ToolInventory{}, nil
	}
	surfaces, err := c.serverSurfaces(ctx, rc, registries)
	if err != nil {
		return nil, err
	}
	// Exposed names are resolved across every reachable server at once — a name
	// two servers both serve gets qualified — so the inventory has to resolve
	// them the same way tools/list does, or it would advertise names tools/call
	// rejects.
	var candidates []binding
	for _, surface := range surfaces {
		if surface.serves() {
			candidates = append(candidates, surface.bindings...)
		}
	}
	resolved := resolveNames(candidates)

	out := &ToolInventory{Servers: make([]InventoryServer, 0, len(surfaces))}
	cursor := 0
	for _, surface := range surfaces {
		server := InventoryServer{
			Name:   inventoryServerName(surface.registry),
			Code:   registryCatalogCode(surface.registry),
			Denied: surface.denied,
			policy: surface.policy,
		}
		switch {
		case surface.consent != nil:
			server.State = InventoryStateNeedsConnect
			server.Provider = surface.consent.Provider
			server.Cause = surface.consent.Cause
		case surface.err != nil:
			// The upstream's own error is logged, not handed to the caller: it
			// carries hosts and transport detail the caller cannot act on.
			server.State = InventoryStateUnavailable
		default:
			for range surface.bindings {
				if cursor >= len(resolved) {
					break
				}
				b := resolved[cursor]
				cursor++
				server.Tools = append(server.Tools, InventoryEntry{
					Name:        b.exposed,
					Title:       stringField(b.tool.payload, "title"),
					Description: stringField(b.tool.payload, "description"),
					Callable:    true,
				})
			}
			server.State = InventoryStateReady
			if len(server.Tools) == 0 {
				server.State = InventoryStateNoTools
			}
		}
		out.Servers = append(out.Servers, server)
	}
	return out, nil
}

// serves reports whether the server answered discovery, so its bindings took
// part in name resolution.
func (s serverSurface) serves() bool {
	return s.consent == nil && s.err == nil
}

func inventoryServerName(reg *registrydomain.Registry) string {
	if reg == nil {
		return ""
	}
	if name := strings.TrimSpace(reg.Name); name != "" {
		return name
	}
	return registryCatalogCode(reg)
}

func registryCatalogCode(reg *registrydomain.Registry) string {
	if reg == nil || reg.MCPTarget == nil {
		return ""
	}
	return strings.TrimSpace(reg.MCPTarget.Code)
}

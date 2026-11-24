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

	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
)

// Surface is which set of the gateway's own tools a caller is offered.
//
// The gateway grew one meta-tool per need — an inventory, a call-through, a
// connect tool per provider, six Store tools, two agent tools — until there
// were four ways to look something up and three ways to call. The
// consolidated surface replaces them with three: trustgate_search to find
// anything, trustgate_call to call a tool or an agent by name, and
// trustgate_access to change what the user has.
//
// The earlier tools cannot simply go. Claude's hosted connectors keep the
// tool list they fetched when the person connected them, whatever the gateway
// announces, until the person reconnects. A connection opened before the
// gateway turned the consolidated tools on is still offered the earlier ones,
// and every name — earlier and consolidated — is answered on every
// connection, so a list fetched under either keeps working.
type Surface int

const (
	// SurfaceLegacy is the earlier set: trustgate_list_tools,
	// trustgate_call_tool, trustgate_connect_*, trustgate_store_*,
	// trustgate_list_agents and trustgate_call_agent.
	SurfaceLegacy Surface = iota
	// SurfaceConsolidated is trustgate_search, trustgate_call and
	// trustgate_access.
	SurfaceConsolidated
)

// String names the surface for telemetry and logs.
func (s Surface) String() string {
	if s == SurfaceConsolidated {
		return "consolidated"
	}
	return "legacy"
}

// SurfaceFor decides which of the gateway's tools this request is offered.
//
// A gateway that has not turned the consolidated tools on serves the earlier
// ones to everyone. One that has serves the consolidated tools, except to a
// session its own sign-in opened before they were turned on: that client
// fetched the earlier list when it connected and, if it is a hosted connector,
// keeps it until the person reconnects. A session from before the connection
// time was recorded is one of those. Api keys, personal keys, certificates and
// a customer identity provider's tokens carry no connection time; the clients
// that use them re-list on start, and the earlier names keep answering for
// the ones that do not.
func SurfaceFor(ctx context.Context) Surface {
	gw, ok := appgateway.FromContext(ctx)
	if !ok {
		return SurfaceLegacy
	}
	since, on := gw.MCPGatewayToolsSince()
	if !on {
		return SurfaceLegacy
	}
	principal := identity.PrincipalFromContext(ctx)
	if !principal.IsGatewaySession() {
		return SurfaceConsolidated
	}
	connected, dated := principal.MCPSessionStart()
	if !dated || connected.Before(since) {
		return SurfaceLegacy
	}
	return SurfaceConsolidated
}

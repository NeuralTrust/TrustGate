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

package response

import (
	"testing"
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/version"
)

func TestFromDomain_IncludesSlug(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	gw := domain.Rehydrate(ids.New[ids.GatewayKind](), "acme", "active", "", nil, nil, nil, now, now)

	got := FromDomain(gw, "llm.neuraltrust.ai", "mcp.neuraltrust.ai")
	if got.Slug != "acme" {
		t.Fatalf("Slug = %q, want acme", got.Slug)
	}
	if got.Version != version.Version {
		t.Fatalf("Version = %q, want %q", got.Version, version.Version)
	}
	if got.Hosts.Proxy != "acme.llm.neuraltrust.ai" {
		t.Fatalf("Hosts.Proxy = %q, want acme.llm.neuraltrust.ai", got.Hosts.Proxy)
	}
	if got.Hosts.MCP != "acme.mcp.neuraltrust.ai" {
		t.Fatalf("Hosts.MCP = %q, want acme.mcp.neuraltrust.ai", got.Hosts.MCP)
	}
}

func TestFromDomain_IncludesEntitlements(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	gw := domain.Rehydrate(ids.New[ids.GatewayKind](), "acme", "active", "", nil, nil, nil, now, now)
	gw.Entitlements = domain.Entitlements{Tier: "standard"}

	got := FromDomain(gw, "llm.neuraltrust.ai", "mcp.neuraltrust.ai")
	if got.Entitlements.Tier != "standard" {
		t.Fatalf("Entitlements.Tier = %q, want standard", got.Entitlements.Tier)
	}
}

func TestFromDomain_CustomDomainHost(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	gw := domain.Rehydrate(ids.New[ids.GatewayKind](), "acme", "active", "", nil, nil, nil, now, now)
	gw.Domain = "api.acme.com"

	got := FromDomain(gw, "llm.neuraltrust.ai", "mcp.neuraltrust.ai")
	if got.Hosts.Proxy != "api.acme.com" {
		t.Fatalf("Hosts.Proxy = %q, want api.acme.com", got.Hosts.Proxy)
	}
	if got.Hosts.MCP != "acme.mcp.neuraltrust.ai" {
		t.Fatalf("Hosts.MCP = %q, want acme.mcp.neuraltrust.ai", got.Hosts.MCP)
	}
}

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
	"encoding/json"
	"strings"
	"testing"
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/version"
)

func TestFromDomain_IncludesSlug(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	gw := domain.Rehydrate(ids.New[ids.GatewayKind](), "acme", "active", "", nil, nil, nil, now, now)

	got := FromDomain(gw, "llm.neuraltrust.ai", "mcp.neuraltrust.ai", "", "")
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

func TestFromDomain_AgentHost(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	gw := domain.Rehydrate(ids.New[ids.GatewayKind](), "acme", "active", "", nil, nil, nil, now, now)

	got := FromDomain(gw, "llm.neuraltrust.ai", "mcp.neuraltrust.ai", "agents.neuraltrust.ai", "trustgate")
	if got.Hosts.Agent != "acme.agents.neuraltrust.ai" {
		t.Fatalf("Hosts.Agent = %q, want acme.agents.neuraltrust.ai", got.Hosts.Agent)
	}
	if got.AgentTokenIssuer != "trustgate" {
		t.Fatalf("AgentTokenIssuer = %q, want trustgate", got.AgentTokenIssuer)
	}

	without := FromDomain(gw, "llm.neuraltrust.ai", "mcp.neuraltrust.ai", "", "trustgate")
	if without.AgentTokenIssuer != "" {
		t.Fatalf("AgentTokenIssuer without AGENT_BASE_DOMAIN = %q", without.AgentTokenIssuer)
	}
	body, err := json.Marshal(without.Hosts)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"proxy":"acme.llm.neuraltrust.ai","mcp":"acme.mcp.neuraltrust.ai"}` {
		t.Fatalf("hosts without AGENT_BASE_DOMAIN = %s", body)
	}
}

func TestFromDomain_IncludesEntitlements(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	gw := domain.Rehydrate(ids.New[ids.GatewayKind](), "acme", "active", "", nil, nil, nil, now, now)
	gw.Entitlements = domain.Entitlements{Tier: "standard"}

	got := FromDomain(gw, "llm.neuraltrust.ai", "mcp.neuraltrust.ai", "", "")
	if got.Entitlements.Tier != "standard" {
		t.Fatalf("Entitlements.Tier = %q, want standard", got.Entitlements.Tier)
	}
}

func TestFromDomain_CustomDomainHost(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	gw := domain.Rehydrate(ids.New[ids.GatewayKind](), "acme", "active", "", nil, nil, nil, now, now)
	gw.Domain = "api.acme.com"

	got := FromDomain(gw, "llm.neuraltrust.ai", "mcp.neuraltrust.ai", "", "")
	if got.Hosts.Proxy != "api.acme.com" {
		t.Fatalf("Hosts.Proxy = %q, want api.acme.com", got.Hosts.Proxy)
	}
	if got.Hosts.MCP != "acme.mcp.neuraltrust.ai" {
		t.Fatalf("Hosts.MCP = %q, want acme.mcp.neuraltrust.ai", got.Hosts.MCP)
	}
}

// The console reads the Store's curation mode from here to decide what a user
// may install at once. It used to live only inside metadata, and a reader that
// missed it there saw the domain default — open — so a curated Store looked
// wide open and every install came back as an approval request.
func TestFromDomain_ReportsTheStoreMode(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	for _, tc := range []struct {
		name     string
		metadata map[string]string
		want     string
	}{
		{"stamped open", map[string]string{domain.MetadataStoreModeKey: domain.StoreModeOpen}, domain.StoreModeOpen},
		{"stamped none", map[string]string{domain.MetadataStoreModeKey: domain.StoreModeNone}, domain.StoreModeNone},
		// Nothing stamped is a gateway nobody has governed, which grants nobody
		// anything rather than opening the catalog to the whole org.
		{"unstamped", nil, domain.StoreModeCurated},
		{"nonsense", map[string]string{domain.MetadataStoreModeKey: "whatever"}, domain.StoreModeCurated},
	} {
		gw := domain.Rehydrate(ids.New[ids.GatewayKind](), "acme", "active", "", nil, domain.ClientTLSConfig{}, nil, now, now)
		gw.Metadata = tc.metadata
		if got := FromDomain(gw, "llm.neuraltrust.ai", "mcp.neuraltrust.ai", "", ""); got.StoreMode != tc.want {
			t.Fatalf("%s: StoreMode = %q, want %q", tc.name, got.StoreMode, tc.want)
		}
	}
}

func TestFromDomain_OmitsTelemetryCredentials(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	gw := domain.Rehydrate(ids.New[ids.GatewayKind](), "acme", "active", "", nil, nil, nil, now, now)
	gw.Telemetry = &telemetry.Telemetry{Exporters: []telemetry.ExporterConfig{
		{Name: "otlp", Settings: map[string]any{
			"endpoint": "https://collector.example.com",
			"headers":  map[string]any{"Authorization": "Bearer secret-token"},
		}},
		{Name: "postgres", Settings: map[string]any{"dsn": "postgres://u:secret@db/metrics"}},
	}}

	body, err := json.Marshal(FromDomain(gw, "llm.neuraltrust.ai", "mcp.neuraltrust.ai", "", ""))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, leaked := range []string{"secret-token", "u:secret@", `"headers"`, `"dsn"`} {
		if strings.Contains(string(body), leaked) {
			t.Fatalf("response carries %q: %s", leaked, body)
		}
	}
	if !strings.Contains(string(body), "https://collector.example.com") {
		t.Fatalf("response lost the endpoint: %s", body)
	}
	if _, ok := gw.Telemetry.Exporters[0].Settings["headers"]; !ok {
		t.Fatal("FromDomain removed the headers from the stored gateway")
	}
}

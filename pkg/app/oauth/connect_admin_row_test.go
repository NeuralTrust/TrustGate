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

package oauth_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
)

// The admin form writes account_url, database, schema and name into the
// server URL and stores the client on the row. Connect must fill the catalog
// OAuth templates from that URL. An employee value for account_url is not used.
func TestConnect_SnowflakeQAResolvesTheAdminURL(t *testing.T) {
	t.Parallel()
	cat, err := catalog.NewMCPServerCatalog(nil)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	const code = "com.snowflake/mcp"
	entry, ok := cat.GetByCode(code)
	if !ok || entry.OAuth == nil {
		t.Fatal("missing snowflake catalog entry")
	}
	const saved = "https://xy12345.us-east-1.snowflakecomputing.com/api/v2/databases/QA_MCP/schemas/PUBLIC/mcp-servers/QA_AGENT"
	target := &registrydomain.MCPTarget{
		Code:      code,
		URL:       saved,
		Transport: registrydomain.MCPTransportStreamableHTTP,
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     code,
			Registration: registrydomain.RegistrationManual,
			ClientID:     "qa-client",
			ClientSecret: "qa-secret",
		},
	}
	if err := appregistry.CanonicalizeMCPAuthFromCatalog(target, cat); err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if err := appregistry.RequireAdminBoundURLVariables(target, cat); err != nil {
		t.Fatalf("admin gate: %v", err)
	}
	if !strings.Contains(target.Auth.AuthorizeURL, "{account_url}") || !strings.Contains(target.Auth.TokenURL, "{account_url}") {
		t.Fatalf("catalog templates were rewritten: auth=%s token=%s", target.Auth.AuthorizeURL, target.Auth.TokenURL)
	}
	reg, err := registrydomain.NewMCPRegistry(ids.New[ids.GatewayKind](), "snowflake-qa", "", target)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	svc := templatedConnectCatalog(t, reg, map[string]string{
		"account_url": "evil.example",
		"database":    "OTHER",
		"schema":      "OTHER",
		"name":        "OTHER",
	}, &fixedRegistrar{}, cat)
	ticket, err := svc.CreateTicket(context.Background(), reg.GatewayID, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	location, err := startLocation(svc.Start(context.Background(), "https://gw.example.com", "https://gw.example.com", ticket, code, ""))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	const authorize = "https://xy12345.us-east-1.snowflakecomputing.com/oauth/authorize?"
	if !strings.HasPrefix(location, authorize) {
		t.Fatalf("redirect = %q, want prefix %s", location, authorize)
	}
	if strings.Contains(location, "evil.example") || strings.Contains(location, "OTHER") {
		t.Fatalf("employee values reached the redirect: %s", location)
	}
	q := mustAdminQuery(t, location)
	if q.Get("client_id") != "qa-client" {
		t.Fatalf("client_id = %q", q.Get("client_id"))
	}
	if q.Get("resource") != saved {
		t.Fatalf("resource = %q", q.Get("resource"))
	}
}

func TestRequireAdminBoundURLVariables_RejectsAnOpenSnowflakeTemplate(t *testing.T) {
	t.Parallel()
	cat, err := catalog.NewMCPServerCatalog(nil)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	target := adminAppTarget(t, cat, "com.snowflake/mcp", "qa-client", "qa-secret")
	if err := appregistry.CanonicalizeMCPAuthFromCatalog(target, cat); err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	err = appregistry.RequireAdminBoundURLVariables(target, cat)
	if err == nil || !strings.Contains(err.Error(), "account_url") {
		t.Fatalf("gate = %v, want account_url required", err)
	}
}

// Two PagerDuty registries, one per region. Authorize stays on the catalog's
// global endpoint. The EU host is the OAuth resource and the vault key, taken
// from the admin URL, not from an employee installation of the other region.
func TestConnect_PagerDutyInstancesBindTheirOwnRegion(t *testing.T) {
	t.Parallel()
	cat, err := catalog.NewMCPServerCatalog(nil)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	const code = "com.pagerduty/mcp"
	us := pagerDutyAdminRegistry(t, cat, "pagerduty-qa", "https://mcp.pagerduty.com/mcp")
	eu := pagerDutyAdminRegistry(t, cat, "pagerduty-eu-qa", "https://mcp.eu.pagerduty.com/mcp")

	usKey := registrydomain.ForwardedVaultProvider(us)
	euKey := registrydomain.ForwardedVaultProvider(eu)
	if usKey == "" || euKey == "" || usKey == euKey {
		t.Fatalf("vault keys us=%s eu=%s", usKey, euKey)
	}
	overlaid := registrydomain.RegistryWithInstanceConfig(eu, map[string]string{"host": "mcp.pagerduty.com"})
	if registrydomain.ForwardedVaultProvider(overlaid) != euKey {
		t.Fatalf("employee host changed the EU vault key to %s", registrydomain.ForwardedVaultProvider(overlaid))
	}
	if registrydomain.ForwardedCredentialResource(eu) != "https://mcp.eu.pagerduty.com/mcp" {
		t.Fatalf("EU resource = %s", registrydomain.ForwardedCredentialResource(eu))
	}
	if registrydomain.ForwardedCredentialResource(us) != "https://mcp.pagerduty.com/mcp" {
		t.Fatalf("US resource = %s", registrydomain.ForwardedCredentialResource(us))
	}

	gw := eu.GatewayID
	vault := &memVaultRepo{}
	cred, err := vaultdomain.NewCredential(gw, "alice", euKey, "europe-user", "eu-access", "eu-refresh", []string{"read"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if err := vault.Upsert(context.Background(), cred); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if _, err := vault.Find(context.Background(), gw, "alice", euKey); err != nil {
		t.Fatalf("EU credential: %v", err)
	}
	if _, err := vault.Find(context.Background(), gw, "alice", usKey); err == nil {
		t.Fatal("US instance found the EU credential")
	}

	for _, tc := range []struct {
		name     string
		reg      *registrydomain.Registry
		resource string
	}{
		{name: "us", reg: us, resource: "https://mcp.pagerduty.com/mcp"},
		{name: "eu", reg: eu, resource: "https://mcp.eu.pagerduty.com/mcp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			employee := map[string]string{"host": "mcp.pagerduty.com"}
			if tc.name == "us" {
				employee["host"] = "mcp.eu.pagerduty.com"
			}
			svc := templatedConnectCatalog(t, tc.reg, employee, &fixedRegistrar{}, cat)
			ticket, err := svc.CreateTicket(context.Background(), tc.reg.GatewayID, "alice", "/dev/mcp")
			if err != nil {
				t.Fatalf("CreateTicket: %v", err)
			}
			location, err := startLocation(svc.Start(context.Background(), "https://gw.example.com", "https://gw.example.com", ticket, code, tc.reg.ID.String()))
			if err != nil {
				t.Fatalf("Start: %v", err)
			}
			const authorize = "https://app.pagerduty.com/global/oauth/authorize?"
			if !strings.HasPrefix(location, authorize) {
				t.Fatalf("redirect = %q, want the catalog authorize endpoint", location)
			}
			q := mustAdminQuery(t, location)
			if q.Get("resource") != tc.resource {
				t.Fatalf("resource = %q, want %s", q.Get("resource"), tc.resource)
			}
			if strings.Contains(q.Get("resource"), "{") {
				t.Fatalf("resource is still a template: %s", q.Get("resource"))
			}
		})
	}
}

func pagerDutyAdminRegistry(t *testing.T, cat catalog.MCPServerCatalog, name, savedURL string) *registrydomain.Registry {
	t.Helper()
	const code = "com.pagerduty/mcp"
	target := &registrydomain.MCPTarget{
		Code:      code,
		URL:       savedURL,
		Transport: registrydomain.MCPTransportStreamableHTTP,
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     code,
			Registration: registrydomain.RegistrationManual,
			ClientID:     "pagerduty-client",
			ClientSecret: "pagerduty-secret",
			Resource:     "https://{host}/mcp",
		},
	}
	if err := appregistry.CanonicalizeMCPAuthFromCatalog(target, cat); err != nil {
		t.Fatalf("canonicalize %s: %v", name, err)
	}
	// The resource the admin saved is the concrete server URL. Put the catalog
	// template back so the credential key has to recover the region from the
	// URL, which is what a row keeps when the template was stored.
	target.Auth.Resource = "https://{host}/mcp"
	target.Auth.ResourcePerInstance = true
	reg, err := registrydomain.NewMCPRegistry(ids.New[ids.GatewayKind](), name, "", target)
	if err != nil {
		t.Fatalf("registry %s: %v", name, err)
	}
	return reg
}

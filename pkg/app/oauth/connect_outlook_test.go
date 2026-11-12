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

package oauth

import (
	"context"
	"testing"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

const (
	outlookCode         = "com.microsoft/outlook"
	outlookTenant       = "11111111-2222-3333-4444-555555555555"
	outlookResource     = "api://ea9ffc3e-8a23-4a7d-836d-234d7c7565c1"
	outlookTenantMCPURL = "https://agent365.svc.cloud.microsoft/agents/tenants/" + outlookTenant + "/servers/mcp_MailTools"
)

// Entra rejects a resource that is not an identifier of the API named in
// scope (AADSTS9010010). Agent Tools does not list the tenant-scoped MCP URL
// among its identifiers, so a row installed when the catalog copied that URL
// into resource must still send the Agent Tools app id URI at connect time.
func TestFinalizeAuthURLs_ExistingOutlookRowSendsAgentToolsResource(t *testing.T) {
	t.Parallel()
	cat, entry := outlookCatalog(t)
	cfg := &registrydomain.MCPAuth{
		Mode:         registrydomain.MCPAuthModeForwarded,
		Provider:     outlookCode,
		Registration: registrydomain.RegistrationManual,
		ClientID:     "cid",
		AuthorizeURL: "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize",
		TokenURL:     "https://login.microsoftonline.com/organizations/oauth2/v2.0/token",
		Scopes:       entry.OAuth.Scopes,
		Resource:     entry.URL,
	}
	reg, res := outlookRow(entry, cfg)

	finalized, err := (&connectService{catalog: cat}).finalizeAuthURLs(
		context.Background(), reg.GatewayID, "alice", reg, applyCatalog(cfg, reg, cat, res), nil, res,
	)
	if err != nil {
		t.Fatalf("finalizeAuthURLs: %v", err)
	}
	if finalized.Resource != outlookResource {
		t.Fatalf("resource = %q, want %s", finalized.Resource, outlookResource)
	}
	if cfg.Resource != entry.URL {
		t.Fatal("applyCatalog mutated the stored auth")
	}
}

// A new install copies the catalog authorize and token templates. They must
// resolve to the tenant's own authority: a single-tenant app cannot sign in
// through /organizations.
func TestFinalizeAuthURLs_NewOutlookRowUsesTenantAuthority(t *testing.T) {
	t.Parallel()
	cat, entry := outlookCatalog(t)
	cfg := &registrydomain.MCPAuth{
		Mode:         registrydomain.MCPAuthModeForwarded,
		Provider:     outlookCode,
		Registration: registrydomain.RegistrationManual,
		ClientID:     "cid",
		ClientSecret: "secret",
		AuthorizeURL: entry.OAuth.AuthorizeURL,
		TokenURL:     entry.OAuth.TokenURL,
		Scopes:       entry.OAuth.Scopes,
		Resource:     entry.OAuth.Resource,
	}
	reg, res := outlookRow(entry, cfg)

	finalized, err := (&connectService{catalog: cat}).finalizeAuthURLs(
		context.Background(), reg.GatewayID, "alice", reg, applyCatalog(cfg, reg, cat, res), nil, res,
	)
	if err != nil {
		t.Fatalf("finalizeAuthURLs: %v", err)
	}
	authority := "https://login.microsoftonline.com/" + outlookTenant + "/oauth2/v2.0/"
	if finalized.AuthorizeURL != authority+"authorize" {
		t.Fatalf("authorize = %q", finalized.AuthorizeURL)
	}
	if finalized.TokenURL != authority+"token" {
		t.Fatalf("token = %q", finalized.TokenURL)
	}
	if finalized.Resource != outlookResource {
		t.Fatalf("resource = %q, want %s", finalized.Resource, outlookResource)
	}
}

func outlookCatalog(t *testing.T) (authCatalog, catalogdomain.MCPServer) {
	t.Helper()
	cat, err := appcatalog.NewMCPServerCatalog(nil)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	entry, ok := cat.GetByCode(outlookCode)
	if !ok || entry.OAuth == nil {
		t.Fatalf("missing catalog entry %s", outlookCode)
	}
	return cat, entry
}

func outlookRow(entry catalogdomain.MCPServer, cfg *registrydomain.MCPAuth) (*registrydomain.Registry, upstreamResolution) {
	vars := make([]registrydomain.MCPURLVariable, 0, len(entry.URLVariables))
	for _, variable := range entry.URLVariables {
		vars = append(vars, toRegistryURLVar(variable))
	}
	values := map[string]string{"tenantId": outlookTenant}
	reg := &registrydomain.Registry{
		GatewayID: ids.New[ids.GatewayKind](),
		MCPTarget: &registrydomain.MCPTarget{
			Code:           outlookCode,
			URL:            entry.URL,
			URLVariables:   vars,
			InstanceConfig: values,
			Auth:           cfg,
		},
	}
	return reg, upstreamResolution{url: outlookTenantMCPURL, values: values, ready: true}
}

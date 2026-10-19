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
	"net/url"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// An admin-registered OAuth app accepts a client id and an optional client
// secret, and the authorize redirect carries that client id with PKCE. An
// empty client id is rejected before a registry can be stored.
func TestConnectService_AdminOAuthAppsUseClientIDAndPKCE(t *testing.T) {
	t.Parallel()
	cat, err := catalog.NewMCPServerCatalog(nil)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	cases := []struct {
		code            string
		values          map[string]string
		authorizePrefix string
		scope           string
		resource        string
	}{
		{
			code:            "com.salesforce/mcp",
			values:          map[string]string{"server": "sobject-all"},
			authorizePrefix: "https://login.salesforce.com/services/oauth2/authorize?",
			scope:           "mcp_api refresh_token",
			resource:        "https://api.salesforce.com/platform/mcp/v1/platform/sobject-all",
		},
		{
			code:            "com.salesforce/mcp-sandbox",
			values:          map[string]string{"server": "sobject-all"},
			authorizePrefix: "https://test.salesforce.com/services/oauth2/authorize?",
			scope:           "mcp_api refresh_token",
			resource:        "https://api.salesforce.com/platform/mcp/v1/sandbox/platform/sobject-all",
		},
		{
			code:            "com.servicenow/mcp",
			values:          map[string]string{"instance": "acme", "server": "quickstart"},
			authorizePrefix: "https://acme.service-now.com/oauth_auth.do?",
			scope:           "useraccount",
			resource:        "https://acme.service-now.com/sncapps/mcp-server/mcp/quickstart",
		},
		{
			code: "com.snowflake/mcp",
			values: map[string]string{
				"account_url": "org-acct.snowflakecomputing.com",
				"database":    "ANALYTICS",
				"schema":      "PUBLIC",
				"name":        "AGENT",
			},
			authorizePrefix: "https://org-acct.snowflakecomputing.com/oauth/authorize?",
			scope:           "refresh_token session:role:all",
			resource:        "https://org-acct.snowflakecomputing.com/api/v2/databases/ANALYTICS/schemas/PUBLIC/mcp-servers/AGENT",
		},
		{
			code:            "com.getdbt/mcp",
			values:          map[string]string{"dbt_host": "acme.us1.dbt.com"},
			authorizePrefix: "https://acme.us1.dbt.com/oauth/authorize?",
			scope:           "offline_access account:read projects:query catalog:read",
			resource:        "https://acme.us1.dbt.com/api/ai/v1/mcp/",
		},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			t.Parallel()
			assertAdminClientRejected(t, cat, tc.code, "")
			assertAdminClientRejected(t, cat, tc.code, "   ")
			for _, secret := range []string{"", "admin-secret"} {
				reg := adminAppRegistry(t, cat, tc.code, "admin-client", secret)
				registrar := &fixedRegistrar{}
				svc := templatedConnectCatalog(t, reg, tc.values, registrar, cat)
				ticket, err := svc.CreateTicket(context.Background(), reg.GatewayID, "alice", "/dev/mcp")
				if err != nil {
					t.Fatalf("CreateTicket: %v", err)
				}
				location, err := startLocation(svc.Start(context.Background(), "https://gw.example.com", "https://gw.example.com", ticket, tc.code, ""))
				if err != nil {
					t.Fatalf("Start secret=%q: %v", secret, err)
				}
				if !strings.HasPrefix(location, tc.authorizePrefix) {
					t.Fatalf("redirect = %q", location)
				}
				if len(registrar.discovered) != 0 {
					t.Fatalf("manual registration discovered %v", registrar.discovered)
				}
				q := mustAdminQuery(t, location)
				if q.Get("client_id") != "admin-client" {
					t.Fatalf("client_id = %q", q.Get("client_id"))
				}
				if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
					t.Fatalf("pkce = challenge %q method %q", q.Get("code_challenge"), q.Get("code_challenge_method"))
				}
				if q.Get("scope") != tc.scope {
					t.Fatalf("scope = %q", q.Get("scope"))
				}
				if q.Get("resource") != tc.resource {
					t.Fatalf("resource = %q", q.Get("resource"))
				}
			}
		})
	}
}

func assertAdminClientRejected(t *testing.T, cat catalog.MCPServerCatalog, code, clientID string) {
	t.Helper()
	target := adminAppTarget(t, cat, code, clientID, "admin-secret")
	if err := appregistry.CanonicalizeMCPAuthFromCatalog(target, cat); err != nil {
		t.Fatalf("canonicalize %s: %v", code, err)
	}
	if strings.TrimSpace(target.Auth.ClientID) != "" {
		t.Fatalf("empty client id was kept as %q", target.Auth.ClientID)
	}
	_, err := registrydomain.NewMCPRegistry(ids.New[ids.GatewayKind](), code, "", target)
	if err == nil || !strings.Contains(err.Error(), "requires client_id") {
		t.Fatalf("NewMCPRegistry(%q) = %v, want client_id required", clientID, err)
	}
}

func adminAppRegistry(t *testing.T, cat catalog.MCPServerCatalog, code, clientID, clientSecret string) *registrydomain.Registry {
	t.Helper()
	target := adminAppTarget(t, cat, code, clientID, clientSecret)
	if err := appregistry.CanonicalizeMCPAuthFromCatalog(target, cat); err != nil {
		t.Fatalf("canonicalize %s: %v", code, err)
	}
	if target.Auth.Registration != registrydomain.RegistrationManual {
		t.Fatalf("registration = %s", target.Auth.Registration)
	}
	if target.Auth.ClientID != clientID || target.Auth.ClientSecret != clientSecret {
		t.Fatalf("credentials changed: id=%q secret=%q", target.Auth.ClientID, target.Auth.ClientSecret)
	}
	entry, _ := cat.GetByCode(code)
	if strings.Join(target.Auth.Scopes, " ") != strings.Join(entry.OAuth.Scopes, " ") {
		t.Fatalf("scopes = %v, want %v", target.Auth.Scopes, entry.OAuth.Scopes)
	}
	reg, err := registrydomain.NewMCPRegistry(ids.New[ids.GatewayKind](), code, "", target)
	if err != nil {
		t.Fatalf("registry %s: %v", code, err)
	}
	return reg
}

func adminAppTarget(t *testing.T, cat catalog.MCPServerCatalog, code, clientID, clientSecret string) *registrydomain.MCPTarget {
	t.Helper()
	entry, ok := cat.GetByCode(code)
	if !ok || entry.OAuth == nil {
		t.Fatalf("missing catalog entry %s", code)
	}
	return &registrydomain.MCPTarget{
		Code:         code,
		URL:          entry.URL,
		Transport:    registrydomain.MCPTransportStreamableHTTP,
		URLVariables: adminAppURLVars(entry),
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     code,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		},
	}
}

func adminAppURLVars(entry catalogdomain.MCPServer) []registrydomain.MCPURLVariable {
	if len(entry.URLVariables) == 0 {
		return nil
	}
	out := make([]registrydomain.MCPURLVariable, 0, len(entry.URLVariables))
	for _, variable := range entry.URLVariables {
		converted := registrydomain.MCPURLVariable{
			Name:       variable.Name,
			Required:   variable.Required,
			HostSuffix: append([]string(nil), variable.HostSuffix...),
		}
		for _, option := range variable.Options {
			converted.Options = append(converted.Options, registrydomain.MCPURLVariableOption{
				Value: option.Value,
				Label: option.Label,
			})
		}
		out = append(out, converted)
	}
	return out
}

func mustAdminQuery(t *testing.T, location string) url.Values {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("location: %v", err)
	}
	return u.Query()
}

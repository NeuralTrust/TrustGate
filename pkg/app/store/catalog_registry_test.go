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

package store

import (
	"testing"

	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func TestCatalogRegistry_OAuthAuto(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg, err := catalogRegistry(catalogdomain.MCPServer{
		Code:        "app.linear/mcp",
		DisplayName: "Linear",
		URL:         "https://mcp.linear.app/mcp",
		Transport:   "streamable-http",
		AuthHint:    "oauth",
		OAuth: &catalogdomain.MCPOAuth{
			Required:     true,
			Registration: "auto",
			AuthorizeURL: "https://mcp.linear.app/authorize",
			TokenURL:     "https://mcp.linear.app/token",
			Scopes:       []string{"read", "write"},
			Resource:     "https://mcp.linear.app/mcp",
		},
	}, gw)
	if err != nil {
		t.Fatalf("catalogRegistry: %v", err)
	}
	if reg.GatewayID != gw || reg.Type != registrydomain.TypeMCP || !reg.Enabled {
		t.Fatalf("unexpected registry envelope: %+v", reg)
	}
	tgt := reg.MCPTarget
	if tgt == nil || tgt.Code != "app.linear/mcp" || tgt.URL != "https://mcp.linear.app/mcp" {
		t.Fatalf("unexpected target: %+v", tgt)
	}
	if tgt.Store == nil || !tgt.StoreAvailable() {
		t.Fatalf("materialised registry must be available on the shelf: %+v", tgt.Store)
	}
	if tgt.Auth == nil || tgt.Auth.Mode != registrydomain.MCPAuthModeForwarded {
		t.Fatalf("oauth-auto must map to forwarded, got %+v", tgt.Auth)
	}
	if tgt.Auth.Registration != registrydomain.RegistrationAuto ||
		tgt.Auth.AuthorizeURL != "https://mcp.linear.app/authorize" ||
		tgt.Auth.TokenURL != "https://mcp.linear.app/token" {
		t.Fatalf("oauth fields not carried: %+v", tgt.Auth)
	}
}

func TestCatalogRegistry_UrlTemplatePreserved(t *testing.T) {
	// Snowflake's URL is a template with {account_url} etc. — the shared registry
	// keeps the template; per-user values fill it from the installation later.
	reg, err := catalogRegistry(catalogdomain.MCPServer{
		Code:      "com.snowflake/mcp",
		URL:       "https://{account_url}/api/v2/databases/{database}/schemas/{schema}/mcp-servers/{name}",
		Transport: "streamable-http",
		AuthHint:  "oauth",
		OAuth:     &catalogdomain.MCPOAuth{Required: true, ResourceMetadata: true},
	}, ids.New[ids.GatewayKind]())
	if err != nil {
		t.Fatalf("catalogRegistry: %v", err)
	}
	if reg.MCPTarget.URL != "https://{account_url}/api/v2/databases/{database}/schemas/{schema}/mcp-servers/{name}" {
		t.Fatalf("URL template must be preserved verbatim, got %q", reg.MCPTarget.URL)
	}
	if reg.MCPTarget.Auth.Mode != registrydomain.MCPAuthModeForwarded {
		t.Fatalf("oauth with no explicit registration defaults to forwarded/auto, got %+v", reg.MCPTarget.Auth)
	}
}

func TestCatalogRegistry_NoAuthPublicServer(t *testing.T) {
	reg, err := catalogRegistry(catalogdomain.MCPServer{
		Code:      "dev.socket/mcp",
		URL:       "https://mcp.socket.dev/",
		Transport: "streamable-http",
		AuthHint:  "none",
	}, ids.New[ids.GatewayKind]())
	if err != nil {
		t.Fatalf("catalogRegistry: %v", err)
	}
	if reg.MCPTarget.Auth == nil || reg.MCPTarget.Auth.Mode != registrydomain.MCPAuthModeNone {
		t.Fatalf("public server must map to auth none, got %+v", reg.MCPTarget.Auth)
	}
	if !reg.MCPTarget.StoreAvailable() {
		t.Fatal("public server must be available on the shelf")
	}
}

func TestCatalogRegistry_ClientCredentials(t *testing.T) {
	reg, err := catalogRegistry(catalogdomain.MCPServer{
		Code:     "com.example/mcp",
		URL:      "https://mcp.example.com/mcp",
		AuthHint: "oauth",
		OAuth: &catalogdomain.MCPOAuth{
			GrantType: "client_credentials",
			TokenURL:  "https://mcp.example.com/token",
		},
	}, ids.New[ids.GatewayKind]())
	if err != nil {
		t.Fatalf("catalogRegistry: %v", err)
	}
	if reg.MCPTarget.Auth.Mode != registrydomain.MCPAuthModeClientCredentials {
		t.Fatalf("client_credentials grant must map to that mode, got %+v", reg.MCPTarget.Auth)
	}
	// Secret is never in the catalog — left blank for the admin to fill.
	if reg.MCPTarget.Auth.ClientSecret != "" {
		t.Fatalf("client secret must not be materialised from the catalog, got %q", reg.MCPTarget.Auth.ClientSecret)
	}
}

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

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
)

type stubScopeCatalog struct {
	code   string
	scopes []string
}

func (c stubScopeCatalog) GetByCode(code string) (catalogdomain.MCPServer, bool) {
	if code != c.code {
		return catalogdomain.MCPServer{}, false
	}
	return catalogdomain.MCPServer{
		Code:  c.code,
		OAuth: &catalogdomain.MCPOAuth{Scopes: c.scopes},
	}, true
}

// A registry keeps the scopes it was created with, so correcting the catalog is
// the only way to stop asking an upstream for a scope it no longer publishes
// (Vanta dropped mcp-api.all:read). The auto-registration path used to ignore
// the catalog entirely, leaving such a registry stuck on the stale list.
func TestConnectService_AutoRegistrationAppliesCatalogScopes(t *testing.T) {
	t.Parallel()
	registrations := 0
	var tokenForm url.Values
	upstream := fakeSpecUpstream(t, &registrations, &tokenForm)

	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "vanta-mcp", "", &registrydomain.MCPTarget{
		URL:  upstream.URL + "/mcp",
		Code: "com.vanta/mcp",
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     "com.vanta/mcp",
			Registration: registrydomain.RegistrationAuto,
			// Persisted before the catalog dropped the read scope.
			Scopes: []string{"mcp-api.all:read", "mcp-api.all:write"},
		},
	})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	data := appconsumer.NewData(gw, []appconsumer.RoutableConsumer{{
		Consumer: &consumerdomain.Consumer{
			ID: ids.New[ids.ConsumerKind](), GatewayID: gw,
			Type: consumerdomain.TypeMCP, Slug: "dev", Active: true,
		},
		Registries: []*registrydomain.Registry{reg},
	}})
	store := newMemConnectStore()
	svc := oauth.NewConnectService(
		store,
		&memVaultRepo{},
		&stubDataFinder{data: data},
		infraoauth.NewProviderClient(nil),
		infraoauth.NewUpstreamRegistrar(store, nil),
		discardConnectAuditor(),
		nil,
		nil,
		stubScopeCatalog{code: "com.vanta/mcp", scopes: []string{"mcp-api.all:write"}},
	)
	ctx := context.Background()

	ticket, err := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	location, err := svc.Start(ctx, "https://gw.example.com", ticket, "com.vanta/mcp")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	u, _ := url.Parse(location)
	if got := u.Query().Get("scope"); got != "mcp-api.all:write" {
		t.Fatalf("scope = %q, want only the catalog scope mcp-api.all:write", got)
	}

	refreshed, err := svc.RefreshAuth(ctx, gw, reg)
	if err != nil {
		t.Fatalf("RefreshAuth: %v", err)
	}
	if got := strings.Join(refreshed.Scopes, " "); got != "mcp-api.all:write" {
		t.Fatalf("refresh scope = %q, want only the catalog scope", got)
	}
}

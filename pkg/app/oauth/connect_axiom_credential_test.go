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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
)

// axiomStyleUpstream mimics Axiom: protected-resource metadata at the MCP
// path advertises the origin as its resource, while the MCP endpoint itself
// is origin/mcp.
func axiomStyleUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srvURL string
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              srvURL,
			"authorization_servers": []string{srvURL},
			"scopes_supported":      []string{"read"},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 srvURL,
			"authorization_endpoint": srvURL + "/authorize",
			"token_endpoint":         srvURL + "/token",
			"registration_endpoint":  srvURL + "/register",
		})
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "axiom-client"})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "axiom-access", "refresh_token": "axiom-refresh", "expires_in": 3600,
		})
	})
	srv := httptest.NewServer(mux)
	srvURL = srv.URL
	t.Cleanup(srv.Close)
	return srv
}

// The catalog resource (the origin) and the registry resource (the MCP URL)
// differ, which is Axiom's shape. Connect stores the credential under the
// registry's vault key, and the dial path reads that same key.
func TestConnectService_AxiomCredentialIsFoundOnTheDialPath(t *testing.T) {
	t.Parallel()
	upstream := axiomStyleUpstream(t)
	origin := upstream.URL
	mcpURL := origin + "/mcp"

	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "axiom-mcp", "", &registrydomain.MCPTarget{
		URL:  mcpURL,
		Code: "co.axiom/mcp",
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     "co.axiom/mcp",
			Registration: registrydomain.RegistrationAuto,
			Resource:     mcpURL,
		},
	})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	rc := appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID: ids.New[ids.ConsumerKind](), GatewayID: gw,
			Type: consumerdomain.TypeMCP, Slug: "dev", Active: true,
		},
		Registries: []*registrydomain.Registry{reg},
	}
	data := appconsumer.NewData(gw, []appconsumer.RoutableConsumer{rc})
	vault := &memVaultRepo{}
	store := newMemConnectStore()
	svc := oauth.NewConnectService(
		store,
		vault,
		&stubDataFinder{data: data},
		infraoauth.NewProviderClient(nil),
		infraoauth.NewUpstreamRegistrar(store, nil),
		discardConnectAuditor(),
		nil,
		nil,
		stubScopeCatalog{code: "co.axiom/mcp", url: mcpURL, resource: origin},
		nil,
	)
	ctx := context.Background()
	ticket, err := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	location, err := startLocation(svc.Start(ctx, "https://gw.example.com", "https://gw.example.com", ticket, "co.axiom/mcp", ""))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	u, _ := url.Parse(location)
	if got := u.Query().Get("resource"); got != origin {
		t.Fatalf("authorize resource = %q, want the catalog origin %q", got, origin)
	}
	if _, err := svc.Callback(ctx, "https://gw.example.com", "co.axiom/mcp", u.Query().Get("state"), "the-code", "", ""); err != nil {
		t.Fatalf("Callback: %v", err)
	}

	dialKey := registrydomain.ForwardedVaultProvider(reg)
	if registrydomain.ForwardedCredentialResource(reg) != mcpURL && !strings.HasSuffix(registrydomain.ForwardedCredentialResource(reg), "/mcp") {
		t.Fatalf("dial resource = %q, want the registry MCP resource", registrydomain.ForwardedCredentialResource(reg))
	}
	if registrydomain.ForwardedCredentialResource(reg) == origin {
		t.Fatal("dial resource collapsed to the catalog origin")
	}
	cred, err := vault.Find(ctx, gw, "alice", dialKey)
	if err != nil || cred.AccessToken != "axiom-access" {
		t.Fatalf("credential at the dial key = %+v, err = %v", cred, err)
	}

	auth := *reg.MCPTarget.Auth
	auth.Resource = origin
	catalogView := *reg
	target := *reg.MCPTarget
	target.Auth = &auth
	catalogView.MCPTarget = &target
	if registrydomain.ForwardedVaultProvider(&catalogView) == dialKey {
		t.Fatal("catalog origin and registry resource unexpectedly share a vault key")
	}

	resolver := appmcp.NewCredentialResolver(nil, vault, nil, nil, nil)
	dialCtx := identity.WithPrincipal(ctx, &identity.Principal{Subject: "alice"})
	dialTarget := &appmcp.Target{URL: mcpURL, Headers: map[string]string{}}
	if err := resolver.Apply(dialCtx, &rc, reg, dialTarget); err != nil {
		t.Fatalf("dial path did not find the credential stored at connect: %v", err)
	}
	if got := dialTarget.Headers["Authorization"]; got != "Bearer axiom-access" {
		t.Fatalf("Authorization = %q, want the token stored at connect", got)
	}
}

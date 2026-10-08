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
	"sync"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/app/mcpoauth"
	"github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
)

// discoveringRegistrar answers discovery with fixed metadata; it registers no
// clients.
type discoveringRegistrar struct{ meta oauth.UpstreamAuthServer }

func (r discoveringRegistrar) Discover(context.Context, string) (*oauth.UpstreamAuthServer, error) {
	meta := r.meta
	return &meta, nil
}

func (discoveringRegistrar) EnsureClient(context.Context, string, *oauth.UpstreamAuthServer, string) (*oauth.RegisteredClient, error) {
	return nil, nil
}

func (discoveringRegistrar) CachedClient(context.Context, string) (*oauth.RegisteredClient, error) {
	return nil, nil
}

func sharedGmailWithDiscovery(t *testing.T, meta oauth.UpstreamAuthServer, client *http.Client) (oauth.ConnectService, ids.GatewayID, *registrydomain.Registry) {
	t.Helper()
	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "gmail-mcp", "", &registrydomain.MCPTarget{
		Code: mcpoauth.GmailCode,
		URL:  "https://gmailmcp.googleapis.com/mcp/v1",
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     mcpoauth.GmailCode,
			Registration: registrydomain.RegistrationManual,
			ClientID:     "placeholder",
			ClientSecret: "placeholder",
			AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:     "https://oauth2.googleapis.com/token",
		},
	})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	auth := reg.MCPTarget.Auth
	auth.ClientID, auth.ClientSecret, auth.AuthorizeURL, auth.TokenURL = "", "", "", ""
	data := appconsumer.NewData(gw, []appconsumer.RoutableConsumer{{
		Consumer: &consumerdomain.Consumer{
			ID: ids.New[ids.ConsumerKind](), GatewayID: gw,
			Type: consumerdomain.TypeMCP, Slug: "dev", Active: true,
		},
		Registries: []*registrydomain.Registry{reg},
	}})
	svc := oauth.NewConnectService(
		newMemConnectStore(),
		&memVaultRepo{},
		&stubDataFinder{data: data},
		infraoauth.NewProviderClient(client),
		discoveringRegistrar{meta: meta},
		discardConnectAuditor(),
		mcpoauth.NewGoogleWorkspace("nt-client", "nt-secret"),
		nil, nil, nil,
	)
	return svc, gw, reg
}

func TestConnectService_SharedSecretWithheldWhenDiscoveryPointsElsewhere(t *testing.T) {
	t.Parallel()
	var (
		mu       sync.Mutex
		gotForm  url.Values
		tokenHit bool
	)
	token := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		gotForm, tokenHit = r.Form, true
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "a", "expires_in": 3600})
	}))
	defer token.Close()
	svc, gw, reg := sharedGmailWithDiscovery(t, oauth.UpstreamAuthServer{
		AuthorizationEndpoint: "https://login.elsewhere.example/authorize",
		TokenEndpoint:         token.URL,
	}, nil)
	ctx := context.Background()

	refreshed, err := svc.RefreshAuth(ctx, gw, reg)
	if err != nil {
		t.Fatalf("RefreshAuth: %v", err)
	}
	if refreshed.ClientID != "nt-client" || refreshed.ClientSecret != "" || refreshed.TokenURL != token.URL {
		t.Fatalf("refresh cfg = client %q secret set %v token %q, want the shared id without its secret",
			refreshed.ClientID, refreshed.ClientSecret != "", refreshed.TokenURL)
	}

	ticket, _ := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
	started, err := svc.Start(ctx, "https://gw.example", "https://gw.example", ticket, mcpoauth.GmailCode, "")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := svc.Callback(ctx, "https://gw.example", mcpoauth.GmailCode, started.State, "the-code", "", ""); err != nil {
		t.Fatalf("Callback: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !tokenHit {
		t.Fatal("the code was not redeemed at the discovered token endpoint")
	}
	if gotForm.Get("client_secret") != "" {
		t.Fatal("the shared client secret was sent to an endpoint that is not the provider's")
	}
}

func TestConnectService_SharedSecretKeptWhenDiscoveryPointsAtTheProvider(t *testing.T) {
	t.Parallel()
	svc, gw, reg := sharedGmailWithDiscovery(t, oauth.UpstreamAuthServer{
		AuthorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
		TokenEndpoint:         "https://oauth2.googleapis.com/token",
	}, nil)
	refreshed, err := svc.RefreshAuth(context.Background(), gw, reg)
	if err != nil {
		t.Fatalf("RefreshAuth: %v", err)
	}
	if refreshed.ClientID != "nt-client" || refreshed.ClientSecret != "nt-secret" {
		t.Fatalf("refresh cfg = client %q secret kept %v, want the shared client", refreshed.ClientID, refreshed.ClientSecret == "nt-secret")
	}
}

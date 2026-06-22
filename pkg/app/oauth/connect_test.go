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
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
)

type memConnectStore struct {
	tickets  map[string]oauth.ConnectTicket
	connects map[string]oauth.ConnectState
	clients  map[string]oauth.RegisteredClient
}

func newMemConnectStore() *memConnectStore {
	return &memConnectStore{
		tickets:  map[string]oauth.ConnectTicket{},
		connects: map[string]oauth.ConnectState{},
		clients:  map[string]oauth.RegisteredClient{},
	}
}

func (m *memConnectStore) SaveClient(_ context.Context, key string, c oauth.RegisteredClient) error {
	m.clients[key] = c
	return nil
}

func (m *memConnectStore) GetClient(_ context.Context, key string) (*oauth.RegisteredClient, error) {
	c, ok := m.clients[key]
	if !ok {
		return nil, nil
	}
	return &c, nil
}

func (m *memConnectStore) SaveTicket(_ context.Context, id string, t oauth.ConnectTicket) error {
	m.tickets[id] = t
	return nil
}

func (m *memConnectStore) GetTicket(_ context.Context, id string) (*oauth.ConnectTicket, error) {
	t, ok := m.tickets[id]
	if !ok {
		return nil, nil
	}
	return &t, nil
}

func (m *memConnectStore) SaveConnect(_ context.Context, state string, s oauth.ConnectState) error {
	m.connects[state] = s
	return nil
}

func (m *memConnectStore) TakeConnect(_ context.Context, state string) (*oauth.ConnectState, error) {
	s, ok := m.connects[state]
	if !ok {
		return nil, nil
	}
	delete(m.connects, state)
	return &s, nil
}

type memVaultRepo struct {
	creds map[string]*vaultdomain.Credential
}

func (m *memVaultRepo) k(gw ids.GatewayID, sub, p string) string { return gw.String() + sub + p }

func (m *memVaultRepo) Upsert(_ context.Context, c *vaultdomain.Credential) error {
	if m.creds == nil {
		m.creds = map[string]*vaultdomain.Credential{}
	}
	m.creds[m.k(c.GatewayID, c.PrincipalSub, c.Provider)] = c
	return nil
}

func (m *memVaultRepo) Find(_ context.Context, gw ids.GatewayID, sub, p string) (*vaultdomain.Credential, error) {
	c, ok := m.creds[m.k(gw, sub, p)]
	if !ok {
		return nil, vaultdomain.ErrNotFound
	}
	return c, nil
}

func (m *memVaultRepo) ListByPrincipal(context.Context, ids.GatewayID, string) ([]*vaultdomain.Credential, error) {
	return nil, nil
}

func (m *memVaultRepo) Delete(_ context.Context, gw ids.GatewayID, sub, p string) error {
	if _, ok := m.creds[m.k(gw, sub, p)]; !ok {
		return vaultdomain.ErrNotFound
	}
	delete(m.creds, m.k(gw, sub, p))
	return nil
}

type stubDataFinder struct {
	data *appconsumer.Data
}

func (s *stubDataFinder) FindByGateway(context.Context, ids.GatewayID) (*appconsumer.Data, error) {
	return s.data, nil
}

func connectFixture(t *testing.T, providerTokenURL string) (oauth.ConnectService, *memVaultRepo, ids.GatewayID) {
	t.Helper()
	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "github-mcp", "", &registrydomain.MCPTarget{
		URL: "https://up.example.com/mcp",
		Auth: &registrydomain.MCPAuth{
			Mode: registrydomain.MCPAuthModeForwarded, Provider: "github",
			ClientID: "cid", ClientSecret: "csecret",
			AuthorizeURL: "https://github.com/login/oauth/authorize",
			TokenURL:     providerTokenURL,
			Scopes:       []string{"repo"},
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
	vault := &memVaultRepo{}
	store := newMemConnectStore()
	svc := oauth.NewConnectService(store, vault, &stubDataFinder{data: data}, infraoauth.NewProviderClient(nil), infraoauth.NewUpstreamRegistrar(store, nil))
	return svc, vault, gw
}

func TestConnectService_FullConsentFlow(t *testing.T) {
	t.Parallel()
	var gotForm url.Values
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.Form
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "gh-access", "refresh_token": "gh-refresh",
			"expires_in": 3600, "scope": "repo",
		})
	}))
	defer provider.Close()

	svc, vault, gw := connectFixture(t, provider.URL)
	ctx := context.Background()

	ticket, err := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}

	page, err := svc.Page(ctx, ticket)
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if len(page.Providers) != 1 || page.Providers[0].Provider != "github" || page.Providers[0].Linked {
		t.Fatalf("page = %+v, want one unlinked github provider", page)
	}

	location, err := svc.Start(ctx, "https://gw.example.com", ticket, "github")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	u, _ := url.Parse(location)
	if !strings.HasPrefix(location, "https://github.com/login/oauth/authorize?") {
		t.Fatalf("redirect = %q", location)
	}
	if u.Query().Get("redirect_uri") != "https://gw.example.com/oauth/callback/github" {
		t.Fatalf("redirect_uri = %q", u.Query().Get("redirect_uri"))
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatal("no state in authorize URL")
	}

	backTicket, err := svc.Callback(ctx, "https://gw.example.com", "github", state, "the-code", "", "")
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if backTicket != ticket {
		t.Fatalf("ticket = %q, want %q", backTicket, ticket)
	}
	if gotForm.Get("code") != "the-code" || gotForm.Get("client_secret") != "csecret" {
		t.Fatalf("token form = %v", gotForm)
	}

	cred, err := vault.Find(ctx, gw, "alice", "github")
	if err != nil {
		t.Fatalf("vault.Find: %v", err)
	}
	if cred.AccessToken != "gh-access" || cred.RefreshToken != "gh-refresh" {
		t.Fatalf("vaulted credential = %+v", cred)
	}

	page, _ = svc.Page(ctx, ticket)
	if !page.Providers[0].Linked {
		t.Fatal("provider not reported linked after callback")
	}

	if err := svc.Disconnect(ctx, ticket, "github"); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if _, err := vault.Find(ctx, gw, "alice", "github"); !errors.Is(err, vaultdomain.ErrNotFound) {
		t.Fatal("credential still present after disconnect")
	}
}

func fakeSpecUpstream(t *testing.T, registrations *int, tokenForm *url.Values) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srvURL string
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              srvURL + "/mcp",
			"authorization_servers": []string{srvURL},
			"scopes_supported":      []string{"read", "write"},
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
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		*registrations++
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["token_endpoint_auth_method"] != "none" {
			t.Errorf("DCR auth method = %v, want none (public client + PKCE)", req["token_endpoint_auth_method"])
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "dcr-client-1"})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		*tokenForm = r.Form
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "linear-access", "refresh_token": "linear-refresh", "expires_in": 3600,
		})
	})
	srv := httptest.NewServer(mux)
	srvURL = srv.URL
	t.Cleanup(srv.Close)
	return srv
}

func TestConnectService_AutoRegistrationFlow(t *testing.T) {
	t.Parallel()
	registrations := 0
	var tokenForm url.Values
	upstream := fakeSpecUpstream(t, &registrations, &tokenForm)

	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "linear-mcp", "", &registrydomain.MCPTarget{
		URL: upstream.URL + "/mcp",
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     "linear",
			Registration: registrydomain.RegistrationAuto,
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
	registrar := infraoauth.NewUpstreamRegistrar(store, nil)
	vault := &memVaultRepo{}
	svc := oauth.NewConnectService(store, vault, &stubDataFinder{data: data}, infraoauth.NewProviderClient(nil), registrar)
	ctx := context.Background()

	ticket, err := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	location, err := svc.Start(ctx, "https://gw.example.com", ticket, "linear")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	u, _ := url.Parse(location)
	if !strings.HasPrefix(location, upstream.URL+"/authorize?") {
		t.Fatalf("redirect = %q, want discovered authorize endpoint", location)
	}
	q := u.Query()
	if q.Get("client_id") != "dcr-client-1" {
		t.Fatalf("client_id = %q, want DCR-issued client", q.Get("client_id"))
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("missing PKCE challenge in %v", q)
	}
	if q.Get("resource") != upstream.URL+"/mcp" {
		t.Fatalf("resource = %q, want upstream MCP URL", q.Get("resource"))
	}
	if q.Get("scope") != "read write" {
		t.Fatalf("scope = %q, want scopes from discovery", q.Get("scope"))
	}

	if _, err := svc.Callback(ctx, "https://gw.example.com", "linear", q.Get("state"), "the-code", "", ""); err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if tokenForm.Get("code_verifier") == "" {
		t.Fatal("token call missing PKCE code_verifier")
	}
	if tokenForm.Get("client_secret") != "" {
		t.Fatal("public client must not send client_secret")
	}
	if tokenForm.Get("client_id") != "dcr-client-1" {
		t.Fatalf("token client_id = %q", tokenForm.Get("client_id"))
	}
	cred, err := vault.Find(ctx, gw, "alice", "linear")
	if err != nil || cred.AccessToken != "linear-access" {
		t.Fatalf("vaulted credential = %+v, err = %v", cred, err)
	}
	if registrations != 1 {
		t.Fatalf("registrations = %d, want exactly 1 (Callback must reuse the cached client)", registrations)
	}

	if _, err := svc.Start(ctx, "https://gw.example.com", ticket, "linear"); err != nil {
		t.Fatalf("second Start: %v", err)
	}
	if registrations != 1 {
		t.Fatalf("registrations = %d after second Start, want 1", registrations)
	}

	refreshCfg, err := svc.RefreshAuth(ctx, gw, reg)
	if err != nil {
		t.Fatalf("RefreshAuth: %v", err)
	}
	if refreshCfg.ClientID != "dcr-client-1" || refreshCfg.TokenURL != upstream.URL+"/token" {
		t.Fatalf("refresh cfg = %+v", refreshCfg)
	}
}

func TestConnectService_AutoRegistrationUpstreamNotDiscoverable(t *testing.T) {
	t.Parallel()
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer dead.Close()

	gw := ids.New[ids.GatewayKind]()
	reg, _ := registrydomain.NewMCPRegistry(gw, "legacy-mcp", "", &registrydomain.MCPTarget{
		URL: dead.URL + "/mcp",
		Auth: &registrydomain.MCPAuth{
			Mode: registrydomain.MCPAuthModeForwarded, Provider: "legacy",
			Registration: registrydomain.RegistrationAuto,
		},
	})
	data := appconsumer.NewData(gw, []appconsumer.RoutableConsumer{{
		Consumer: &consumerdomain.Consumer{
			ID: ids.New[ids.ConsumerKind](), GatewayID: gw,
			Type: consumerdomain.TypeMCP, Slug: "dev", Active: true,
		},
		Registries: []*registrydomain.Registry{reg},
	}})
	store := newMemConnectStore()
	svc := oauth.NewConnectService(store, &memVaultRepo{}, &stubDataFinder{data: data}, infraoauth.NewProviderClient(nil), infraoauth.NewUpstreamRegistrar(store, nil))
	ctx := context.Background()
	ticket, _ := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
	if _, err := svc.Start(ctx, "https://gw", ticket, "legacy"); !errors.Is(err, oauth.ErrUpstreamNotDiscoverable) {
		t.Fatalf("error = %v, want oauth.ErrUpstreamNotDiscoverable", err)
	}
}

func TestConnectService_StateIsSingleUse(t *testing.T) {
	t.Parallel()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "x"})
	}))
	defer provider.Close()
	svc, _, gw := connectFixture(t, provider.URL)
	ctx := context.Background()
	ticket, _ := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
	location, _ := svc.Start(ctx, "https://gw", ticket, "github")
	u, _ := url.Parse(location)
	state := u.Query().Get("state")

	if _, err := svc.Callback(ctx, "https://gw", "github", state, "c", "", ""); err != nil {
		t.Fatalf("first callback: %v", err)
	}
	if _, err := svc.Callback(ctx, "https://gw", "github", state, "c", "", ""); err == nil {
		t.Fatal("state replay succeeded, want single-use")
	}
}

func TestConnectService_UnknownTicketAndProvider(t *testing.T) {
	t.Parallel()
	svc, _, gw := connectFixture(t, "https://unused")
	ctx := context.Background()
	if _, err := svc.Page(ctx, "missing"); !errors.Is(err, oauth.ErrTicketNotFound) {
		t.Fatalf("error = %v, want oauth.ErrTicketNotFound", err)
	}
	ticket, _ := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
	if _, err := svc.Start(ctx, "https://gw", ticket, "slack"); !errors.Is(err, oauth.ErrProviderNotFound) {
		t.Fatalf("error = %v, want oauth.ErrProviderNotFound", err)
	}
}

func TestConnectService_ChainURL(t *testing.T) {
	t.Parallel()
	svc, vault, gw := connectFixture(t, "https://unused")
	ctx := context.Background()
	resume := "cursor://anysphere.cursor-mcp/oauth/callback?code=gw-code&state=s"

	loc, err := svc.ChainURL(ctx, "https://gw.example.com", gw, "https://gw.example.com/dev/mcp", "alice", resume)
	if err != nil {
		t.Fatalf("ChainURL: %v", err)
	}
	if !strings.HasPrefix(loc, "https://gw.example.com/dev/mcp/connect?ticket=") {
		t.Fatalf("expected connect page URL, got %q", loc)
	}
	ticket := strings.TrimPrefix(loc, "https://gw.example.com/dev/mcp/connect?ticket=")
	page, err := svc.Page(ctx, ticket)
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if page.ResumeURL != resume {
		t.Fatalf("page resume = %q, want parked client redirect", page.ResumeURL)
	}

	cred, err := vaultdomain.NewCredential(gw, "alice", "github", "", "tok", "ref", nil, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if err := vault.Upsert(ctx, cred); err != nil {
		t.Fatalf("vault: %v", err)
	}
	if loc, err := svc.ChainURL(ctx, "https://gw.example.com", gw, "https://gw.example.com/dev/mcp", "alice", resume); err != nil || loc != "" {
		t.Fatalf("linked principal: loc=%q err=%v, want no detour", loc, err)
	}

	for _, resource := range []string{"https://gw.example.com/v1/mcp/other", ""} {
		loc, err := svc.ChainURL(ctx, "https://gw.example.com", gw, resource, "bob", resume)
		if err != nil {
			t.Fatalf("resource %q: %v", resource, err)
		}
		if !strings.HasPrefix(loc, "https://gw.example.com/dev/mcp/connect?ticket=") {
			t.Fatalf("resource %q: expected fallback detour to /dev/mcp, got %q", resource, loc)
		}
	}

	if loc, err := svc.ChainURL(ctx, "https://gw.example.com", gw, "", "alice", resume); err != nil || loc != "" {
		t.Fatalf("linked principal scan: loc=%q err=%v, want no detour", loc, err)
	}
}

func TestConnectService_ProviderDenialRelaysTicket(t *testing.T) {
	t.Parallel()
	svc, vault, gw := connectFixture(t, "https://unused")
	ctx := context.Background()
	ticket, _ := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
	location, _ := svc.Start(ctx, "https://gw", ticket, "github")
	u, _ := url.Parse(location)
	state := u.Query().Get("state")

	backTicket, err := svc.Callback(ctx, "https://gw", "github", state, "", "access_denied", "user said no")
	if err == nil {
		t.Fatal("denied consent returned nil error")
	}
	if backTicket != ticket {
		t.Fatalf("ticket = %q, want %q for page redirect", backTicket, ticket)
	}
	if len(vault.creds) != 0 {
		t.Fatal("denied consent stored a credential")
	}
}

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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/app/mcpoauth"
	"github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
	"github.com/golang-jwt/jwt/v5"
)

type memConnectStore struct {
	tickets       map[string]oauth.ConnectTicket
	connects      map[string]oauth.ConnectState
	clients       map[string]oauth.RegisteredClient
	saveTicketErr error
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

func (m *memConnectStore) SaveClientIfAbsent(_ context.Context, key string, c oauth.RegisteredClient) (*oauth.RegisteredClient, error) {
	if existing, ok := m.clients[key]; ok {
		return &existing, nil
	}
	m.clients[key] = c
	return &c, nil
}

// SaveTicket keeps the ticket as the real store does — as JSON — so a field
// whose zero value does not survive the round trip fails here and not only in
// Redis. `providers` was exactly that: an empty snapshot came back as nil,
// which reads as an unpinned ticket and is rejected.
func (m *memConnectStore) SaveTicket(_ context.Context, id string, t oauth.ConnectTicket) error {
	if m.saveTicketErr != nil {
		return m.saveTicketErr
	}
	raw, err := json.Marshal(t)
	if err != nil {
		return err
	}
	var stored oauth.ConnectTicket
	if err := json.Unmarshal(raw, &stored); err != nil {
		return err
	}
	m.tickets[id] = stored
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
	creds         map[string]*vaultdomain.Credential
	findProviders []string
	upsertErr     error
	deleteErr     error
}

func (m *memVaultRepo) k(gw ids.GatewayID, sub, p string) string { return gw.String() + sub + p }

func (m *memVaultRepo) Upsert(_ context.Context, c *vaultdomain.Credential) error {
	if m.upsertErr != nil {
		return m.upsertErr
	}
	if m.creds == nil {
		m.creds = map[string]*vaultdomain.Credential{}
	}
	m.creds[m.k(c.GatewayID, c.PrincipalSub, c.Provider)] = c
	return nil
}

func (m *memVaultRepo) Find(_ context.Context, gw ids.GatewayID, sub, p string) (*vaultdomain.Credential, error) {
	m.findProviders = append(m.findProviders, p)
	c, ok := m.creds[m.k(gw, sub, p)]
	if !ok {
		return nil, vaultdomain.ErrNotFound
	}
	return c, nil
}

func (m *memVaultRepo) ListByPrincipal(
	_ context.Context,
	gw ids.GatewayID,
	sub string,
) ([]*vaultdomain.Credential, error) {
	out := make([]*vaultdomain.Credential, 0, len(m.creds))
	for _, c := range m.creds {
		if c.GatewayID == gw && c.PrincipalSub == sub {
			out = append(out, c)
		}
	}
	// Stable order: callers sweep this list and delete as they go.
	sort.Slice(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	return out, nil
}

func (m *memVaultRepo) Delete(_ context.Context, gw ids.GatewayID, sub, p string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
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

func discardConnectAuditor() oauth.ConnectAuditor {
	return oauth.NewConnectAuditor(slog.New(slog.NewJSONHandler(io.Discard, nil)))
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
	svc := oauth.NewConnectService(
		store,
		vault,
		&stubDataFinder{data: data},
		infraoauth.NewProviderClient(nil),
		infraoauth.NewUpstreamRegistrar(store, nil),
		discardConnectAuditor(),
		nil,
		nil,
		nil,
		nil,
	)
	return svc, vault, gw
}

func TestConnectService_SharedGoogleWorkspaceClient(t *testing.T) {
	t.Parallel()
	var gotForm url.Values
	tokenURL := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.Form
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "google-access", "expires_in": 3600})
	}))
	defer tokenURL.Close()

	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "gmail-mcp", "", &registrydomain.MCPTarget{
		Code: "com.google.workspace/gmail",
		URL:  "https://gmailmcp.googleapis.com/mcp/v1",
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     "com.google.workspace/gmail",
			Registration: registrydomain.RegistrationManual,
			ClientID:     "stale-client",
			ClientSecret: "stale-secret",
			AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:     tokenURL.URL,
			Scopes:       []string{"https://www.googleapis.com/auth/gmail.readonly"},
		},
	})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	reg.MCPTarget.Auth.ClientID = ""
	reg.MCPTarget.Auth.ClientSecret = ""
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
		mcpoauth.NewGoogleWorkspace("nt-client", "nt-secret"),
		nil,
		nil,
		nil,
	)
	ctx := context.Background()
	ticket, err := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	location, err := svc.Start(ctx, "https://gw.example.com", ticket, "com.google.workspace/gmail", "")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse authorize url: %v", err)
	}
	if u.Query().Get("client_id") != "nt-client" {
		t.Fatalf("client_id = %q, want platform client", u.Query().Get("client_id"))
	}
	if _, err := svc.Callback(ctx, "https://gw.example.com", "com.google.workspace/gmail", u.Query().Get("state"), "the-code", "", ""); err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if gotForm.Get("client_id") != "nt-client" || gotForm.Get("client_secret") != "nt-secret" {
		t.Fatalf("token form = %v", gotForm)
	}

	refreshCfg, err := svc.RefreshAuth(ctx, gw, reg)
	if err != nil {
		t.Fatalf("RefreshAuth: %v", err)
	}
	if refreshCfg.ClientID != "nt-client" || refreshCfg.ClientSecret != "nt-secret" {
		t.Fatalf("refresh cfg = %+v", refreshCfg)
	}
}

func TestConnectService_SharedGoogleWorkspacePreservesBYO(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "gmail-mcp", "", &registrydomain.MCPTarget{
		Code: "com.google.workspace/gmail",
		URL:  "https://gmailmcp.googleapis.com/mcp/v1",
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     "com.google.workspace/gmail",
			Registration: registrydomain.RegistrationManual,
			ClientID:     "customer-client",
			ClientSecret: "customer-secret",
			AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:     "https://oauth2.googleapis.com/token",
			Scopes:       []string{"https://www.googleapis.com/auth/gmail.readonly"},
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
	svc := oauth.NewConnectService(
		newMemConnectStore(),
		&memVaultRepo{},
		&stubDataFinder{data: data},
		infraoauth.NewProviderClient(nil),
		infraoauth.NewUpstreamRegistrar(newMemConnectStore(), nil),
		discardConnectAuditor(),
		mcpoauth.NewGoogleWorkspace("nt-client", "nt-secret"),
		nil,
		nil,
		nil,
	)
	refreshCfg, err := svc.RefreshAuth(context.Background(), gw, reg)
	if err != nil {
		t.Fatalf("RefreshAuth: %v", err)
	}
	if refreshCfg.ClientID != "customer-client" || refreshCfg.ClientSecret != "customer-secret" {
		t.Fatalf("BYO credentials overwritten: %+v", refreshCfg)
	}
}

func TestConnectService_OverlaysCatalogGmailModifyScope(t *testing.T) {
	t.Parallel()
	catalog, err := appcatalog.NewMCPServerCatalog(nil)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}

	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "gmail-mcp", "", &registrydomain.MCPTarget{
		Code: "com.google.workspace/gmail",
		URL:  "https://gmailmcp.googleapis.com/mcp/v1",
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     "com.google.workspace/gmail",
			Registration: registrydomain.RegistrationManual,
			ClientID:     "nt-client",
			ClientSecret: "nt-secret",
			AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:     "https://oauth2.googleapis.com/token",
			Scopes:       []string{"https://www.googleapis.com/auth/gmail.readonly"},
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
		catalog,
		nil,
	)
	ctx := context.Background()
	ticket, err := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	location, err := svc.Start(ctx, "https://gw.example.com", ticket, "com.google.workspace/gmail", "")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse authorize url: %v", err)
	}
	scope := u.Query().Get("scope")
	if !strings.Contains(scope, "https://www.googleapis.com/auth/gmail.modify") {
		t.Fatalf("authorize scope = %q, want catalog gmail.modify", scope)
	}

	refreshCfg, err := svc.RefreshAuth(ctx, gw, reg)
	if err != nil {
		t.Fatalf("RefreshAuth: %v", err)
	}
	found := false
	for _, s := range refreshCfg.Scopes {
		if s == "https://www.googleapis.com/auth/gmail.modify" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("refresh scopes = %v, want catalog gmail.modify", refreshCfg.Scopes)
	}
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
			"id_token": unsignedConnectJWT(t, jwt.MapClaims{"email": "octocat@github.com", "sub": "1"}),
		})
	}))
	defer provider.Close()

	svc, vault, gw := connectFixture(t, provider.URL)
	ctx := context.Background()

	ticket, err := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}

	statuses, err := svc.Statuses(ctx, gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("Statuses: %v", err)
	}
	if len(statuses) != 1 || statuses[0].Provider != "github" || statuses[0].Linked {
		t.Fatalf("statuses = %+v, want one unlinked github provider", statuses)
	}

	page, err := svc.Page(ctx, ticket)
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if len(page.Providers) != 1 || page.Providers[0].Provider != "github" || page.Providers[0].Linked {
		t.Fatalf("page = %+v, want one unlinked github provider", page)
	}

	location, err := svc.Start(ctx, "https://gw.example.com", ticket, "github", "")
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

	cred, err := vault.Find(ctx, gw, "alice", vaultKey(t, "github", "https://up.example.com/mcp"))
	if err != nil {
		t.Fatalf("vault.Find: %v", err)
	}
	if cred.AccessToken != "gh-access" || cred.RefreshToken != "gh-refresh" {
		t.Fatalf("vaulted credential = %+v", cred)
	}
	if cred.AccountRef != "octocat@github.com" {
		t.Fatalf("AccountRef = %q, want the id_token email", cred.AccountRef)
	}

	page, _ = svc.Page(ctx, ticket)
	if !page.Providers[0].Linked {
		t.Fatal("provider not reported linked after callback")
	}
	if page.Providers[0].AccountRef != "octocat@github.com" {
		t.Fatalf("page AccountRef = %q", page.Providers[0].AccountRef)
	}

	if err := svc.Disconnect(ctx, ticket, "github", ""); err != nil {
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
	svc := oauth.NewConnectService(
		store,
		vault,
		&stubDataFinder{data: data},
		infraoauth.NewProviderClient(nil),
		registrar,
		discardConnectAuditor(),
		nil,
		nil,
		nil,
		nil,
	)
	ctx := context.Background()

	ticket, err := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	location, err := svc.Start(ctx, "https://gw.example.com", ticket, "linear", "")
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
	cred, err := vault.Find(ctx, gw, "alice", registrydomain.ForwardedVaultProvider(reg))
	if err != nil || cred.AccessToken != "linear-access" {
		t.Fatalf("vaulted credential = %+v, err = %v", cred, err)
	}
	if registrations != 1 {
		t.Fatalf("registrations = %d, want exactly 1 (Callback must reuse the cached client)", registrations)
	}

	if _, err := svc.Start(ctx, "https://gw.example.com", ticket, "linear", ""); err != nil {
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

func TestConnectService_ManualClientDiscoversEndpoints(t *testing.T) {
	t.Parallel()
	registrations := 0
	var tokenForm url.Values
	upstream := fakeSpecUpstream(t, &registrations, &tokenForm)

	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "snowflake-mcp", "", &registrydomain.MCPTarget{
		URL: upstream.URL + "/mcp",
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     "com.snowflake/mcp",
			Registration: registrydomain.RegistrationManual,
			ClientID:     "manual-client",
			ClientSecret: "manual-secret",
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
		nil,
		nil,
	)

	ticket, err := svc.CreateTicket(context.Background(), gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	location, err := svc.Start(context.Background(), "https://gw.example.com", ticket, "com.snowflake/mcp", "")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	u, _ := url.Parse(location)
	if !strings.HasPrefix(location, upstream.URL+"/authorize?") {
		t.Fatalf("redirect = %q, want discovered authorize endpoint", location)
	}
	if got := u.Query().Get("client_id"); got != "manual-client" {
		t.Fatalf("client_id = %q, want manual client", got)
	}
	if registrations != 0 {
		t.Fatalf("registrations = %d, manual client must not call DCR", registrations)
	}

	refreshCfg, err := svc.RefreshAuth(context.Background(), gw, reg)
	if err != nil {
		t.Fatalf("RefreshAuth: %v", err)
	}
	if refreshCfg.AuthorizeURL != upstream.URL+"/authorize" || refreshCfg.TokenURL != upstream.URL+"/token" {
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
	svc := oauth.NewConnectService(
		store,
		&memVaultRepo{},
		&stubDataFinder{data: data},
		infraoauth.NewProviderClient(nil),
		infraoauth.NewUpstreamRegistrar(store, nil),
		discardConnectAuditor(),
		nil,
		nil,
		nil,
		nil,
	)
	ctx := context.Background()
	ticket, _ := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
	if _, err := svc.Start(ctx, "https://gw", ticket, "legacy", ""); !errors.Is(err, oauth.ErrUpstreamNotDiscoverable) {
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
	location, _ := svc.Start(ctx, "https://gw", ticket, "github", "")
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
	if _, err := svc.Start(ctx, "https://gw", ticket, "slack", ""); !errors.Is(err, oauth.ErrProviderNotFound) {
		t.Fatalf("error = %v, want oauth.ErrProviderNotFound", err)
	}
}

func TestConnectService_PageReportsDeadGrantAsNeedingReconnect(t *testing.T) {
	t.Parallel()
	svc, vault, gw := connectFixture(t, "https://unused")
	ctx := context.Background()
	ticket, err := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}

	dead, err := vaultdomain.NewCredential(gw, "alice", vaultKey(t, "github", "https://up.example.com/mcp"),
		"", "tok", "", nil, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if err := vault.Upsert(ctx, dead); err != nil {
		t.Fatalf("vault: %v", err)
	}
	page, err := svc.Page(ctx, ticket)
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if !page.Providers[0].NeedsReconnect {
		t.Fatalf("status = %+v, want NeedsReconnect for an expired grant with no refresh token", page.Providers[0])
	}

	renewable, err := vaultdomain.NewCredential(gw, "alice", vaultKey(t, "github", "https://up.example.com/mcp"),
		"", "tok", "ref", nil, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if err := vault.Upsert(ctx, renewable); err != nil {
		t.Fatalf("vault: %v", err)
	}
	page, err = svc.Page(ctx, ticket)
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if !page.Providers[0].Linked || page.Providers[0].NeedsReconnect {
		t.Fatalf("status = %+v, want a refreshable grant to stay linked", page.Providers[0])
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

	cred, err := vaultdomain.NewCredential(gw, "alice", vaultKey(t, "github", "https://up.example.com/mcp"),
		"", "tok", "ref", nil, time.Now().Add(time.Hour))
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
	location, _ := svc.Start(ctx, "https://gw", ticket, "github", "")
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

// stubRegistryLister returns a fixed set of registries for List, standing in for
// registrydomain.Repository so the Store-scoped connect flow can find the
// installed registry a ticket's catalog code points at.
type stubRegistryLister struct {
	items []*registrydomain.Registry
}

func (s *stubRegistryLister) List(
	context.Context,
	registrydomain.ListFilter,
) ([]*registrydomain.Registry, int, error) {
	return s.items, len(s.items), nil
}

// A Store-scoped connect ticket carries only the catalog code; the synthetic
// Store consumer is never persisted and holds no registries. The connect flow
// must rebuild that consumer and attach the materialised registry for the code,
// so forwarded-auth (OAuth) resolves instead of failing with
// "consumer path /store/mcp no longer exists".
func TestConnectService_StoreScopedTicketResolvesMaterialisedRegistry(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "notion-mcp", "", &registrydomain.MCPTarget{
		Code: "com.notion/mcp",
		URL:  "https://mcp.notion.com/mcp",
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     "com.notion/mcp",
			Registration: registrydomain.RegistrationManual,
			ClientID:     "cid",
			ClientSecret: "csecret",
			AuthorizeURL: "https://mcp.notion.com/authorize",
			TokenURL:     "https://mcp.notion.com/token",
			Scopes:       []string{"read"},
		},
	})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	// The persisted consumer data holds no Store consumer: the Store is synthetic.
	data := appconsumer.NewData(gw, nil)
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
		nil,
		&stubRegistryLister{items: []*registrydomain.Registry{reg}},
	)
	ctx := context.Background()
	storePath := appconsumer.MCPPath(consumerdomain.StoreSlug)
	ticket, err := svc.CreateServerTicket(ctx, gw, "alice", storePath, "com.notion/mcp", "")
	if err != nil {
		t.Fatalf("CreateServerTicket: %v", err)
	}

	// Page resolves the synthetic Store consumer and surfaces the code's provider.
	page, err := svc.Page(ctx, ticket)
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if page.Code != "com.notion/mcp" {
		t.Fatalf("page code = %q, want com.notion/mcp", page.Code)
	}
	if len(page.Providers) != 1 || page.Providers[0].Provider != "com.notion/mcp" {
		t.Fatalf("page providers = %+v, want single com.notion/mcp", page.Providers)
	}

	// Start mints an authorize URL, proving forwarded auth resolves end to end.
	location, err := svc.Start(ctx, "https://gw.example.com", ticket, "com.notion/mcp", "")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !strings.HasPrefix(location, "https://mcp.notion.com/authorize") {
		t.Fatalf("authorize url = %q, want notion authorize", location)
	}
}

func unsignedConnectJWT(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	raw, err := tok.SignedString([]byte("test-secret"))
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return raw
}

// An application whose upstreams all carry their own credential has nothing to
// link, and an admin can still land on its connect page. The ticket's provider
// snapshot is empty, not absent — an absent one means "any provider" and is
// refused for an api-key ticket, which turned a valid key into a 401.
func TestConnectService_APIKeyTicketWithNoForwardedProviders(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "internal-mcp", "", &registrydomain.MCPTarget{
		URL:  "https://up.example.com/mcp",
		Auth: &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeStatic, Header: "Authorization", Value: "Bearer shared"},
	})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	consumerID := ids.New[ids.ConsumerKind]()
	authID := ids.New[ids.AuthKind]()
	data := appconsumer.NewData(gw, []appconsumer.RoutableConsumer{{
		Consumer: &consumerdomain.Consumer{
			ID: consumerID, GatewayID: gw,
			Type: consumerdomain.TypeMCP, Slug: "dev", Active: true,
			AuthIDs: []ids.AuthID{authID},
		},
		Auths: []*authdomain.Auth{{
			ID: authID, GatewayID: gw, Name: "prod", Type: authdomain.TypeAPIKey, Enabled: true,
		}},
		Registries: []*registrydomain.Registry{reg},
	}})
	store := newMemConnectStore()
	svc := oauth.NewConnectService(
		store, &memVaultRepo{}, &stubDataFinder{data: data},
		infraoauth.NewProviderClient(nil), infraoauth.NewUpstreamRegistrar(store, nil),
		discardConnectAuditor(), nil, nil, nil, nil,
	)
	ctx := context.Background()

	ticketID, err := svc.CreateAppTicket(ctx, gw, "prod", "/dev/mcp", consumerID, authID, nil, "")
	if err != nil {
		t.Fatalf("CreateAppTicket: %v", err)
	}

	page, err := svc.Page(ctx, ticketID)
	if err != nil {
		t.Fatalf("Page: %v (a consumer with no forwarded registry must still reach its connect page)", err)
	}
	if len(page.Providers) != 0 {
		t.Fatalf("providers = %+v, want none to connect", page.Providers)
	}

	// Still pinned to nothing: the ticket cannot be used to connect a provider
	// that gets added to the consumer later.
	if _, err := svc.Start(ctx, "https://gw", ticketID, "github", ""); !errors.Is(err, oauth.ErrProviderNotFound) {
		t.Fatalf("Start error = %v, want oauth.ErrProviderNotFound", err)
	}
}

// TestConnectService_PageReportsAReconnectWhenTheRegisteredClientIsGone: the
// vault is not the whole answer. A dynamically registered client lives in the
// shared cache and the credential in the vault, so the credential outlives it
// whenever that cache is lost — and the refresh token, issued to that client,
// cannot be redeemed without it. Reading the vault alone made the connect page
// and the Portal call such an account connected while every tool call on it was
// refused with "user consent required".
func TestConnectService_PageReportsAReconnectWhenTheRegisteredClientIsGone(t *testing.T) {
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
	vault := &memVaultRepo{}
	// A live credential: a fresh access token and a refresh token. Nothing about
	// it says "reconnect".
	cred, err := vaultdomain.NewCredential(gw, "alice", registrydomain.ForwardedVaultProvider(reg), "alice@corp",
		"at", "rt", []string{"read"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if err := vault.Upsert(context.Background(), cred); err != nil {
		t.Fatalf("seed vault: %v", err)
	}
	svc := oauth.NewConnectService(
		store,
		vault,
		&stubDataFinder{data: data},
		infraoauth.NewProviderClient(nil),
		infraoauth.NewUpstreamRegistrar(store, nil),
		discardConnectAuditor(),
		nil,
		nil,
		nil,
		nil,
	)
	ctx := context.Background()

	// No client registered yet (the cache was lost): the account needs one.
	statuses, err := svc.Statuses(ctx, gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("Statuses: %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("statuses = %d, want the one forwarded provider", len(statuses))
	}
	if !statuses[0].Linked {
		t.Fatal("the credential is stored, so the account is linked")
	}
	if !statuses[0].NeedsReconnect {
		t.Fatal("without the client its refresh token was issued to, the account needs a reconnect")
	}

	// Registering the client again (what connecting does) settles it.
	ticket, err := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	if _, err := svc.Start(ctx, "https://gw.example.com", ticket, "linear", ""); err != nil {
		t.Fatalf("Start: %v", err)
	}
	statuses, err = svc.Statuses(ctx, gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("Statuses: %v", err)
	}
	if statuses[0].NeedsReconnect {
		t.Fatal("with the client registered the stored credential is usable again")
	}
}

// A registry whose OAuth client is configured has nothing that can go missing
// in the cache, so the check must not invent a reconnect for it.
func TestConnectService_ConfiguredClientNeedsNoRegistrationCheck(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "notion-mcp", "", &registrydomain.MCPTarget{
		URL: "https://mcp.notion.com/mcp",
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     "notion",
			Registration: registrydomain.RegistrationManual,
			ClientID:     "configured-client",
			AuthorizeURL: "https://idp.example.com/a",
			TokenURL:     "https://idp.example.com/t",
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
	vault := &memVaultRepo{}
	cred, err := vaultdomain.NewCredential(gw, "alice", registrydomain.ForwardedVaultProvider(reg), "alice@corp",
		"at", "rt", []string{"read"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if err := vault.Upsert(context.Background(), cred); err != nil {
		t.Fatalf("seed vault: %v", err)
	}
	svc := oauth.NewConnectService(
		store,
		vault,
		&stubDataFinder{data: data},
		infraoauth.NewProviderClient(nil),
		infraoauth.NewUpstreamRegistrar(store, nil),
		discardConnectAuditor(),
		nil,
		nil,
		nil,
		nil,
	)

	statuses, err := svc.Statuses(context.Background(), gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("Statuses: %v", err)
	}
	if len(statuses) != 1 || !statuses[0].Linked || statuses[0].NeedsReconnect {
		t.Fatalf("a configured client stays connected, got %+v", statuses)
	}
}

// Two instances of one catalog code, each on its own upstream: the credential
// belongs to the instance that was connected, and connecting one says nothing
// about the other. Before the vault was keyed by the instance's resource, both
// rows shared the provider's single credential, so connecting Develop reported
// Prod as connected too and Prod's calls forwarded Develop's token.
func TestConnectService_TwoInstancesOfOneProviderConnectSeparately(t *testing.T) {
	t.Parallel()
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "prod-access", "refresh_token": "prod-refresh", "expires_in": 3600,
		})
	}))
	defer tokenServer.Close()

	gw := ids.New[ids.GatewayKind]()
	instance := func(name, upstream string) *registrydomain.Registry {
		reg, err := registrydomain.NewMCPRegistry(gw, name, "", &registrydomain.MCPTarget{
			URL:  upstream,
			Code: "app.linear/mcp",
			Auth: &registrydomain.MCPAuth{
				Mode: registrydomain.MCPAuthModeForwarded, Provider: "app.linear/mcp",
				ClientID: "cid", ClientSecret: "csecret",
				AuthorizeURL: "https://linear.app/oauth/authorize",
				TokenURL:     tokenServer.URL,
			},
		})
		if err != nil {
			t.Fatalf("registry: %v", err)
		}
		return reg
	}
	develop := instance("Linear Develop", "https://develop.linear.app/mcp")
	prod := instance("Linear Prod", "https://prod.linear.app/mcp")
	data := appconsumer.NewData(gw, []appconsumer.RoutableConsumer{{
		Consumer: &consumerdomain.Consumer{
			ID: ids.New[ids.ConsumerKind](), GatewayID: gw,
			Type: consumerdomain.TypeMCP, Slug: "dev", Active: true,
		},
		Registries: []*registrydomain.Registry{develop, prod},
	}})
	store := newMemConnectStore()
	vault := &memVaultRepo{}
	svc := oauth.NewConnectService(
		store,
		vault,
		&stubDataFinder{data: data},
		infraoauth.NewProviderClient(nil),
		infraoauth.NewUpstreamRegistrar(store, nil),
		discardConnectAuditor(),
		nil,
		nil,
		nil,
		nil,
	)
	ctx := context.Background()
	ticket, err := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}

	// The page offers a row per instance, each naming the one it acts on.
	page, err := svc.Page(ctx, ticket)
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if len(page.Providers) != 2 {
		t.Fatalf("providers = %+v, want a row per instance", page.Providers)
	}
	if page.Providers[0].Instance == page.Providers[1].Instance {
		t.Fatalf("both rows name the same instance: %+v", page.Providers)
	}

	// Connect the second instance, naming it: the flow must not fall back to
	// whichever registry happens to serve the provider first.
	location, err := svc.Start(ctx, "https://gw.example.com", ticket, "app.linear/mcp", prod.ID.String())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse authorize url: %v", err)
	}
	if _, err := svc.Callback(
		ctx, "https://gw.example.com", "app.linear/mcp", parsed.Query().Get("state"), "the-code", "", "",
	); err != nil {
		t.Fatalf("Callback: %v", err)
	}

	if _, err := vault.Find(ctx, gw, "alice", registrydomain.ForwardedVaultProvider(prod)); err != nil {
		t.Fatalf("the connected instance holds the credential: %v", err)
	}
	if _, err := vault.Find(ctx, gw, "alice", registrydomain.ForwardedVaultProvider(develop)); err == nil {
		t.Fatal("connecting one instance must not connect the other")
	}

	page, err = svc.Page(ctx, ticket)
	if err != nil {
		t.Fatalf("Page after connect: %v", err)
	}
	byInstance := map[string]bool{}
	for _, status := range page.Providers {
		byInstance[status.Instance] = status.Linked
	}
	if !byInstance[prod.ID.String()] {
		t.Fatalf("the connected instance reads as linked: %+v", page.Providers)
	}
	if byInstance[develop.ID.String()] {
		t.Fatalf("the other instance still reads as linked: %+v", page.Providers)
	}

	// Revoking is per instance too.
	if err := svc.Disconnect(ctx, ticket, "app.linear/mcp", prod.ID.String()); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if _, err := vault.Find(ctx, gw, "alice", registrydomain.ForwardedVaultProvider(prod)); err == nil {
		t.Fatal("the revoked credential is gone")
	}
}

// A dynamically registered client is cached under the same key as the
// credential it mints, so a refresh always redeems a token with the client it
// was issued to. Keyed by registry instead, two instances of one provider
// registered two clients over one shared credential and the refresh presented
// the wrong client_id — the upstream answered invalid_grant, which the user saw
// as an expired session on a page that still said connected.
func TestConnectService_RegisteredClientFollowsTheCredentialNotTheRegistry(t *testing.T) {
	t.Parallel()
	registrations := 0
	var tokenForm url.Values
	upstream := fakeSpecUpstream(t, &registrations, &tokenForm)
	otherRegistrations := 0
	var otherTokenForm url.Values
	otherUpstream := fakeSpecUpstream(t, &otherRegistrations, &otherTokenForm)

	gw := ids.New[ids.GatewayKind]()
	instance := func(name, upstreamURL string) *registrydomain.Registry {
		reg, err := registrydomain.NewMCPRegistry(gw, name, "", &registrydomain.MCPTarget{
			URL: upstreamURL,
			Auth: &registrydomain.MCPAuth{
				Mode:         registrydomain.MCPAuthModeForwarded,
				Provider:     "linear",
				Registration: registrydomain.RegistrationAuto,
			},
		})
		if err != nil {
			t.Fatalf("registry: %v", err)
		}
		return reg
	}
	// Same deployment as `connected`, a second registry over it: one credential,
	// so it must share the client too.
	connected := instance("linear-mcp", upstream.URL+"/mcp")
	sameDeployment := instance("linear-mcp-readonly", upstream.URL+"/mcp")
	elsewhere := instance("linear-mcp-other", otherUpstream.URL+"/mcp")
	data := appconsumer.NewData(gw, []appconsumer.RoutableConsumer{{
		Consumer: &consumerdomain.Consumer{
			ID: ids.New[ids.ConsumerKind](), GatewayID: gw,
			Type: consumerdomain.TypeMCP, Slug: "dev", Active: true,
		},
		Registries: []*registrydomain.Registry{connected, sameDeployment, elsewhere},
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
		nil,
		nil,
	)
	ctx := context.Background()
	ticket, err := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	if _, err := svc.Start(ctx, "https://gw.example.com", ticket, "linear", connected.ID.String()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	refreshCfg, err := svc.RefreshAuth(ctx, gw, connected)
	if err != nil {
		t.Fatalf("RefreshAuth for the connected instance: %v", err)
	}
	if refreshCfg.ClientID != "dcr-client-1" {
		t.Fatalf("client id = %q, want the one the authorization was started with", refreshCfg.ClientID)
	}

	// The second registry over the same deployment shares the credential, so it
	// shares the client — no second registration.
	shared, err := svc.RefreshAuth(ctx, gw, sameDeployment)
	if err != nil {
		t.Fatalf("RefreshAuth for a registry on the same deployment: %v", err)
	}
	if shared.ClientID != refreshCfg.ClientID {
		t.Fatalf("client id = %q, want the shared %q", shared.ClientID, refreshCfg.ClientID)
	}
	if registrations != 1 {
		t.Fatalf("registrations = %d, want exactly 1 for one deployment", registrations)
	}

	// A different deployment holds a different credential, so its client is its
	// own and is not there until it is connected in turn.
	if _, err := svc.RefreshAuth(ctx, gw, elsewhere); !errors.Is(err, oauth.ErrNoRegisteredClient) {
		t.Fatalf("error = %v, want oauth.ErrNoRegisteredClient for an unconnected deployment", err)
	}
	if otherRegistrations != 0 {
		t.Fatalf("registrations against the other deployment = %d, want none", otherRegistrations)
	}
}

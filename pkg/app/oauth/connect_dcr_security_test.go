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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
)

type principalURLValues map[string]map[string]string

func (v principalURLValues) Values(_ context.Context, _ ids.GatewayID, principalSub string, _ *registrydomain.Registry) (map[string]string, error) {
	return v[principalSub], nil
}

// hostRewrite sends discovery requests for a public hostname to that host's
// httptest server. Resolved upstreams must be public names, so the test cannot
// point the template at a loopback address directly.
type hostRewrite struct {
	targets map[string]*httptest.Server
}

func (h hostRewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	srv := h.targets[req.URL.Hostname()]
	if srv == nil {
		return http.DefaultTransport.RoundTrip(req)
	}
	dest, err := url.Parse(srv.URL)
	if err != nil {
		return nil, err
	}
	cloned := req.Clone(req.Context())
	cloned.URL.Scheme = dest.Scheme
	cloned.URL.Host = dest.Host
	return http.DefaultTransport.RoundTrip(cloned)
}

type hostServer struct {
	server        *httptest.Server
	registrations atomic.Int64
	tokenClient   string
	mu            sync.Mutex
}

func (h *hostServer) lastTokenClient() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.tokenClient
}

func newHostServer(t *testing.T, host, tokenError string) *hostServer {
	t.Helper()
	h := &hostServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              "https://" + host + "/mcp",
			"authorization_servers": []string{"https://" + host},
			"scopes_supported":      []string{"read"},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 "https://" + host,
			"authorization_endpoint": "https://" + host + "/authorize",
			"token_endpoint":         h.server.URL + "/token",
			"registration_endpoint":  h.server.URL + "/register",
		})
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, _ *http.Request) {
		n := h.registrations.Add(1)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":                host + "-client-" + strconv.FormatInt(n, 10),
			"client_secret_expires_at": time.Now().Add(time.Hour).Unix(),
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		h.mu.Lock()
		h.tokenClient = r.Form.Get("client_id")
		h.mu.Unlock()
		if tokenError != "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": tokenError, "error_description": "unrecognized client_id",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "expires_in": 3600})
	})
	h.server = httptest.NewServer(mux)
	t.Cleanup(h.server.Close)
	return h
}

func templatedRegistry(t *testing.T, gw ids.GatewayID) *registrydomain.Registry {
	t.Helper()
	reg, err := registrydomain.NewMCPRegistry(gw, "hosted-mcp", "", &registrydomain.MCPTarget{
		URL:          "https://{host}/mcp",
		URLVariables: []registrydomain.MCPURLVariable{{Name: "host", Required: true}},
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

func connectWithHosts(t *testing.T, gw ids.GatewayID, reg *registrydomain.Registry, store *memConnectStore, hosts map[string]*httptest.Server, values principalURLValues) oauth.ConnectService {
	t.Helper()
	data := appconsumer.NewData(gw, []appconsumer.RoutableConsumer{{
		Consumer: &consumerdomain.Consumer{
			ID: ids.New[ids.ConsumerKind](), GatewayID: gw,
			Type: consumerdomain.TypeMCP, Slug: "dev", Active: true,
		},
		Registries: []*registrydomain.Registry{reg},
	}})
	return oauth.NewConnectService(
		store, &memVaultRepo{}, &stubDataFinder{data: data},
		infraoauth.NewProviderClient(nil),
		infraoauth.NewUpstreamRegistrar(store, &http.Client{Transport: hostRewrite{targets: hosts}}),
		discardConnectAuditor(), nil, nil, nil, nil,
		oauth.WithConnectURLValues(values),
	)
}

func TestConnectService_CallbackErrorDoesNotDropCachedClient(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		errCode string
		errDesc string
	}{
		{name: "invalid_client", errCode: "invalid_client", errDesc: "Unrecognized client_id"},
		{name: "unauthorized_client", errCode: "unauthorized_client"},
		{
			name:    "invalid_request redirect_uri",
			errCode: "invalid_request",
			errDesc: "The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered redirect urls.",
		},
		{name: "access_denied", errCode: "access_denied", errDesc: "user said no"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var registrations atomic.Int64
			var srvURL string
			mux := http.NewServeMux()
			mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"resource":              srvURL + "/mcp",
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
				n := registrations.Add(1)
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"client_id":                "client-" + strconv.FormatInt(n, 10),
					"client_secret_expires_at": time.Now().Add(time.Hour).Unix(),
				})
			})
			srv := httptest.NewServer(mux)
			srvURL = srv.URL
			t.Cleanup(srv.Close)

			gw := ids.New[ids.GatewayKind]()
			reg, err := registrydomain.NewMCPRegistry(gw, "linear-mcp", "", &registrydomain.MCPTarget{
				URL: srv.URL + "/mcp",
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
			svc := oauth.NewConnectService(
				store, &memVaultRepo{}, &stubDataFinder{data: data},
				infraoauth.NewProviderClient(nil), infraoauth.NewUpstreamRegistrar(store, nil),
				discardConnectAuditor(), nil, nil, nil, nil,
			)
			ctx := context.Background()
			ticket, err := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
			if err != nil {
				t.Fatalf("CreateTicket: %v", err)
			}
			location, err := startLocation(svc.Start(ctx, "https://gw.example.com", "https://gw.example.com", ticket, "linear", ""))
			if err != nil {
				t.Fatalf("Start: %v", err)
			}
			state := mustQuery(t, location).Get("state")
			back, err := svc.Callback(ctx, "https://gw.example.com", "linear", state, "", tc.errCode, tc.errDesc)
			if back != ticket {
				t.Fatalf("ticket = %q, want %q", back, ticket)
			}
			var oe *oauth.OAuthError
			if !errors.As(err, &oe) || oe.Code != tc.errCode {
				t.Fatalf("error = %v, want oauth error %s", err, tc.errCode)
			}
			usable, err := svc.CredentialUsable(ctx, gw, reg)
			if err != nil {
				t.Fatalf("CredentialUsable: %v", err)
			}
			if !usable {
				t.Fatal("callback error dropped the cached client")
			}
			stored := soleClient(t, store)
			if stored.ClientSecretExpiresAt > 0 && stored.ClientSecretExpiresAt <= time.Now().Unix() {
				t.Fatalf("cached client expired: %+v", stored)
			}
			again, err := startLocation(svc.Start(ctx, "https://gw.example.com", "https://gw.example.com", ticket, "linear", ""))
			if err != nil {
				t.Fatalf("second Start: %v", err)
			}
			if got := mustQuery(t, again).Get("client_id"); got != stored.ClientID || registrations.Load() != 1 {
				t.Fatalf("client_id = %q, registrations = %d, want the cached client", got, registrations.Load())
			}
		})
	}
}

func TestConnectService_CallbackExchangesTheClientItStartedWith(t *testing.T) {
	t.Parallel()
	var registrations atomic.Int64
	var tokenClient atomic.Value
	var srvURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              srvURL + "/mcp",
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
		n := registrations.Add(1)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":                "client-" + strconv.FormatInt(n, 10),
			"client_secret_expires_at": time.Now().Add(time.Hour).Unix(),
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		tokenClient.Store(form.Get("client_id"))
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "invalid_client", "error_description": "unrecognized client_id",
		})
	})
	srv := httptest.NewServer(mux)
	srvURL = srv.URL
	t.Cleanup(srv.Close)

	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "linear-mcp", "", &registrydomain.MCPTarget{
		URL: srv.URL + "/mcp",
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
	svc := oauth.NewConnectService(
		store, &memVaultRepo{}, &stubDataFinder{data: data},
		infraoauth.NewProviderClient(nil), infraoauth.NewUpstreamRegistrar(store, nil),
		discardConnectAuditor(), nil, nil, nil, nil,
	)
	ctx := context.Background()
	ticket, err := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	location, err := startLocation(svc.Start(ctx, "https://gw.example.com", "https://gw.example.com", ticket, "linear", ""))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	query := mustQuery(t, location)
	pending, err := store.PeekConnect(ctx, query.Get("state"))
	if err != nil || pending == nil || pending.ClientID != "client-1" {
		t.Fatalf("stored client = %+v, err %v, want client-1", pending, err)
	}
	for key, client := range store.clients {
		client.ClientID = "client-2"
		store.clients[key] = client
	}

	_, err = svc.Callback(ctx, "https://gw.example.com", "linear", query.Get("state"), "the-code", "", "")
	if !errors.Is(err, oauth.ErrInvalidClient) {
		t.Fatalf("error = %v, want ErrInvalidClient", err)
	}
	if got := tokenClient.Load(); got != "client-1" {
		t.Fatalf("token client_id = %v, want the client the flow started with", got)
	}
	if registrations.Load() != 1 {
		t.Fatalf("registrations = %d, want no registration on the callback", registrations.Load())
	}
	stored := soleClient(t, store)
	if stored.ClientID != "client-2" || stored.ClientSecretExpiresAt <= time.Now().Unix() {
		t.Fatalf("cached client = %+v, want client-2 left in place", stored)
	}
}

func TestConnectService_TemplatedHostsIsolateDynamicClients(t *testing.T) {
	t.Parallel()
	good := newHostServer(t, "good.example", "")
	evil := newHostServer(t, "evil.example", "invalid_client")
	gw := ids.New[ids.GatewayKind]()
	reg := templatedRegistry(t, gw)
	store := newMemConnectStore()
	values := principalURLValues{
		"alice":   {"host": "good.example"},
		"mallory": {"host": "evil.example"},
	}
	svc := connectWithHosts(t, gw, reg, store, map[string]*httptest.Server{
		"good.example": good.server,
		"evil.example": evil.server,
	}, values)
	ctx := context.Background()
	base := "https://gw.example.com"

	aliceTicket, err := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("alice ticket: %v", err)
	}
	aliceURL, err := startLocation(svc.Start(ctx, base, base, aliceTicket, "linear", ""))
	if err != nil {
		t.Fatalf("alice Start: %v", err)
	}
	aliceClient := mustQuery(t, aliceURL).Get("client_id")
	if aliceClient != "good.example-client-1" || good.registrations.Load() != 1 {
		t.Fatalf("alice client = %q, registrations = %d", aliceClient, good.registrations.Load())
	}

	malloryTicket, err := svc.CreateTicket(ctx, gw, "mallory", "/dev/mcp")
	if err != nil {
		t.Fatalf("mallory ticket: %v", err)
	}
	malloryURL, err := startLocation(svc.Start(ctx, base, base, malloryTicket, "linear", ""))
	if err != nil {
		t.Fatalf("mallory Start: %v", err)
	}
	malloryClient := mustQuery(t, malloryURL).Get("client_id")
	if malloryClient != "evil.example-client-1" || evil.registrations.Load() != 1 {
		t.Fatalf("mallory client = %q, registrations = %d", malloryClient, evil.registrations.Load())
	}
	legacy := gw.String() + "|" + registrydomain.ForwardedVaultProvider(reg)
	if len(store.clients) != 2 {
		t.Fatalf("cached clients = %d, want one per host", len(store.clients))
	}
	for key, client := range store.clients {
		if key == legacy || len(key) <= len(legacy)+1 || key[:len(legacy)+1] != legacy+"|" {
			t.Fatalf("cache key %q, want it scoped under %s", key, legacy)
		}
		if client.ClientID != aliceClient && client.ClientID != malloryClient {
			t.Fatalf("unexpected client %q", client.ClientID)
		}
	}

	_, err = svc.Callback(ctx, base, "linear", mustQuery(t, malloryURL).Get("state"), "the-code", "", "")
	if !errors.Is(err, oauth.ErrInvalidClient) {
		t.Fatalf("mallory callback: %v", err)
	}
	if evil.lastTokenClient() != malloryClient {
		t.Fatalf("token client_id = %q, want %q", evil.lastTokenClient(), malloryClient)
	}
	if good.registrations.Load() != 1 {
		t.Fatalf("good registrations = %d, want the other host's rejection to leave it", good.registrations.Load())
	}
	aliceCtx := identity.WithPrincipal(ctx, &identity.Principal{Subject: "alice"})
	malloryCtx := identity.WithPrincipal(ctx, &identity.Principal{Subject: "mallory"})
	aliceUsable, err := svc.CredentialUsable(aliceCtx, gw, reg)
	if err != nil || !aliceUsable {
		t.Fatalf("alice usable = %v, err %v", aliceUsable, err)
	}
	malloryUsable, err := svc.CredentialUsable(malloryCtx, gw, reg)
	if err != nil || malloryUsable {
		t.Fatalf("mallory usable = %v, err %v, want the rejected client dropped", malloryUsable, err)
	}
	for _, client := range store.clients {
		switch client.ClientID {
		case aliceClient:
			if client.ClientSecretExpiresAt <= time.Now().Unix() {
				t.Fatalf("alice's client was expired: %+v", client)
			}
		case malloryClient:
			if client.ClientSecretExpiresAt <= 0 || client.ClientSecretExpiresAt > time.Now().Unix() {
				t.Fatalf("mallory's client = %+v, want it expired", client)
			}
		}
	}
}

func TestConnectService_LegacyClientKeyStaysReadableForItsIssuer(t *testing.T) {
	t.Parallel()
	good := newHostServer(t, "good.example", "")
	evil := newHostServer(t, "evil.example", "")
	gw := ids.New[ids.GatewayKind]()
	reg := templatedRegistry(t, gw)
	store := newMemConnectStore()
	legacy := gw.String() + "|" + registrydomain.ForwardedVaultProvider(reg)
	redirect := "https://gw.example.com/oauth/callback/linear"
	store.clients[legacy] = oauth.RegisteredClient{
		ClientID:              "legacy-client",
		RedirectURI:           redirect,
		ClientName:            infraoauth.DefaultClientName,
		Issuer:                "https://good.example",
		RegistrationEndpoint:  good.server.URL + "/register",
		ClientSecretExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	svc := connectWithHosts(t, gw, reg, store, map[string]*httptest.Server{
		"good.example": good.server,
		"evil.example": evil.server,
	}, principalURLValues{
		"alice":   {"host": "good.example"},
		"mallory": {"host": "evil.example"},
	})
	ctx := context.Background()
	base := "https://gw.example.com"

	aliceTicket, err := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("alice ticket: %v", err)
	}
	aliceURL, err := startLocation(svc.Start(ctx, base, base, aliceTicket, "linear", ""))
	if err != nil {
		t.Fatalf("alice Start: %v", err)
	}
	if got := mustQuery(t, aliceURL).Get("client_id"); got != "legacy-client" || good.registrations.Load() != 0 {
		t.Fatalf("alice client = %q, registrations = %d, want the legacy client", got, good.registrations.Load())
	}
	if store.clients[legacy].ClientID != "legacy-client" {
		t.Fatal("the legacy row was rewritten")
	}

	malloryTicket, err := svc.CreateTicket(ctx, gw, "mallory", "/dev/mcp")
	if err != nil {
		t.Fatalf("mallory ticket: %v", err)
	}
	malloryURL, err := startLocation(svc.Start(ctx, base, base, malloryTicket, "linear", ""))
	if err != nil {
		t.Fatalf("mallory Start: %v", err)
	}
	if got := mustQuery(t, malloryURL).Get("client_id"); got == "legacy-client" || evil.registrations.Load() != 1 {
		t.Fatalf("mallory client = %q, registrations = %d, want a client of her own", got, evil.registrations.Load())
	}
	if store.clients[legacy].ClientID != "legacy-client" || store.clients[legacy].ClientSecretExpiresAt <= time.Now().Unix() {
		t.Fatalf("legacy row = %+v, want it unchanged", store.clients[legacy])
	}
	if good.registrations.Load() != 0 {
		t.Fatalf("good registrations = %d, want the legacy client kept", good.registrations.Load())
	}
}

func TestConnectService_UnboundLegacyClientIsNotReregistered(t *testing.T) {
	t.Parallel()
	good := newHostServer(t, "good.example", "")
	gw := ids.New[ids.GatewayKind]()
	reg := templatedRegistry(t, gw)
	store := newMemConnectStore()
	legacy := gw.String() + "|" + registrydomain.ForwardedVaultProvider(reg)
	store.clients[legacy] = oauth.RegisteredClient{
		ClientID:    "legacy-client",
		RedirectURI: "https://gw.example.com/oauth/callback/linear",
		ClientName:  infraoauth.DefaultClientName,
	}
	svc := connectWithHosts(t, gw, reg, store, map[string]*httptest.Server{
		"good.example": good.server,
	}, principalURLValues{"alice": {"host": "good.example"}})
	ctx := context.Background()
	ticket, err := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("ticket: %v", err)
	}
	location, err := startLocation(svc.Start(ctx, "https://gw.example.com", "https://gw.example.com", ticket, "linear", ""))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := mustQuery(t, location).Get("client_id"); got != "legacy-client" || good.registrations.Load() != 0 {
		t.Fatalf("client_id = %q, registrations = %d, want the unbound legacy client", got, good.registrations.Load())
	}
	if store.clients[legacy].ClientID != "legacy-client" {
		t.Fatal("the legacy row was replaced")
	}
}

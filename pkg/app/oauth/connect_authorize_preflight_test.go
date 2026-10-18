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
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
)

const (
	legacyClientID   = "legacy-client"
	legacyCode       = "com.example/mcp"
	legacyProvider   = "linear"
	legacyRedirect   = "https://gw.example.com/oauth/callback/linear"
	foreignAuthorize = "https://api.vendor.example/oauth/authorize"
)

type authorizeCatalog struct {
	code string
	url  string
}

func (c authorizeCatalog) GetByCode(code string) (catalogdomain.MCPServer, bool) {
	if c.code == "" || code != c.code {
		return catalogdomain.MCPServer{}, false
	}
	return catalogdomain.MCPServer{
		Code:  c.code,
		OAuth: &catalogdomain.MCPOAuth{AuthorizeURL: c.url},
	}, true
}

type legacyGateway struct {
	srv            *httptest.Server
	registrations  atomic.Int64
	authorizeHits  atomic.Int64
	otherHits      atomic.Int64
	mu             sync.Mutex
	probe          url.Values
	rejectRegister bool
	store          *memConnectStore
	vault          *memVaultRepo
	svc            oauth.ConnectService
	tokenClient    string
	tokenSecret    string
	gw             ids.GatewayID
	reg            *registrydomain.Registry
	legacyKey      string
	registrar      oauth.UpstreamRegistrar
}

func (g *legacyGateway) recordProbe(q url.Values) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.probe = q
}

func (g *legacyGateway) probeQuery() url.Values {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.probe
}

func newLegacyGateway(t *testing.T, catalogURL string, withIssuer bool, authorize http.HandlerFunc) *legacyGateway {
	t.Helper()
	g := &legacyGateway{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              g.srv.URL + "/mcp",
			"authorization_servers": []string{g.srv.URL},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 g.srv.URL,
			"authorization_endpoint": g.srv.URL + "/authorize",
			"token_endpoint":         g.srv.URL + "/token",
			"registration_endpoint":  g.srv.URL + "/register",
		})
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if g.rejectRegister {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_client_metadata"})
			return
		}
		n := g.registrations.Add(1)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":     "fresh-" + strconv.FormatInt(n, 10),
			"client_secret": "secret-" + strconv.FormatInt(n, 10),
		})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		g.authorizeHits.Add(1)
		g.recordProbe(r.URL.Query())
		if authorize != nil {
			authorize(w, r)
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) {
		g.otherHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		g.otherHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		g.mu.Lock()
		g.tokenClient = r.PostForm.Get("client_id")
		g.tokenSecret = r.PostForm.Get("client_secret")
		g.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"refreshed-access","token_type":"Bearer","expires_in":3600}`))
	})
	g.srv = httptest.NewTLSServer(mux)
	t.Cleanup(g.srv.Close)

	g.gw = ids.New[ids.GatewayKind]()
	var err error
	g.reg, err = registrydomain.NewMCPRegistry(g.gw, "example-mcp", "", &registrydomain.MCPTarget{
		Code: legacyCode,
		URL:  g.srv.URL + "/mcp",
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     legacyProvider,
			Registration: registrydomain.RegistrationAuto,
		},
	})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	g.store = newMemConnectStore()
	g.legacyKey = g.gw.String() + "|" + registrydomain.ForwardedVaultProvider(g.reg)
	cached := oauth.RegisteredClient{
		ClientID:    legacyClientID,
		RedirectURI: legacyRedirect,
		ClientName:  infraoauth.DefaultClientName,
	}
	if withIssuer {
		cached.Issuer = g.srv.URL
		cached.RegistrationEndpoint = g.srv.URL + "/register"
	}
	g.store.clients[g.legacyKey] = cached
	g.store.clients["other-slot"] = oauth.RegisteredClient{ClientID: "other-client", ClientSecret: "keep"}

	var catalog oauthCatalog
	if catalogURL != "" {
		catalog = authorizeCatalog{code: legacyCode, url: catalogURL}
	}
	g.vault = &memVaultRepo{}
	g.registrar = infraoauth.NewUpstreamRegistrar(g.store, g.srv.Client())
	data := appconsumer.NewData(g.gw, []appconsumer.RoutableConsumer{{
		Consumer: &consumerdomain.Consumer{
			ID: ids.New[ids.ConsumerKind](), GatewayID: g.gw,
			Type: consumerdomain.TypeMCP, Slug: "dev", Active: true,
		},
		Registries: []*registrydomain.Registry{g.reg},
	}})
	g.svc = oauth.NewConnectService(
		g.store, g.vault, &stubDataFinder{data: data},
		infraoauth.NewProviderClient(nil), g.registrar,
		discardConnectAuditor(), nil, nil, catalog, nil,
	)
	return g
}

// oauthCatalog is the unexported catalog shape NewConnectService accepts.
// The helper stores it as the concrete stub, which implements GetByCode.
type oauthCatalog interface {
	GetByCode(code string) (catalogdomain.MCPServer, bool)
}

func (g *legacyGateway) start(ctx context.Context) (string, error) {
	ticket, err := g.svc.CreateTicket(ctx, g.gw, "alice", "/dev/mcp")
	if err != nil {
		return "", err
	}
	return startLocation(g.svc.Start(ctx, "https://gw.example.com", "https://gw.example.com", ticket, legacyProvider, ""))
}

func (g *legacyGateway) scopedClient(t *testing.T) (string, oauth.RegisteredClient) {
	t.Helper()
	var key string
	var client oauth.RegisteredClient
	found := 0
	for k, c := range g.store.clients {
		if k == g.legacyKey || k == "other-slot" {
			continue
		}
		found++
		key, client = k, c
	}
	if found != 1 {
		t.Fatalf("scoped clients = %d, want 1", found)
	}
	return key, client
}

func rejectUnrecognized(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusUnprocessableEntity)
	_ = json.NewEncoder(w).Encode(map[string]any{"message": "Unrecognized client_id"})
}

func rejectRedirectURI(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_redirect_uri"})
}

func rejectRedirectRequest(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":             "invalid_request",
		"error_description": "redirect_uri not allowed",
	})
}

func rejectInvalidClient(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_client"})
}

func rejectUnauthorizedClient(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": "unauthorized_client"})
}

func TestLegacyAuthorizePreflight_RejectionReplacesOnlyThatSlot(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		authorize http.HandlerFunc
	}{
		{name: "unrecognized client_id", authorize: rejectUnrecognized},
		{name: "invalid_client", authorize: rejectInvalidClient},
		{name: "unauthorized_client", authorize: rejectUnauthorizedClient},
		{name: "same origin invalid_client", authorize: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "/error?error=invalid_client&error_description=Unrecognized+client_id")
			w.WriteHeader(http.StatusFound)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := newLegacyGateway(t, "", false, tc.authorize)
			g.svc = relinkCatalog(t, g, g.srv.URL+"/authorize")
			ctx := context.Background()
			location, err := g.start(ctx)
			if err != nil {
				t.Fatalf("Start: %v", err)
			}
			if g.authorizeHits.Load() != 1 || g.otherHits.Load() != 0 {
				t.Fatalf("authorize hits = %d, followed = %d, want one probe and no redirect", g.authorizeHits.Load(), g.otherHits.Load())
			}
			if g.registrations.Load() != 1 {
				t.Fatalf("registrations = %d, want one replacement", g.registrations.Load())
			}
			probe := g.probeQuery()
			if probe.Get("client_id") != legacyClientID || probe.Get("redirect_uri") != legacyRedirect {
				t.Fatalf("probe client_id = %q redirect_uri = %q", probe.Get("client_id"), probe.Get("redirect_uri"))
			}
			if probe.Get("state") == "" || probe.Get("code_challenge") == "" {
				t.Fatal("probe is missing the throwaway state or pkce challenge")
			}
			query := mustQuery(t, location)
			if query.Get("client_id") == legacyClientID || query.Get("client_id") == "" {
				t.Fatalf("authorize client_id = %q, want the replacement", query.Get("client_id"))
			}
			if query.Get("state") == probe.Get("state") || query.Get("code_challenge") == probe.Get("code_challenge") {
				t.Fatal("the browser authorize URL reused the probe state or challenge")
			}
			legacy := g.store.clients[g.legacyKey]
			if legacy.ClientID != legacyClientID || legacy.ClientSecretExpiresAt != 1 {
				t.Fatalf("legacy row = %+v, want the same client tombstoned", legacy)
			}
			if other := g.store.clients["other-slot"]; other.ClientID != "other-client" || other.ClientSecretExpiresAt != 0 {
				t.Fatalf("other slot = %+v, want it untouched", other)
			}
			key, fresh := g.scopedClient(t)
			if fresh.ClientID != query.Get("client_id") || fresh.Issuer == "" || fresh.RegistrationEndpoint == "" {
				t.Fatalf("scoped client = %+v, want issuer and registration endpoint recorded", fresh)
			}
			if err := g.registrar.DropCachedClient(ctx, key, legacyClientID); err != nil {
				t.Fatalf("drop stale id: %v", err)
			}
			if got := g.store.clients[key]; got.ClientID != fresh.ClientID || got.ClientSecretExpiresAt != fresh.ClientSecretExpiresAt {
				t.Fatalf("scoped client after stale drop = %+v, want it unchanged", got)
			}

			again, err := g.start(ctx)
			if err != nil {
				t.Fatalf("second Start: %v", err)
			}
			if g.authorizeHits.Load() != 1 || g.registrations.Load() != 1 {
				t.Fatalf("after second connect authorize = %d registrations = %d, want the bound row left alone", g.authorizeHits.Load(), g.registrations.Load())
			}
			if mustQuery(t, again).Get("client_id") != fresh.ClientID {
				t.Fatalf("second client_id = %q, want %q", mustQuery(t, again).Get("client_id"), fresh.ClientID)
			}
		})
	}
}

func relinkCatalog(t *testing.T, g *legacyGateway, authorizeURL string, opts ...oauth.ConnectOption) oauth.ConnectService {
	t.Helper()
	data := appconsumer.NewData(g.gw, []appconsumer.RoutableConsumer{{
		Consumer: &consumerdomain.Consumer{
			ID: ids.New[ids.ConsumerKind](), GatewayID: g.gw,
			Type: consumerdomain.TypeMCP, Slug: "dev", Active: true,
		},
		Registries: []*registrydomain.Registry{g.reg},
	}})
	vault := g.vault
	if vault == nil {
		vault = &memVaultRepo{}
	}
	return oauth.NewConnectService(
		g.store, vault, &stubDataFinder{data: data},
		infraoauth.NewProviderClient(nil), g.registrar,
		discardConnectAuditor(), nil, nil, authorizeCatalog{code: legacyCode, url: authorizeURL}, nil,
		opts...,
	)
}

func TestLegacyAuthorizePreflight_AcceptanceOrAmbiguousKeepsTheSlot(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		timeout   bool
		authorize http.HandlerFunc
	}{
		{name: "200", authorize: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"message":"Unrecognized client_id"}`)
		}},
		{name: "login redirect", authorize: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "http://"+r.Host+"/login")
			w.WriteHeader(http.StatusFound)
		}},
		{name: "callback redirect", authorize: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "https://gw.example.com/oauth/callback/linear?error=invalid_client")
			w.WriteHeader(http.StatusFound)
		}},
		{name: "ambiguous invalid_request", authorize: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": "invalid_request", "error_description": "missing parameter",
			})
		}},
		{name: "upstream 500", authorize: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}},
		{name: "403 html", authorize: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "<html><body>Request blocked by WAF</body></html>")
		}},
		{name: "404 html unknown client", authorize: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, "<html><body>unknown client</body></html>")
		}},
		{name: "429 unknown client", authorize: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":"invalid_client","message":"unknown client"}`)
		}},
		{name: "400 html unknown client", authorize: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "<html><body>unknown client invalid_client</body></html>")
		}},
		{name: "timeout", timeout: true, authorize: func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(time.Second):
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := newLegacyGateway(t, "", false, tc.authorize)
			g.svc = relinkCatalog(t, g, g.srv.URL+"/authorize")
			ctx := context.Background()
			if tc.timeout {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 500*time.Millisecond)
				defer cancel()
			}
			location, err := g.start(ctx)
			if err != nil {
				t.Fatalf("Start: %v", err)
			}
			if mustQuery(t, location).Get("client_id") != legacyClientID || g.registrations.Load() != 0 {
				t.Fatalf("client_id = %q registrations = %d, want the cached client", mustQuery(t, location).Get("client_id"), g.registrations.Load())
			}
			if g.otherHits.Load() != 0 {
				t.Fatalf("followed = %d, want the redirect left alone", g.otherHits.Load())
			}
			legacy := g.store.clients[g.legacyKey]
			if legacy.ClientID != legacyClientID || legacy.ClientSecretExpiresAt != 0 || legacy.Issuer != "" {
				t.Fatalf("legacy row = %+v, want it unchanged", legacy)
			}
			if _, ok := scopedOrNone(g); ok {
				t.Fatal("a scoped client was registered")
			}
		})
	}
}

func scopedOrNone(g *legacyGateway) (oauth.RegisteredClient, bool) {
	for k, c := range g.store.clients {
		if k == g.legacyKey || k == "other-slot" {
			continue
		}
		return c, true
	}
	return oauth.RegisteredClient{}, false
}

func TestLegacyAuthorizePreflight_IssuerSkipsTheProbe(t *testing.T) {
	t.Parallel()
	g := newLegacyGateway(t, "", true, rejectUnrecognized)
	g.svc = relinkCatalog(t, g, g.srv.URL+"/authorize")
	location, err := g.start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if g.authorizeHits.Load() != 0 || g.registrations.Load() != 0 {
		t.Fatalf("authorize = %d registrations = %d, want no probe", g.authorizeHits.Load(), g.registrations.Load())
	}
	if mustQuery(t, location).Get("client_id") != legacyClientID {
		t.Fatalf("client_id = %q, want the bound client", mustQuery(t, location).Get("client_id"))
	}
}

func TestLegacyAuthorizePreflight_DisallowedHostIsNotRequested(t *testing.T) {
	t.Parallel()
	g := newLegacyGateway(t, "", false, rejectUnrecognized)
	g.svc = relinkCatalog(t, g, foreignAuthorize)
	location, err := g.start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if g.authorizeHits.Load() != 0 || g.registrations.Load() != 0 {
		t.Fatalf("authorize = %d registrations = %d, want no request to the discovered host", g.authorizeHits.Load(), g.registrations.Load())
	}
	if mustQuery(t, location).Get("client_id") != legacyClientID {
		t.Fatalf("client_id = %q, want the cached client", mustQuery(t, location).Get("client_id"))
	}
	legacy := g.store.clients[g.legacyKey]
	if legacy.ClientSecretExpiresAt != 0 {
		t.Fatalf("legacy row = %+v, want it kept", legacy)
	}
}

func TestLegacyAuthorizePreflight_DifferentOriginIsNotRejection(t *testing.T) {
	t.Parallel()
	var followed atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		followed.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(other.Close)
	g := newLegacyGateway(t, "", false, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", other.URL+"/error?error=invalid_client&error_description=Unrecognized+client_id")
		w.WriteHeader(http.StatusFound)
	})
	g.svc = relinkCatalog(t, g, g.srv.URL+"/authorize")
	location, err := g.start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if followed.Load() != 0 || g.registrations.Load() != 0 {
		t.Fatalf("followed = %d registrations = %d, want the other origin ignored", followed.Load(), g.registrations.Load())
	}
	if mustQuery(t, location).Get("client_id") != legacyClientID {
		t.Fatalf("client_id = %q, want the cached client", mustQuery(t, location).Get("client_id"))
	}
}

func TestLegacyAuthorizePreflight_TemplatedHostIsNotProbed(t *testing.T) {
	t.Parallel()
	var authorizeHits atomic.Int64
	var registrations atomic.Int64
	var srvURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              "https://good.example/mcp",
			"authorization_servers": []string{"https://good.example"},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 "https://good.example",
			"authorization_endpoint": "https://good.example/authorize",
			"token_endpoint":         srvURL + "/token",
			"registration_endpoint":  srvURL + "/register",
		})
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, _ *http.Request) {
		n := registrations.Add(1)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "scoped-" + strconv.FormatInt(n, 10)})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, _ *http.Request) {
		authorizeHits.Add(1)
		rejectUnrecognized(w, nil)
	})
	srv := httptest.NewServer(mux)
	srvURL = srv.URL
	t.Cleanup(srv.Close)

	gw := ids.New[ids.GatewayKind]()
	reg := templatedRegistry(t, gw)
	reg.MCPTarget.Code = legacyCode
	store := newMemConnectStore()
	legacy := gw.String() + "|" + registrydomain.ForwardedVaultProvider(reg)
	store.clients[legacy] = oauth.RegisteredClient{
		ClientID:    legacyClientID,
		RedirectURI: legacyRedirect,
		ClientName:  infraoauth.DefaultClientName,
	}
	data := appconsumer.NewData(gw, []appconsumer.RoutableConsumer{{
		Consumer: &consumerdomain.Consumer{
			ID: ids.New[ids.ConsumerKind](), GatewayID: gw,
			Type: consumerdomain.TypeMCP, Slug: "dev", Active: true,
		},
		Registries: []*registrydomain.Registry{reg},
	}})
	wired := oauth.NewConnectService(
		store, &memVaultRepo{}, &stubDataFinder{data: data},
		infraoauth.NewProviderClient(nil),
		infraoauth.NewUpstreamRegistrar(store, &http.Client{Transport: hostRewrite{targets: map[string]*httptest.Server{"good.example": srv}}}),
		discardConnectAuditor(), nil, nil, authorizeCatalog{code: legacyCode, url: "https://good.example/authorize"}, nil,
		oauth.WithConnectURLValues(principalURLValues{"alice": {"host": "good.example"}}),
	)
	ticket, err := wired.CreateTicket(context.Background(), gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("ticket: %v", err)
	}
	location, err := startLocation(wired.Start(context.Background(), "https://gw.example.com", "https://gw.example.com", ticket, "linear", ""))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if authorizeHits.Load() != 0 {
		t.Fatalf("authorize hits = %d, want no probe of a templated host", authorizeHits.Load())
	}
	if mustQuery(t, location).Get("client_id") == legacyClientID || registrations.Load() != 1 {
		t.Fatalf("client_id = %q registrations = %d, want a scoped registration", mustQuery(t, location).Get("client_id"), registrations.Load())
	}
	if store.clients[legacy].ClientID != legacyClientID || store.clients[legacy].ClientSecretExpiresAt != 0 {
		t.Fatalf("legacy row = %+v, want it untouched", store.clients[legacy])
	}
}

func TestLegacyAuthorizePreflight_RegistrationFailureStaysTheExistingError(t *testing.T) {
	t.Parallel()
	g := newLegacyGateway(t, "", false, rejectUnrecognized)
	g.rejectRegister = true
	g.svc = relinkCatalog(t, g, g.srv.URL+"/authorize")
	_, err := g.start(context.Background())
	if !errors.Is(err, oauth.ErrUpstreamRegistrationRejected) {
		t.Fatalf("Start error = %v, want registration rejected", err)
	}
	if g.authorizeHits.Load() != 1 {
		t.Fatalf("authorize hits = %d, want one probe", g.authorizeHits.Load())
	}
	legacy := g.store.clients[g.legacyKey]
	if legacy.ClientID != legacyClientID || legacy.ClientSecretExpiresAt != 0 || legacy.Issuer != "" {
		t.Fatalf("legacy row = %+v, want it untouched", legacy)
	}
	if _, ok := scopedOrNone(g); ok {
		t.Fatal("a failed replacement was stored")
	}
}

func TestLegacyAuthorizePreflight_RedirectURIKeepsExistingRefresh(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		authorize http.HandlerFunc
	}{
		{name: "invalid_redirect_uri", authorize: rejectRedirectURI},
		{name: "invalid_request redirect_uri", authorize: rejectRedirectRequest},
		{name: "same origin redirect_uri", authorize: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "/error?error=invalid_request&error_description=The+redirect_uri+parameter+does+not+match")
			w.WriteHeader(http.StatusFound)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := newLegacyGateway(t, "", false, tc.authorize)
			legacy := g.store.clients[g.legacyKey]
			legacy.ClientSecret = "legacy-secret"
			g.store.clients[g.legacyKey] = legacy
			g.svc = relinkCatalog(t, g, g.srv.URL+"/authorize")
			ctx := identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "alice"})
			cred, err := vaultdomain.NewCredential(g.gw, "alice", registrydomain.ForwardedVaultProvider(g.reg), "acct", "old-access", "user-refresh", nil, time.Now().Add(-time.Hour))
			if err != nil {
				t.Fatalf("credential: %v", err)
			}
			if err := g.vault.Upsert(ctx, cred); err != nil {
				t.Fatalf("vault: %v", err)
			}
			location, err := g.start(ctx)
			if err != nil {
				t.Fatalf("Start: %v", err)
			}
			if g.authorizeHits.Load() != 1 || g.otherHits.Load() != 0 || g.registrations.Load() != 1 {
				t.Fatalf("authorize = %d followed = %d registrations = %d, want one probe and one replacement", g.authorizeHits.Load(), g.otherHits.Load(), g.registrations.Load())
			}
			freshID := mustQuery(t, location).Get("client_id")
			if freshID == "" || freshID == legacyClientID {
				t.Fatalf("authorize client_id = %q, want the replacement", freshID)
			}
			kept := g.store.clients[g.legacyKey]
			if kept.ClientID != legacyClientID || kept.ClientSecret != "legacy-secret" || kept.ClientSecretExpiresAt != 1 {
				t.Fatalf("legacy row = %+v, want the original client kept and tombstoned", kept)
			}
			if other := g.store.clients["other-slot"]; other.ClientID != "other-client" {
				t.Fatalf("other slot = %+v, want it untouched", other)
			}
			_, scoped := g.scopedClient(t)
			if scoped.ClientID != freshID || scoped.Issuer == "" {
				t.Fatalf("scoped client = %+v, want the replacement with an issuer", scoped)
			}

			auth, err := g.svc.RefreshAuth(ctx, g.gw, g.reg)
			if err != nil {
				t.Fatalf("RefreshAuth: %v", err)
			}
			if auth.ClientID != legacyClientID || auth.ClientSecret != "legacy-secret" {
				t.Fatalf("refresh client = %q / %q, want the original client", auth.ClientID, auth.ClientSecret)
			}
			if _, err := infraoauth.NewProviderClient(g.srv.Client()).Refresh(ctx, auth, "user-refresh"); err != nil {
				t.Fatalf("Refresh: %v", err)
			}
			g.mu.Lock()
			tokenClient, tokenSecret := g.tokenClient, g.tokenSecret
			g.mu.Unlock()
			if tokenClient != legacyClientID || tokenSecret != "legacy-secret" {
				t.Fatalf("token client = %q secret = %q, want the original client", tokenClient, tokenSecret)
			}

			cred.OAuthClientID = freshID
			if err := g.vault.Upsert(ctx, cred); err != nil {
				t.Fatalf("stamp vault: %v", err)
			}
			next, err := g.svc.RefreshAuth(ctx, g.gw, g.reg)
			if err != nil {
				t.Fatalf("RefreshAuth new grant: %v", err)
			}
			if next.ClientID != freshID {
				t.Fatalf("new grant refresh client = %q, want %q", next.ClientID, freshID)
			}

			again, err := g.start(ctx)
			if err != nil {
				t.Fatalf("second Start: %v", err)
			}
			if g.authorizeHits.Load() != 1 || g.registrations.Load() != 1 {
				t.Fatalf("after second connect authorize = %d registrations = %d, want the row left alone", g.authorizeHits.Load(), g.registrations.Load())
			}
			if mustQuery(t, again).Get("client_id") != freshID {
				t.Fatalf("second client_id = %q, want %q", mustQuery(t, again).Get("client_id"), freshID)
			}
		})
	}
}

func TestLegacyAuthorizePreflight_RedirectRegistrationFailureLeavesTheRow(t *testing.T) {
	t.Parallel()
	g := newLegacyGateway(t, "", false, rejectRedirectURI)
	g.rejectRegister = true
	g.svc = relinkCatalog(t, g, g.srv.URL+"/authorize")
	_, err := g.start(context.Background())
	if !errors.Is(err, oauth.ErrUpstreamRegistrationRejected) {
		t.Fatalf("Start error = %v, want registration rejected", err)
	}
	if g.authorizeHits.Load() != 1 || g.registrations.Load() != 0 {
		t.Fatalf("authorize = %d registrations = %d, want one probe and no registration", g.authorizeHits.Load(), g.registrations.Load())
	}
	legacy := g.store.clients[g.legacyKey]
	if legacy.ClientID != legacyClientID || legacy.ClientSecretExpiresAt != 0 || legacy.Issuer != "" {
		t.Fatalf("legacy row = %+v, want it untouched", legacy)
	}
	if _, ok := scopedOrNone(g); ok {
		t.Fatal("a failed replacement was stored")
	}
}

func TestLegacyAuthorizePreflight_InsecureCatalogIsNotRequested(t *testing.T) {
	t.Parallel()
	g := newLegacyGateway(t, "", false, rejectUnrecognized)
	parsed, err := url.Parse(g.srv.URL)
	if err != nil {
		t.Fatalf("server url: %v", err)
	}
	g.svc = relinkCatalog(t, g, "http://"+parsed.Host+"/authorize")
	location, err := g.start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if g.authorizeHits.Load() != 0 || g.registrations.Load() != 0 {
		t.Fatalf("authorize = %d registrations = %d, want no request", g.authorizeHits.Load(), g.registrations.Load())
	}
	if mustQuery(t, location).Get("client_id") != legacyClientID {
		t.Fatalf("client_id = %q, want the cached client", mustQuery(t, location).Get("client_id"))
	}
}

func TestLegacyAuthorizePreflight_WrongPortIsNotRequested(t *testing.T) {
	t.Parallel()
	g := newLegacyGateway(t, "", false, rejectUnrecognized)
	parsed, err := url.Parse(g.srv.URL)
	if err != nil {
		t.Fatalf("server url: %v", err)
	}
	g.svc = relinkCatalog(t, g, "https://"+parsed.Hostname()+":1/authorize")
	location, err := g.start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if g.authorizeHits.Load() != 0 || g.registrations.Load() != 0 {
		t.Fatalf("authorize = %d registrations = %d, want no request", g.authorizeHits.Load(), g.registrations.Load())
	}
	if mustQuery(t, location).Get("client_id") != legacyClientID {
		t.Fatalf("client_id = %q, want the cached client", mustQuery(t, location).Get("client_id"))
	}
}

func TestLegacyAuthorizePreflight_AcceptedResultIsNotProbedAgainUntilTTL(t *testing.T) {
	t.Parallel()
	g := newLegacyGateway(t, "", false, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
	})
	current := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	g.svc = relinkCatalog(t, g, g.srv.URL+"/authorize", oauth.WithConnectClock(func() time.Time { return current }))
	ctx := context.Background()
	for range 2 {
		location, err := g.start(ctx)
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
		if mustQuery(t, location).Get("client_id") != legacyClientID {
			t.Fatalf("client_id = %q, want the cached client", mustQuery(t, location).Get("client_id"))
		}
	}
	if g.authorizeHits.Load() != 1 || g.registrations.Load() != 0 {
		t.Fatalf("authorize = %d registrations = %d, want one accepted probe", g.authorizeHits.Load(), g.registrations.Load())
	}
	current = current.Add(time.Hour + time.Second)
	if _, err := g.start(ctx); err != nil {
		t.Fatalf("Start after TTL: %v", err)
	}
	if g.authorizeHits.Load() != 2 {
		t.Fatalf("authorize = %d, want a fresh probe after the acceptance expired", g.authorizeHits.Load())
	}
	legacy := g.store.clients[g.legacyKey]
	if legacy.ClientID != legacyClientID || legacy.ClientSecretExpiresAt != 0 {
		t.Fatalf("legacy row = %+v, want it untouched", legacy)
	}
}

func TestLegacyAuthorizePreflight_AmbiguousResultIsProbedAgain(t *testing.T) {
	t.Parallel()
	g := newLegacyGateway(t, "", false, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "<html><body>unknown client</body></html>")
	})
	g.svc = relinkCatalog(t, g, g.srv.URL+"/authorize")
	ctx := context.Background()
	for range 2 {
		location, err := g.start(ctx)
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
		if mustQuery(t, location).Get("client_id") != legacyClientID {
			t.Fatalf("client_id = %q, want the cached client", mustQuery(t, location).Get("client_id"))
		}
	}
	if g.authorizeHits.Load() != 2 || g.registrations.Load() != 0 {
		t.Fatalf("authorize = %d registrations = %d, want each connect to probe and neither to replace", g.authorizeHits.Load(), g.registrations.Load())
	}
	legacy := g.store.clients[g.legacyKey]
	if legacy.ClientID != legacyClientID || legacy.ClientSecretExpiresAt != 0 {
		t.Fatalf("legacy row = %+v, want it untouched", legacy)
	}
}

func TestLegacyAuthorizePreflight_ConcurrentConnectsConverge(t *testing.T) {
	t.Parallel()
	g := newLegacyGateway(t, "", false, rejectUnrecognized)
	locked := &lockedConnectStore{memConnectStore: g.store}
	g.store = nil
	g.registrar = infraoauth.NewUpstreamRegistrar(locked, g.srv.Client())
	g.svc = oauth.NewConnectService(
		locked, &memVaultRepo{}, &stubDataFinder{data: consumerData(g.gw, g.reg)},
		infraoauth.NewProviderClient(nil), g.registrar,
		discardConnectAuditor(), nil, nil, authorizeCatalog{code: legacyCode, url: g.srv.URL + "/authorize"}, nil,
	)
	const n = 2
	locations := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			locations[i], errs[i] = g.start(context.Background())
		}(i)
	}
	wg.Wait()
	var clientID string
	for i, err := range errs {
		if err != nil {
			t.Fatalf("connect %d: %v", i, err)
		}
		got := mustQuery(t, locations[i]).Get("client_id")
		if got == "" || got == legacyClientID {
			t.Fatalf("connect %d client_id = %q", i, got)
		}
		if clientID == "" {
			clientID = got
		}
		if got != clientID {
			t.Fatalf("connect %d client_id = %q, want %q", i, got, clientID)
		}
	}
	locked.mu.Lock()
	defer locked.mu.Unlock()
	legacy := locked.clients[g.legacyKey]
	if legacy.ClientID != legacyClientID || legacy.ClientSecretExpiresAt != 1 {
		t.Fatalf("legacy row = %+v, want it tombstoned", legacy)
	}
	if other := locked.clients["other-slot"]; other.ClientID != "other-client" || other.ClientSecretExpiresAt != 0 {
		t.Fatalf("other slot = %+v", other)
	}
	found := 0
	for key, client := range locked.clients {
		if key == g.legacyKey || key == "other-slot" {
			continue
		}
		found++
		if client.ClientID != clientID || client.Issuer == "" {
			t.Fatalf("scoped client = %+v", client)
		}
	}
	if found != 1 {
		t.Fatalf("scoped rows = %d, want 1", found)
	}
}

type lockedConnectStore struct {
	mu sync.Mutex
	*memConnectStore
}

func (s *lockedConnectStore) SaveClient(ctx context.Context, key string, c oauth.RegisteredClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.memConnectStore.SaveClient(ctx, key, c)
}

func (s *lockedConnectStore) GetClient(ctx context.Context, key string) (*oauth.RegisteredClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.memConnectStore.GetClient(ctx, key)
}

func (s *lockedConnectStore) SaveClientIfAbsent(ctx context.Context, key string, c oauth.RegisteredClient) (*oauth.RegisteredClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.memConnectStore.SaveClientIfAbsent(ctx, key, c)
}

func (s *lockedConnectStore) ReplaceClientIfMatch(ctx context.Context, key, expectedClientID string, next oauth.RegisteredClient) (*oauth.RegisteredClient, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.memConnectStore.ReplaceClientIfMatch(ctx, key, expectedClientID, next)
}

func (s *lockedConnectStore) SaveTicket(ctx context.Context, id string, ticket oauth.ConnectTicket) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.memConnectStore.SaveTicket(ctx, id, ticket)
}

func (s *lockedConnectStore) GetTicket(ctx context.Context, id string) (*oauth.ConnectTicket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.memConnectStore.GetTicket(ctx, id)
}

func (s *lockedConnectStore) SaveConnect(ctx context.Context, state string, st oauth.ConnectState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.memConnectStore.SaveConnect(ctx, state, st)
}

func (s *lockedConnectStore) TakeConnect(ctx context.Context, state string) (*oauth.ConnectState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.memConnectStore.TakeConnect(ctx, state)
}

func (s *lockedConnectStore) PeekConnect(ctx context.Context, state string) (*oauth.ConnectState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.memConnectStore.PeekConnect(ctx, state)
}

func (s *lockedConnectStore) SaveFinish(ctx context.Context, token string, f oauth.ConnectFinish) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.memConnectStore.SaveFinish(ctx, token, f)
}

func (s *lockedConnectStore) TakeFinish(ctx context.Context, token string) (*oauth.ConnectFinish, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.memConnectStore.TakeFinish(ctx, token)
}

func consumerData(gw ids.GatewayID, reg *registrydomain.Registry) *appconsumer.Data {
	return appconsumer.NewData(gw, []appconsumer.RoutableConsumer{{
		Consumer: &consumerdomain.Consumer{
			ID: ids.New[ids.ConsumerKind](), GatewayID: gw,
			Type: consumerdomain.TypeMCP, Slug: "dev", Active: true,
		},
		Registries: []*registrydomain.Registry{reg},
	}})
}

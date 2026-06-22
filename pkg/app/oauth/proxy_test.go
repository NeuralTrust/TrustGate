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
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

type memFlowStore struct {
	mu      sync.Mutex
	pending map[string]PendingAuthorization
	codes   map[string]CodeGrant
	clients map[string]RegisteredGatewayClient
}

func newMemFlowStore() *memFlowStore {
	return &memFlowStore{
		pending: map[string]PendingAuthorization{},
		codes:   map[string]CodeGrant{},
		clients: map[string]RegisteredGatewayClient{},
	}
}

func (s *memFlowStore) SaveGatewayClient(_ context.Context, c RegisteredGatewayClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ClientID] = c
	return nil
}

func (s *memFlowStore) GetGatewayClient(_ context.Context, clientID string) (*RegisteredGatewayClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[clientID]
	if !ok {
		return nil, nil
	}
	return &c, nil
}

func (s *memFlowStore) SavePending(_ context.Context, state string, p PendingAuthorization) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[state] = p
	return nil
}

func (s *memFlowStore) TakePending(_ context.Context, state string) (*PendingAuthorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[state]
	if !ok {
		return nil, nil
	}
	delete(s.pending, state)
	return &p, nil
}

func (s *memFlowStore) SaveCode(_ context.Context, code string, g CodeGrant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code] = g
	return nil
}

func (s *memFlowStore) TakeCode(_ context.Context, code string) (*CodeGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.codes[code]
	if !ok {
		return nil, nil
	}
	delete(s.codes, code)
	return &g, nil
}

// fakeIdP serves AS metadata and a token endpoint, capturing the exchange form.
func fakeIdP(t *testing.T) (*httptest.Server, *url.Values) {
	t.Helper()
	captured := &url.Values{}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 srv.URL,
				"authorization_endpoint": srv.URL + "/authorize",
				"token_endpoint":         srv.URL + "/token",
			})
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			*captured = r.PostForm
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "idp-access-token",
				"refresh_token": "idp-refresh-token",
				"token_type":    "Bearer",
				"expires_in":    3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, captured
}

func newProxyUnderTest(t *testing.T, idpURL string, store FlowStore) AuthProxy {
	t.Helper()
	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{
		oauth2Auth(t, authdomain.OAuth2Config{
			Issuer:         idpURL,
			ClientID:       "gw-client-id",
			ClientSecret:   "gw-secret",
			RequiredScopes: []string{"api://gw-client-id/mcp.access"},
		}),
	}}
	return NewAuthProxy(finder, nil, http.DefaultClient, store, nil)
}

func TestBrokeredFlowEndToEnd(t *testing.T) {
	t.Parallel()
	idp, captured := fakeIdP(t)
	store := newMemFlowStore()
	proxy := newProxyUnderTest(t, idp.URL, store)
	ctx := context.Background()

	// Leg 1: client authorize -> IdP redirect.
	location, err := proxy.Authorize(ctx, "http://gw.example.com", AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "gw-client-id",
		RedirectURI:         "cursor://anysphere.cursor-mcp/oauth/callback",
		State:               "client-state",
		CodeChallenge:       s256("client-verifier"),
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	loc, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse IdP redirect: %v", err)
	}
	if !strings.HasPrefix(location, idp.URL+"/authorize?") {
		t.Fatalf("expected redirect to IdP authorize, got %s", location)
	}
	q := loc.Query()
	if q.Get("redirect_uri") != "http://gw.example.com/oauth/callback" {
		t.Fatalf("IdP must only see the gateway callback, got %s", q.Get("redirect_uri"))
	}
	if q.Get("client_id") != "gw-client-id" || q.Get("code_challenge") == "" {
		t.Fatalf("missing IdP leg parameters: %v", q)
	}
	if !strings.Contains(q.Get("scope"), "api://gw-client-id/mcp.access") {
		t.Fatalf("required scopes must be injected, got %q", q.Get("scope"))
	}
	gwState := q.Get("state")

	// Leg 2: IdP callback -> gateway exchanges code, mints its own.
	clientLoc, err := proxy.Callback(ctx, "http://gw.example.com", gwState, "idp-code", "", "")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if !strings.HasPrefix(clientLoc, "cursor://anysphere.cursor-mcp/oauth/callback?") {
		t.Fatalf("expected redirect to client callback, got %s", clientLoc)
	}
	cu, _ := url.Parse(clientLoc)
	cq := cu.Query()
	if cq.Get("state") != "client-state" {
		t.Fatalf("client state must be relayed, got %q", cq.Get("state"))
	}
	gwCode := cq.Get("code")
	if gwCode == "" || gwCode == "idp-code" {
		t.Fatalf("expected gateway-minted code, got %q", gwCode)
	}
	if captured.Get("code") != "idp-code" || captured.Get("client_secret") != "gw-secret" {
		t.Fatalf("IdP exchange used wrong form: %v", *captured)
	}

	// Leg 3: client token exchange with PKCE.
	token, err := proxy.Exchange(ctx, "http://gw.example.com", TokenRequest{
		GrantType:    "authorization_code",
		Code:         gwCode,
		RedirectURI:  "cursor://anysphere.cursor-mcp/oauth/callback",
		ClientID:     "gw-client-id",
		CodeVerifier: "client-verifier",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if token["access_token"] != "idp-access-token" {
		t.Fatalf("expected IdP token passthrough, got %v", token)
	}

	// Codes are single-use.
	if _, err := proxy.Exchange(ctx, "http://gw.example.com", TokenRequest{
		GrantType:    "authorization_code",
		Code:         gwCode,
		RedirectURI:  "cursor://anysphere.cursor-mcp/oauth/callback",
		CodeVerifier: "client-verifier",
	}); err == nil {
		t.Fatal("expected reused code to be rejected")
	}
}

func TestExchangeRejectsBadPKCE(t *testing.T) {
	t.Parallel()
	idp, _ := fakeIdP(t)
	store := newMemFlowStore()
	proxy := newProxyUnderTest(t, idp.URL, store)
	ctx := context.Background()

	_ = store.SaveCode(ctx, "gw-code", CodeGrant{
		RedirectURI:   "http://127.0.0.1:1234/callback",
		CodeChallenge: s256("right-verifier"),
		Token:         map[string]any{"access_token": "x"},
	})

	_, err := proxy.Exchange(ctx, "http://gw.example.com", TokenRequest{
		GrantType:    "authorization_code",
		Code:         "gw-code",
		RedirectURI:  "http://127.0.0.1:1234/callback",
		CodeVerifier: "wrong-verifier",
	})
	var oe *OAuthError
	if !errors.As(err, &oe) || oe.Code != "invalid_grant" {
		t.Fatalf("expected invalid_grant, got %v", err)
	}
}

func TestExchangeRejectsRedirectMismatch(t *testing.T) {
	t.Parallel()
	idp, _ := fakeIdP(t)
	store := newMemFlowStore()
	proxy := newProxyUnderTest(t, idp.URL, store)
	ctx := context.Background()

	_ = store.SaveCode(ctx, "gw-code", CodeGrant{
		RedirectURI:   "cursor://anysphere.cursor-mcp/oauth/callback",
		CodeChallenge: s256("v"),
		Token:         map[string]any{"access_token": "x"},
	})

	_, err := proxy.Exchange(ctx, "http://gw.example.com", TokenRequest{
		GrantType:    "authorization_code",
		Code:         "gw-code",
		RedirectURI:  "http://evil.example.com/callback",
		CodeVerifier: "v",
	})
	var oe *OAuthError
	if !errors.As(err, &oe) || oe.Code != "invalid_grant" {
		t.Fatalf("expected invalid_grant, got %v", err)
	}
}

func TestAuthorizeEnforcesRegisteredRedirectURIs(t *testing.T) {
	t.Parallel()
	idp, _ := fakeIdP(t)
	store := newMemFlowStore()
	_ = store.SaveGatewayClient(context.Background(), RegisteredGatewayClient{
		ClientID:     "agw-abc",
		RedirectURIs: []string{"cursor://anysphere.cursor-mcp/oauth/callback"},
	})
	proxy := newProxyUnderTest(t, idp.URL, store)

	_, err := proxy.Authorize(context.Background(), "http://gw.example.com", AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "agw-abc",
		RedirectURI:         "https://attacker.example.com/cb",
		CodeChallenge:       s256("v"),
		CodeChallengeMethod: "S256",
	})
	var oe *OAuthError
	if !errors.As(err, &oe) || oe.Code != "invalid_request" {
		t.Fatalf("expected invalid_request for unregistered redirect_uri, got %v", err)
	}

	location, err := proxy.Authorize(context.Background(), "http://gw.example.com", AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "agw-abc",
		RedirectURI:         "cursor://anysphere.cursor-mcp/oauth/callback",
		CodeChallenge:       s256("v"),
		CodeChallengeMethod: "S256",
	})
	if err != nil || !strings.HasPrefix(location, idp.URL+"/authorize?") {
		t.Fatalf("registered redirect_uri must pass: %v (%s)", err, location)
	}
}

func TestAuthorizeRejectsUnsafeRedirectForUnregisteredClients(t *testing.T) {
	t.Parallel()
	idp, _ := fakeIdP(t)
	proxy := newProxyUnderTest(t, idp.URL, newMemFlowStore())

	_, err := proxy.Authorize(context.Background(), "http://gw.example.com", AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "gw-client-id",
		RedirectURI:         "http://attacker.example.com/cb",
		CodeChallenge:       s256("v"),
		CodeChallengeMethod: "S256",
	})
	var oe *OAuthError
	if !errors.As(err, &oe) || oe.Code != "invalid_request" {
		t.Fatalf("expected invalid_request for non-loopback http redirect, got %v", err)
	}
}

func TestAuthorizeRequiresPrivateUseRedirectRegistration(t *testing.T) {
	t.Parallel()
	idp, _ := fakeIdP(t)
	proxy := newProxyUnderTest(t, idp.URL, newMemFlowStore())

	_, err := proxy.Authorize(context.Background(), "http://gw.example.com", AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "gw-client-id",
		RedirectURI:         "claude://oauth/callback",
		CodeChallenge:       s256("v"),
		CodeChallengeMethod: "S256",
	})
	var oe *OAuthError
	if !errors.As(err, &oe) || oe.Code != "invalid_request" {
		t.Fatalf("expected invalid_request for unregistered private-use redirect_uri, got %v", err)
	}
}

func TestAuthorizeRequiresPKCE(t *testing.T) {
	t.Parallel()
	idp, _ := fakeIdP(t)
	proxy := newProxyUnderTest(t, idp.URL, newMemFlowStore())

	_, err := proxy.Authorize(context.Background(), "http://gw.example.com", AuthorizeRequest{
		ResponseType: "code",
		RedirectURI:  "cursor://cb",
	})
	var oe *OAuthError
	if !errors.As(err, &oe) || oe.Code != "invalid_request" {
		t.Fatalf("expected invalid_request for missing PKCE, got %v", err)
	}
}

func TestCallbackRelaysIdPDenial(t *testing.T) {
	t.Parallel()
	idp, _ := fakeIdP(t)
	store := newMemFlowStore()
	proxy := newProxyUnderTest(t, idp.URL, store)
	ctx := context.Background()

	_ = store.SavePending(ctx, "gw-state", PendingAuthorization{
		RedirectURI: "cursor://cb",
		State:       "client-state",
	})

	loc, err := proxy.Callback(ctx, "http://gw.example.com", "gw-state", "", "access_denied", "user cancelled")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	u, _ := url.Parse(loc)
	if u.Query().Get("error") != "access_denied" || u.Query().Get("state") != "client-state" {
		t.Fatalf("expected denial relayed to client, got %s", loc)
	}
}

func TestRefreshProxiesToIdP(t *testing.T) {
	t.Parallel()
	idp, captured := fakeIdP(t)
	proxy := newProxyUnderTest(t, idp.URL, newMemFlowStore())

	token, err := proxy.Exchange(context.Background(), "http://gw.example.com", TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: "old-refresh",
	})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if token["access_token"] != "idp-access-token" {
		t.Fatalf("expected refreshed IdP token, got %v", token)
	}
	if captured.Get("refresh_token") != "old-refresh" || captured.Get("grant_type") != "refresh_token" {
		t.Fatalf("IdP refresh used wrong form: %v", *captured)
	}
}

type fakePathResolver struct {
	byPath map[string][]appconsumer.PathMatch
}

func (f *fakePathResolver) Match(_ context.Context, _, path string) ([]appconsumer.PathMatch, error) {
	return f.byPath[path], nil
}

// enabledOAuth2Auth builds an Auth entry that passes the Enabled/Type filters
// of resource-scoped selection (the bare oauth2Auth fake does not).
func enabledOAuth2Auth(t *testing.T, cfg authdomain.OAuth2Config) *authdomain.Auth {
	t.Helper()
	a := oauth2Auth(t, cfg)
	a.ID = ids.New[ids.AuthKind]()
	a.GatewayID = ids.New[ids.GatewayKind]()
	a.Type = authdomain.TypeOAuth2
	a.Enabled = true
	return a
}

// Two tenants on two IdPs: the RFC 8707 resource indicator pins the whole
// flow (authorize redirect, callback token exchange) to the addressed
// tenant's IdP, even though both are configured.
func TestResourceScopedFacadeSelectsIdPPerTenant(t *testing.T) {
	t.Parallel()
	idpA, capturedA := fakeIdP(t)
	idpB, capturedB := fakeIdP(t)
	authA := enabledOAuth2Auth(t, authdomain.OAuth2Config{Issuer: idpA.URL, ClientID: "client-a"})
	authB := enabledOAuth2Auth(t, authdomain.OAuth2Config{Issuer: idpB.URL, ClientID: "client-b"})
	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{authA, authB}}
	paths := &fakePathResolver{byPath: map[string][]appconsumer.PathMatch{
		"/v1/mcp/tenant-b": {{GatewayID: authB.GatewayID, Auths: []*authdomain.Auth{authB}}},
	}}
	store := newMemFlowStore()
	proxy := NewAuthProxy(finder, paths, http.DefaultClient, store, nil)
	ctx := context.Background()

	location, err := proxy.Authorize(ctx, "http://gw.example.com", AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "client-b",
		RedirectURI:         "cursor://anysphere.cursor-mcp/oauth/callback",
		State:               "client-state",
		CodeChallenge:       s256("client-verifier"),
		CodeChallengeMethod: "S256",
		Resource:            "http://gw.example.com/v1/mcp/tenant-b",
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	loc, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if got := loc.Scheme + "://" + loc.Host; got != idpB.URL {
		t.Fatalf("authorize must redirect to tenant B's IdP, got %s (want %s)", got, idpB.URL)
	}
	if loc.Query().Get("client_id") != "client-b" {
		t.Fatalf("IdP leg must use tenant B's client, got %q", loc.Query().Get("client_id"))
	}

	// Callback must exchange the code at the same IdP (pinned via AuthID).
	if _, err := proxy.Callback(ctx, "http://gw.example.com", loc.Query().Get("state"), "idp-code", "", ""); err != nil {
		t.Fatalf("callback: %v", err)
	}
	if len(*capturedA) != 0 {
		t.Fatalf("tenant A's IdP must not be contacted, got %v", *capturedA)
	}
	if capturedB.Get("client_id") != "client-b" {
		t.Fatalf("token exchange must hit tenant B's IdP with its client, got %v", *capturedB)
	}
}

// When the resource pins a consumer that has no OAuth2 auth of its own, the
// fallback is scoped to that consumer's gateway: a different tenant's IdP must
// not turn the lookup ambiguous.
func TestAuthorizeResourceFallsBackToGatewayScopedIdP(t *testing.T) {
	t.Parallel()
	idpGateway, _ := fakeIdP(t)
	idpOtherTenant, capturedOther := fakeIdP(t)
	gatewayID := ids.New[ids.GatewayKind]()

	gatewayAuth := enabledOAuth2Auth(t, authdomain.OAuth2Config{Issuer: idpGateway.URL, ClientID: "client-gw"})
	gatewayAuth.GatewayID = gatewayID
	otherTenantAuth := enabledOAuth2Auth(t, authdomain.OAuth2Config{Issuer: idpOtherTenant.URL, ClientID: "client-other"})

	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{gatewayAuth, otherTenantAuth}}
	paths := &fakePathResolver{byPath: map[string][]appconsumer.PathMatch{
		"/cons/mcp": {{GatewayID: gatewayID, Auths: nil}},
	}}
	proxy := NewAuthProxy(finder, paths, http.DefaultClient, newMemFlowStore(), nil)

	location, err := proxy.Authorize(context.Background(), "http://gw.example.com", AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "client-gw",
		RedirectURI:         "cursor://anysphere.cursor-mcp/oauth/callback",
		CodeChallenge:       s256("v"),
		CodeChallengeMethod: "S256",
		Resource:            "http://gw.example.com/cons/mcp",
	})
	if err != nil {
		t.Fatalf("authorize must resolve the gateway's single IdP, got %v", err)
	}
	loc, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if got := loc.Scheme + "://" + loc.Host; got != idpGateway.URL {
		t.Fatalf("authorize must redirect to the gateway IdP, got %s (want %s)", got, idpGateway.URL)
	}
	if len(*capturedOther) != 0 {
		t.Fatalf("another tenant's IdP must never be contacted, got %v", *capturedOther)
	}
}

// A consumer without its own OAuth2 auth on a gateway that hosts several IdPs
// is genuinely ambiguous: the client gets invalid_target, not a cross-tenant
// leak.
func TestAuthorizeResourceAmbiguousWithinGateway(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	authA := enabledOAuth2Auth(t, authdomain.OAuth2Config{Issuer: "https://idp-a.example.com", ClientID: "client-a"})
	authA.GatewayID = gatewayID
	authB := enabledOAuth2Auth(t, authdomain.OAuth2Config{Issuer: "https://idp-b.example.com", ClientID: "client-b"})
	authB.GatewayID = gatewayID

	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{authA, authB}}
	paths := &fakePathResolver{byPath: map[string][]appconsumer.PathMatch{
		"/cons/mcp": {{GatewayID: gatewayID, Auths: nil}},
	}}
	proxy := NewAuthProxy(finder, paths, http.DefaultClient, newMemFlowStore(), nil)

	_, err := proxy.Authorize(context.Background(), "http://gw.example.com", AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "client-a",
		RedirectURI:         "cursor://cb",
		CodeChallenge:       s256("v"),
		CodeChallengeMethod: "S256",
		Resource:            "http://gw.example.com/cons/mcp",
	})
	var oe *OAuthError
	if !errors.As(err, &oe) || oe.Code != "invalid_target" {
		t.Fatalf("expected invalid_target within an ambiguous gateway, got %v", err)
	}
}

func TestAuthorizeResourceNoOAuth2GivesClearError(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	finder := &fakeCredentialFinder{}
	paths := &fakePathResolver{byPath: map[string][]appconsumer.PathMatch{
		"/cons/mcp": {{GatewayID: gatewayID, Auths: nil}},
	}}
	proxy := NewAuthProxy(finder, paths, http.DefaultClient, newMemFlowStore(), nil)

	_, err := proxy.Authorize(context.Background(), "http://gw.example.com", AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "cli",
		RedirectURI:         "cursor://cb",
		CodeChallenge:       s256("v"),
		CodeChallengeMethod: "S256",
		Resource:            "http://gw.example.com/cons/mcp",
	})
	var oe *OAuthError
	if !errors.As(err, &oe) || oe.Code != "invalid_request" {
		t.Fatalf("expected invalid_request for a consumer without oauth2, got %v", err)
	}
}

// Multiple IdPs without a resource indicator cannot be disambiguated: the
// client gets a structured invalid_target error.
func TestAuthorizeMultiIssuerRequiresResource(t *testing.T) {
	t.Parallel()
	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{
		enabledOAuth2Auth(t, authdomain.OAuth2Config{Issuer: "https://idp-a.example.com", ClientID: "client-a"}),
		enabledOAuth2Auth(t, authdomain.OAuth2Config{Issuer: "https://idp-b.example.com", ClientID: "client-b"}),
	}}
	proxy := NewAuthProxy(finder, &fakePathResolver{}, http.DefaultClient, newMemFlowStore(), nil)

	_, err := proxy.Authorize(context.Background(), "http://gw.example.com", AuthorizeRequest{
		ResponseType:        "code",
		RedirectURI:         "cursor://cb",
		CodeChallenge:       s256("v"),
		CodeChallengeMethod: "S256",
	})
	var oe *OAuthError
	if !errors.As(err, &oe) || oe.Code != "invalid_target" {
		t.Fatalf("expected invalid_target, got %v", err)
	}
}

// The refresh leg also honors the resource indicator (RFC 8707 in token
// requests), so refreshes keep hitting the right IdP.
func TestRefreshUsesResourceIndicator(t *testing.T) {
	t.Parallel()
	idpA, capturedA := fakeIdP(t)
	idpB, capturedB := fakeIdP(t)
	authA := enabledOAuth2Auth(t, authdomain.OAuth2Config{Issuer: idpA.URL, ClientID: "client-a"})
	authB := enabledOAuth2Auth(t, authdomain.OAuth2Config{Issuer: idpB.URL, ClientID: "client-b"})
	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{authA, authB}}
	paths := &fakePathResolver{byPath: map[string][]appconsumer.PathMatch{
		"/v1/mcp/tenant-b": {{GatewayID: authB.GatewayID, Auths: []*authdomain.Auth{authB}}},
	}}
	proxy := NewAuthProxy(finder, paths, http.DefaultClient, newMemFlowStore(), nil)

	if _, err := proxy.Exchange(context.Background(), "http://gw.example.com", TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: "rt-1",
		Resource:     "http://gw.example.com/v1/mcp/tenant-b",
	}); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if len(*capturedA) != 0 {
		t.Fatalf("tenant A's IdP must not be contacted, got %v", *capturedA)
	}
	if capturedB.Get("grant_type") != "refresh_token" || capturedB.Get("client_id") != "client-b" {
		t.Fatalf("refresh must be proxied to tenant B's IdP, got %v", *capturedB)
	}
}

type fakeChainer struct {
	url      string
	calls    int
	resource string
	sub      string
	resume   string
}

func (f *fakeChainer) ChainURL(_ context.Context, _ string, _ ids.GatewayID, resource, principalSub, resumeURL string) (string, error) {
	f.calls++
	f.resource, f.sub, f.resume = resource, principalSub, resumeURL
	return f.url, nil
}

// unsignedJWT builds a JWT-shaped token; the callback parses it without
// verification since it arrives straight from the IdP token endpoint.
func unsignedJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

// fakeIdPWithToken mirrors fakeIdP but returns the given access token.
func fakeIdPWithToken(t *testing.T, accessToken string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 srv.URL,
				"authorization_endpoint": srv.URL + "/authorize",
				"token_endpoint":         srv.URL + "/token",
			})
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": accessToken,
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func chainProxyUnderTest(t *testing.T, idpURL string, store FlowStore, chainer ConsentChainer) AuthProxy {
	t.Helper()
	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{
		oauth2Auth(t, authdomain.OAuth2Config{
			Issuer:   idpURL,
			ClientID: "gw-client-id",
		}),
	}}
	return NewAuthProxy(finder, nil, http.DefaultClient, store, chainer)
}

func authorizeAndGetState(t *testing.T, proxy AuthProxy, resource string) string {
	t.Helper()
	location, err := proxy.Authorize(context.Background(), "http://gw.example.com", AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "gw-client-id",
		RedirectURI:         "cursor://anysphere.cursor-mcp/oauth/callback",
		State:               "client-state",
		CodeChallenge:       s256("client-verifier"),
		CodeChallengeMethod: "S256",
		Resource:            resource,
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	loc, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse IdP redirect: %v", err)
	}
	return loc.Query().Get("state")
}

// With a resource indicator and unlinked downstream providers, the callback
// parks the client redirect and detours through the connect page.
func TestCallbackChainsDownstreamConsent(t *testing.T) {
	t.Parallel()
	idp := fakeIdPWithToken(t, unsignedJWT(t, map[string]any{"oid": "user-123", "sub": "pairwise-sub"}))
	store := newMemFlowStore()
	chainer := &fakeChainer{url: "http://gw.example.com/v1/mcp/linear/connect?ticket=tk"}
	proxy := chainProxyUnderTest(t, idp.URL, store, chainer)

	gwState := authorizeAndGetState(t, proxy, "http://gw.example.com/v1/mcp/linear")
	loc, err := proxy.Callback(context.Background(), "http://gw.example.com", gwState, "idp-code", "", "")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if loc != chainer.url {
		t.Fatalf("expected detour to connect page, got %s", loc)
	}
	if chainer.resource != "http://gw.example.com/v1/mcp/linear" {
		t.Fatalf("chainer got resource %q", chainer.resource)
	}
	if chainer.sub != "user-123" {
		t.Fatalf("expected oid-preferred subject, got %q", chainer.sub)
	}
	resume, err := url.Parse(chainer.resume)
	if err != nil || resume.Scheme != "cursor" || resume.Query().Get("code") == "" || resume.Query().Get("state") != "client-state" {
		t.Fatalf("parked resume URL must carry the client redirect with code+state, got %q", chainer.resume)
	}
}

// When everything is already linked (chainer yields "") the callback proceeds
// straight to the client redirect.
func TestCallbackSkipsChainWhenNothingToLink(t *testing.T) {
	t.Parallel()
	idp := fakeIdPWithToken(t, unsignedJWT(t, map[string]any{"sub": "pairwise-sub"}))
	store := newMemFlowStore()
	chainer := &fakeChainer{url: ""}
	proxy := chainProxyUnderTest(t, idp.URL, store, chainer)

	gwState := authorizeAndGetState(t, proxy, "http://gw.example.com/v1/mcp/linear")
	loc, err := proxy.Callback(context.Background(), "http://gw.example.com", gwState, "idp-code", "", "")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if !strings.HasPrefix(loc, "cursor://anysphere.cursor-mcp/oauth/callback?") {
		t.Fatalf("expected direct client redirect, got %s", loc)
	}
	if chainer.calls != 1 || chainer.sub != "pairwise-sub" {
		t.Fatalf("chainer should be consulted once with the sub fallback, got calls=%d sub=%q", chainer.calls, chainer.sub)
	}
}

// Clients do not always send a resource indicator: the chainer is still
// consulted (with an empty resource) so it can fall back to scanning.
func TestCallbackChainsWithoutResource(t *testing.T) {
	t.Parallel()
	idp := fakeIdPWithToken(t, unsignedJWT(t, map[string]any{"sub": "pairwise-sub"}))
	store := newMemFlowStore()
	chainer := &fakeChainer{url: "http://gw.example.com/v1/mcp/linear/connect?ticket=tk"}
	proxy := chainProxyUnderTest(t, idp.URL, store, chainer)

	gwState := authorizeAndGetState(t, proxy, "")
	loc, err := proxy.Callback(context.Background(), "http://gw.example.com", gwState, "idp-code", "", "")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if loc != chainer.url {
		t.Fatalf("expected detour to connect page, got %s", loc)
	}
	if chainer.calls != 1 || chainer.resource != "" {
		t.Fatalf("chainer must run with empty resource, calls=%d resource=%q", chainer.calls, chainer.resource)
	}
}

// A non-JWT (opaque) IdP access token cannot identify the principal: the
// chain is skipped, never broken.
func TestCallbackOpaqueTokenSkipsChain(t *testing.T) {
	t.Parallel()
	idp := fakeIdPWithToken(t, "opaque-token")
	store := newMemFlowStore()
	chainer := &fakeChainer{url: "http://should.not.be/used"}
	proxy := chainProxyUnderTest(t, idp.URL, store, chainer)

	gwState := authorizeAndGetState(t, proxy, "http://gw.example.com/v1/mcp/linear")
	loc, err := proxy.Callback(context.Background(), "http://gw.example.com", gwState, "idp-code", "", "")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if !strings.HasPrefix(loc, "cursor://anysphere.cursor-mcp/oauth/callback?") {
		t.Fatalf("expected direct client redirect, got %s", loc)
	}
	if chainer.calls != 0 {
		t.Fatalf("chainer must not run without a subject, calls=%d", chainer.calls)
	}
}

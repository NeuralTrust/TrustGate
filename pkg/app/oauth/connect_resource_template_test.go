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

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
)

const (
	ahaTemplate   = "https://{domain}.aha.io/api/v1/mcp"
	ahaResolved   = "https://acme.aha.io/api/v1/mcp"
	ahaAuthorize  = "https://acme.aha.io/oauth/authorize"
	ahaAuthorizeT = "https://{domain}.aha.io/oauth/authorize"
)

type mapURLValues map[string]map[string]string

func (v mapURLValues) Values(_ context.Context, _ ids.GatewayID, principalSub string, _ *registrydomain.Registry) (map[string]string, error) {
	return v[principalSub], nil
}

type fixedRegistrar struct {
	meta       *oauth.UpstreamAuthServer
	client     *oauth.RegisteredClient
	discovered []string
}

func (r *fixedRegistrar) Discover(_ context.Context, upstreamURL string) (*oauth.UpstreamAuthServer, error) {
	r.discovered = append(r.discovered, upstreamURL)
	return r.meta, nil
}

func (r *fixedRegistrar) EnsureClient(context.Context, string, *oauth.UpstreamAuthServer, string) (*oauth.RegisteredClient, error) {
	return r.client, nil
}

func (r *fixedRegistrar) CachedClient(context.Context, string) (*oauth.RegisteredClient, error) {
	return r.client, nil
}

func templatedConnect(t *testing.T, reg *registrydomain.Registry, values map[string]string, registrar oauth.UpstreamRegistrar) oauth.ConnectService {
	t.Helper()
	data := appconsumer.NewData(reg.GatewayID, []appconsumer.RoutableConsumer{{
		Consumer: &consumerdomain.Consumer{
			ID: ids.New[ids.ConsumerKind](), GatewayID: reg.GatewayID,
			Type: consumerdomain.TypeMCP, Slug: "dev", Active: true,
		},
		Registries: []*registrydomain.Registry{reg},
	}})
	return oauth.NewConnectService(
		newMemConnectStore(),
		&memVaultRepo{},
		&stubDataFinder{data: data},
		infraoauth.NewProviderClient(nil),
		registrar,
		discardConnectAuditor(),
		nil, nil, nil, nil,
		oauth.WithConnectURLValues(mapURLValues{"alice": values}),
	)
}

func ahaRegistry(t *testing.T, resource, authorizeURL, tokenURL string) *registrydomain.Registry {
	t.Helper()
	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "aha", "", &registrydomain.MCPTarget{
		Code:         "io.aha/mcp",
		URL:          ahaTemplate,
		URLVariables: []registrydomain.MCPURLVariable{{Name: "domain", Required: true}},
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     "io.aha/mcp",
			Registration: registrydomain.RegistrationAuto,
			AuthorizeURL: authorizeURL,
			TokenURL:     tokenURL,
			Resource:     resource,
			Scopes:       []string{"full"},
		},
	})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	return reg
}

// A templated DCR server (Aha!: no catalog oauth.resource) used to send the
// RFC 8707 resource as the literal server template. The authorize and token
// requests have to carry the instance's resolved resource, and the vault key
// stays the template it was derived from.
func TestConnectService_TemplatedServerSendsResolvedResource(t *testing.T) {
	t.Parallel()
	var tokenForm url.Values
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse token form: %v", err)
		}
		tokenForm = r.Form
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "aha-access", "refresh_token": "aha-refresh", "expires_in": 3600,
		})
	}))
	t.Cleanup(tokenSrv.Close)

	reg := ahaRegistry(t, ahaTemplate, ahaAuthorizeT, "https://{domain}.aha.io/oauth/token")
	vaultKey := registrydomain.ForwardedVaultProvider(reg)
	vaultResource := registrydomain.ForwardedCredentialResource(reg)
	registrar := &fixedRegistrar{
		meta: &oauth.UpstreamAuthServer{
			AuthorizationEndpoint: ahaAuthorizeT,
			TokenEndpoint:         tokenSrv.URL,
			Resource:              ahaResolved,
			ScopesSupported:       []string{"full"},
		},
		client: &oauth.RegisteredClient{ClientID: "dcr-aha"},
	}
	svc := templatedConnect(t, reg, map[string]string{"domain": "acme"}, registrar)
	ctx := context.Background()

	ticket, err := svc.CreateTicket(ctx, reg.GatewayID, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	location, err := startLocation(svc.Start(ctx, "https://gw.example.com", "https://gw.example.com", ticket, "io.aha/mcp", ""))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("location: %v", err)
	}
	if !strings.HasPrefix(location, ahaAuthorize+"?") {
		t.Fatalf("redirect = %q, want authorize host substituted", location)
	}
	if got := u.Query().Get("resource"); got != ahaResolved {
		t.Fatalf("authorize resource = %q, want %q", got, ahaResolved)
	}
	if strings.ContainsAny(location, "{}") {
		t.Fatalf("redirect still has a placeholder: %s", location)
	}

	if _, err := svc.Callback(ctx, "https://gw.example.com", "io.aha/mcp", u.Query().Get("state"), "the-code", "", ""); err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if got := tokenForm.Get("resource"); got != ahaResolved {
		t.Fatalf("token resource = %q, want %q", got, ahaResolved)
	}

	refreshCtx := identity.WithPrincipal(ctx, &identity.Principal{Subject: "alice"})
	refreshed, err := svc.RefreshAuth(refreshCtx, reg.GatewayID, reg)
	if err != nil {
		t.Fatalf("RefreshAuth: %v", err)
	}
	if refreshed.Resource != ahaResolved {
		t.Fatalf("refresh resource = %q, want %q", refreshed.Resource, ahaResolved)
	}
	if refreshed.TokenURL != tokenSrv.URL {
		t.Fatalf("refresh token url = %q, want the discovered endpoint", refreshed.TokenURL)
	}

	if registrydomain.ForwardedVaultProvider(reg) != vaultKey {
		t.Fatalf("vault key changed from %q to %q", vaultKey, registrydomain.ForwardedVaultProvider(reg))
	}
	if registrydomain.ForwardedCredentialResource(reg) != vaultResource || !strings.Contains(vaultResource, "{domain}") {
		t.Fatalf("vault resource = %q, want the template %q left as stored", registrydomain.ForwardedCredentialResource(reg), vaultResource)
	}
	for _, discovered := range registrar.discovered {
		if discovered != ahaResolved {
			t.Fatalf("discovered %q, want the resolved server", discovered)
		}
	}
}

// The protected-resource metadata discovered at the resolved URL wins over the
// template copied onto the registry, even when substituting that template
// would produce a different path.
func TestConnectService_TemplatedResourcePrefersDiscoveredPRM(t *testing.T) {
	t.Parallel()
	const prm = "https://acme.aha.io/mcp"
	reg := ahaRegistry(t, ahaTemplate, ahaAuthorizeT, "https://{domain}.aha.io/oauth/token")
	registrar := &fixedRegistrar{
		meta: &oauth.UpstreamAuthServer{
			AuthorizationEndpoint: ahaAuthorize,
			TokenEndpoint:         "https://acme.aha.io/oauth/token",
			Resource:              prm,
		},
		client: &oauth.RegisteredClient{ClientID: "dcr-aha"},
	}
	svc := templatedConnect(t, reg, map[string]string{"domain": "acme"}, registrar)

	ticket, err := svc.CreateTicket(context.Background(), reg.GatewayID, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	location, err := startLocation(svc.Start(context.Background(), "https://gw.example.com", "https://gw.example.com", ticket, "io.aha/mcp", ""))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("location: %v", err)
	}
	if got := u.Query().Get("resource"); got != prm {
		t.Fatalf("authorize resource = %q, want discovered PRM %q", got, prm)
	}
}

func TestConnectService_UnresolvedOAuthPlaceholderDoesNotRedirect(t *testing.T) {
	t.Parallel()
	const unresolved = "https://mcp.example.com/{not_supplied}"
	reg := ahaRegistry(t, unresolved, ahaAuthorize, "https://acme.aha.io/oauth/token")
	registrar := &fixedRegistrar{
		meta: &oauth.UpstreamAuthServer{
			AuthorizationEndpoint: ahaAuthorize,
			TokenEndpoint:         "https://acme.aha.io/oauth/token",
			Resource:              unresolved,
		},
		client: &oauth.RegisteredClient{ClientID: "dcr-aha"},
	}
	svc := templatedConnect(t, reg, map[string]string{"domain": "acme"}, registrar)

	ticket, err := svc.CreateTicket(context.Background(), reg.GatewayID, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	started, err := svc.Start(context.Background(), "https://gw.example.com", "https://gw.example.com", ticket, "io.aha/mcp", "")
	if err == nil || started != nil {
		loc := ""
		if started != nil {
			loc = started.Location
		}
		t.Fatalf("Start = %q, err = %v; want no redirect", loc, err)
	}
	if !errors.Is(err, oauth.ErrUnresolvedOAuthPlaceholder) || !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("err = %v, want unresolved placeholder", err)
	}
}

// A per-user value must not retarget the token endpoint — where the gateway
// sends the client secret — at a host other than the one already resolved and
// validated for this server.
func TestConnectService_TemplatedOAuthURLCannotRetargetSecrets(t *testing.T) {
	t.Parallel()
	reg := ahaRegistry(t, ahaResolved, ahaAuthorize, "https://{domain}.aha.io/oauth/token")
	registrar := &fixedRegistrar{
		meta: &oauth.UpstreamAuthServer{
			AuthorizationEndpoint: ahaAuthorize,
			TokenEndpoint:         "https://{domain}.evil.test/oauth/token",
			Resource:              ahaResolved,
		},
		client: &oauth.RegisteredClient{ClientID: "dcr-aha", ClientSecret: "admin-secret"},
	}
	svc := templatedConnect(t, reg, map[string]string{"domain": "acme"}, registrar)

	ticket, err := svc.CreateTicket(context.Background(), reg.GatewayID, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	started, err := svc.Start(context.Background(), "https://gw.example.com", "https://gw.example.com", ticket, "io.aha/mcp", "")
	if err == nil || started != nil {
		loc := ""
		if started != nil {
			loc = started.Location
		}
		t.Fatalf("Start = %q, err = %v; want no redirect", loc, err)
	}
	if !errors.Is(err, oauth.ErrOAuthURLHost) || !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("err = %v, want host refusal", err)
	}
	if strings.Contains(err.Error(), "admin-secret") || strings.Contains(err.Error(), "evil.test") {
		t.Fatalf("error leaks the secret or the rejected host: %v", err)
	}
}

func TestConnectService_FixedServerResourceAndVaultKeyUnchanged(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	const resource = "https://mcp.linear.app/mcp"
	reg, err := registrydomain.NewMCPRegistry(gw, "linear", "", &registrydomain.MCPTarget{
		URL: resource,
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     "linear",
			Registration: registrydomain.RegistrationManual,
			ClientID:     "cid",
			ClientSecret: "csecret",
			AuthorizeURL: "https://linear.app/oauth/authorize",
			TokenURL:     "https://api.linear.app/oauth/token",
			Resource:     resource,
			Scopes:       []string{"read"},
		},
	})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	vaultKey := registrydomain.ForwardedVaultProvider(reg)
	svc := templatedConnect(t, reg, nil, &fixedRegistrar{})

	ticket, err := svc.CreateTicket(context.Background(), gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	location, err := startLocation(svc.Start(context.Background(), "https://gw.example.com", "https://gw.example.com", ticket, "linear", ""))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("location: %v", err)
	}
	if !strings.HasPrefix(location, "https://linear.app/oauth/authorize?") {
		t.Fatalf("redirect = %q", location)
	}
	if got := u.Query().Get("resource"); got != resource {
		t.Fatalf("resource = %q, want %q", got, resource)
	}
	if registrydomain.ForwardedVaultProvider(reg) != vaultKey {
		t.Fatalf("vault key changed from %q to %q", vaultKey, registrydomain.ForwardedVaultProvider(reg))
	}
	if registrydomain.ForwardedCredentialResource(reg) != resource {
		t.Fatalf("vault resource = %q, want %q", registrydomain.ForwardedCredentialResource(reg), resource)
	}
}

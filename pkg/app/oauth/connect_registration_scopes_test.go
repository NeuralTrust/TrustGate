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
	"net/http"
	"net/http/httptest"
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
	code         string
	url          string
	scopes       []string
	resource     string
	urlVariables []catalogdomain.MCPURLVariable
}

func (c stubScopeCatalog) GetByCode(code string) (catalogdomain.MCPServer, bool) {
	if code != c.code {
		return catalogdomain.MCPServer{}, false
	}
	return catalogdomain.MCPServer{
		Code:         c.code,
		URL:          c.url,
		URLVariables: c.urlVariables,
		OAuth:        &catalogdomain.MCPOAuth{Scopes: c.scopes, Resource: c.resource},
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
		stubScopeCatalog{code: "com.vanta/mcp", url: upstream.URL + "/mcp", scopes: []string{"mcp-api.all:write"}},
		nil,
	)
	ctx := context.Background()

	ticket, err := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	location, err := startLocation(svc.Start(ctx, "https://gw.example.com", "https://gw.example.com", ticket, "com.vanta/mcp", ""))
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

// Axiom's path-specific protected-resource metadata advertises
// https://mcp.axiom.co/mcp, but its authorization server only accepts the root
// resource and bounces the sign-in back with error=invalid_target. A registry
// created from the old catalog entry persisted the rejected value, so the
// catalog has to win on every call that sends the resource upstream.
func TestConnectService_AutoRegistrationAppliesCatalogResource(t *testing.T) {
	t.Parallel()
	registrations := 0
	var tokenForm url.Values
	upstream := fakeSpecUpstream(t, &registrations, &tokenForm)

	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "axiom-mcp", "", &registrydomain.MCPTarget{
		URL:  upstream.URL + "/mcp",
		Code: "co.axiom/mcp",
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     "co.axiom/mcp",
			Registration: registrydomain.RegistrationAuto,
			// Persisted from the old catalog entry.
			Resource: upstream.URL + "/mcp",
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
		stubScopeCatalog{code: "co.axiom/mcp", url: upstream.URL + "/mcp", resource: upstream.URL},
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
	if got := u.Query().Get("resource"); got != upstream.URL {
		t.Fatalf("resource = %q, want the catalog root resource %q", got, upstream.URL)
	}
	if got := u.Query().Get("scope"); got == "" {
		t.Fatalf("scope is empty; a catalog entry without scopes must keep the discovered ones")
	}

	refreshed, err := svc.RefreshAuth(ctx, gw, reg)
	if err != nil {
		t.Fatalf("RefreshAuth: %v", err)
	}
	if refreshed.Resource != upstream.URL {
		t.Fatalf("refresh resource = %q, want the catalog root resource", refreshed.Resource)
	}
}

// An old self-hosted Cube row stores https://{cube_host}/api/mcp. The catalog
// now names the hosted server and its resource. Connect and refresh must keep
// the row's resource and scopes: the hosted resource is not that deployment's
// audience, and the authorization server rejects it with invalid_target.
func TestConnectService_SelfHostedCubeKeepsStoredResourceAndScopes(t *testing.T) {
	t.Parallel()
	const (
		code            = "dev.cube/mcp"
		template        = "https://{cube_host}/api/mcp"
		resolved        = "https://self.cube.example/api/mcp"
		storedScope     = "meta"
		catalogScope    = "mcp-agent-access"
		catalogResource = "https://cubecloud.dev/mcp"
	)
	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "cube", "", &registrydomain.MCPTarget{
		Code:         code,
		URL:          resolved,
		URLVariables: []registrydomain.MCPURLVariable{{Name: "cube_host", Required: true}},
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     code,
			Registration: registrydomain.RegistrationAuto,
			Scopes:       []string{storedScope},
			Resource:     resolved,
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
	registrar := &fixedRegistrar{
		meta: &oauth.UpstreamAuthServer{
			AuthorizationEndpoint: "https://self.cube.example/oauth/authorize",
			TokenEndpoint:         "https://self.cube.example/oauth/token",
			ScopesSupported:       []string{"discovered"},
		},
		client: &oauth.RegisteredClient{ClientID: "dcr-cube"},
	}
	svc := oauth.NewConnectService(
		newMemConnectStore(),
		&memVaultRepo{},
		&stubDataFinder{data: data},
		infraoauth.NewProviderClient(nil),
		registrar,
		discardConnectAuditor(),
		nil, nil,
		stubScopeCatalog{
			code:     code,
			url:      "https://cubecloud.dev/mcp",
			scopes:   []string{catalogScope},
			resource: catalogResource,
		},
		nil,
	)
	ctx := context.Background()

	ticket, err := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	location, err := startLocation(svc.Start(ctx, "https://gw.example.com", "https://gw.example.com", ticket, code, ""))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	u, _ := url.Parse(location)
	if got := u.Query().Get("scope"); got != storedScope {
		t.Fatalf("scope = %q, want the stored scope %q", got, storedScope)
	}
	if got := u.Query().Get("resource"); got != resolved {
		t.Fatalf("resource = %q, want the resolved stored resource %q", got, resolved)
	}

	refreshed, err := svc.RefreshAuth(ctx, gw, reg)
	if err != nil {
		t.Fatalf("RefreshAuth: %v", err)
	}
	if strings.Join(refreshed.Scopes, " ") != storedScope {
		t.Fatalf("refresh scope = %q, want the stored scope", strings.Join(refreshed.Scopes, " "))
	}
	if refreshed.Resource != resolved {
		t.Fatalf("refresh resource = %q, want the resolved stored resource", refreshed.Resource)
	}
}

// A row whose URL is the catalog server URL still takes the catalog scopes and
// resource. The hosted Cube entry is that case: connect and refresh must keep
// applying mcp-agent-access and https://cubecloud.dev/mcp.
func TestConnectService_MatchingCubeURLAppliesCatalogResourceAndScopes(t *testing.T) {
	t.Parallel()
	registrations := 0
	var tokenForm url.Values
	upstream := fakeSpecUpstream(t, &registrations, &tokenForm)

	const (
		code            = "dev.cube/mcp"
		catalogScope    = "mcp-agent-access"
		catalogResource = "https://cubecloud.dev/mcp"
	)
	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "cube-cloud", "", &registrydomain.MCPTarget{
		URL:  upstream.URL + "/mcp",
		Code: code,
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     code,
			Registration: registrydomain.RegistrationAuto,
			Scopes:       []string{"meta"},
			Resource:     upstream.URL + "/mcp",
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
		nil, nil,
		stubScopeCatalog{
			code:     code,
			url:      upstream.URL + "/mcp",
			scopes:   []string{catalogScope},
			resource: catalogResource,
		},
		nil,
	)
	ctx := context.Background()

	ticket, err := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	location, err := startLocation(svc.Start(ctx, "https://gw.example.com", "https://gw.example.com", ticket, code, ""))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	u, _ := url.Parse(location)
	if got := u.Query().Get("scope"); got != catalogScope {
		t.Fatalf("scope = %q, want the catalog scope %q", got, catalogScope)
	}
	if got := u.Query().Get("resource"); got != catalogResource {
		t.Fatalf("resource = %q, want the catalog resource %q", got, catalogResource)
	}

	refreshed, err := svc.RefreshAuth(ctx, gw, reg)
	if err != nil {
		t.Fatalf("RefreshAuth: %v", err)
	}
	if strings.Join(refreshed.Scopes, " ") != catalogScope {
		t.Fatalf("refresh scope = %q, want the catalog scope", strings.Join(refreshed.Scopes, " "))
	}
	if refreshed.Resource != catalogResource {
		t.Fatalf("refresh resource = %q, want the catalog resource", refreshed.Resource)
	}
}

// A catalog server URL that is itself a template matches after the row's
// values fill it. Servers whose URL did not change (only the placeholder
// spelling is shared) still receive the catalog scopes and resource.
func TestConnectService_CatalogAppliesWhenTemplateResolvesToTheRowURL(t *testing.T) {
	t.Parallel()
	const (
		code            = "com.vendor/mcp"
		template        = "https://{host}/mcp"
		resolved        = "https://mcp.vendor.example/mcp"
		catalogScope    = "catalog-scope"
		catalogResource = "https://mcp.vendor.example/audience"
	)
	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "vendor", "", &registrydomain.MCPTarget{
		Code:         code,
		URL:          resolved,
		URLVariables: []registrydomain.MCPURLVariable{{Name: "host", Required: true}},
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     code,
			Registration: registrydomain.RegistrationAuto,
			Scopes:       []string{"stored-scope"},
			Resource:     "https://old.example/audience",
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
	registrar := &fixedRegistrar{
		meta: &oauth.UpstreamAuthServer{
			AuthorizationEndpoint: "https://mcp.vendor.example/oauth/authorize",
			TokenEndpoint:         "https://mcp.vendor.example/oauth/token",
			ScopesSupported:       []string{"discovered"},
		},
		client: &oauth.RegisteredClient{ClientID: "dcr-vendor"},
	}
	svc := oauth.NewConnectService(
		newMemConnectStore(),
		&memVaultRepo{},
		&stubDataFinder{data: data},
		infraoauth.NewProviderClient(nil),
		registrar,
		discardConnectAuditor(),
		nil, nil,
		stubScopeCatalog{
			code:     code,
			url:      template,
			scopes:   []string{catalogScope},
			resource: catalogResource,
			urlVariables: []catalogdomain.MCPURLVariable{{
				Name:     "host",
				Required: true,
			}},
		},
		nil,
	)
	ctx := context.Background()

	ticket, err := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	location, err := startLocation(svc.Start(ctx, "https://gw.example.com", "https://gw.example.com", ticket, code, ""))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if len(registrar.discovered) != 1 || registrar.discovered[0] != resolved {
		t.Fatalf("discovered %v, want %s", registrar.discovered, resolved)
	}
	u, _ := url.Parse(location)
	if got := u.Query().Get("scope"); got != catalogScope {
		t.Fatalf("scope = %q, want the catalog scope %q", got, catalogScope)
	}
	if got := u.Query().Get("resource"); got != catalogResource {
		t.Fatalf("resource = %q, want the catalog resource %q", got, catalogResource)
	}

	refreshed, err := svc.RefreshAuth(ctx, gw, reg)
	if err != nil {
		t.Fatalf("RefreshAuth: %v", err)
	}
	if strings.Join(refreshed.Scopes, " ") != catalogScope {
		t.Fatalf("refresh scope = %q, want the catalog scope", strings.Join(refreshed.Scopes, " "))
	}
	if refreshed.Resource != catalogResource {
		t.Fatalf("refresh resource = %q, want the catalog resource", refreshed.Resource)
	}
}

// A concrete instance URL that equals one closed region of a templated catalog
// entry takes that entry's scopes on the authorize request. The registry row
// is left as stored. New Relic publishes one scope list for both regions.
func TestConnectService_RegionOptionURLUsesCatalogScopes(t *testing.T) {
	t.Parallel()
	const catalogScope = "observability:read offline offline_access"
	tests := []struct {
		name         string
		url          string
		registration registrydomain.MCPClientRegistration
		stored       []string
		want         string
	}{
		{
			name:         "old US URL",
			url:          "https://mcp.newrelic.com/mcp/",
			registration: registrydomain.RegistrationAuto,
			stored:       []string{"openid", "profile", "email"},
			want:         catalogScope,
		},
		{
			name:         "EU URL",
			url:          "https://mcp.eu.newrelic.com/mcp/",
			registration: registrydomain.RegistrationAuto,
			stored:       []string{"openid", "profile", "email"},
			want:         catalogScope,
		},
		{
			name:         "non-catalog URL",
			url:          "https://self.example/mcp/",
			registration: registrydomain.RegistrationAuto,
			stored:       []string{"openid", "profile", "email"},
			want:         "openid profile email",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			const code = "com.newrelic/mcp"
			gw := ids.New[ids.GatewayKind]()
			auth := &registrydomain.MCPAuth{
				Mode:         registrydomain.MCPAuthModeForwarded,
				Provider:     code,
				Registration: tc.registration,
				Scopes:       append([]string(nil), tc.stored...),
				Resource:     tc.url,
			}
			reg, err := registrydomain.NewMCPRegistry(gw, "newrelic", "", &registrydomain.MCPTarget{
				Code: code,
				URL:  tc.url,
				Auth: auth,
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
			host := tc.url
			registrar := &fixedRegistrar{
				meta: &oauth.UpstreamAuthServer{
					AuthorizationEndpoint: host + "oauth/authorize",
					TokenEndpoint:         host + "oauth/token",
					ScopesSupported:       []string{"openid", "observability:read", "offline", "offline_access"},
					Resource:              tc.url,
				},
				client: &oauth.RegisteredClient{ClientID: "dcr-newrelic", Issuer: host},
			}
			svc := oauth.NewConnectService(
				newMemConnectStore(),
				&memVaultRepo{},
				&stubDataFinder{data: data},
				infraoauth.NewProviderClient(nil),
				registrar,
				discardConnectAuditor(),
				nil, nil,
				stubScopeCatalog{
					code:   code,
					url:    "https://{host}/mcp/",
					scopes: []string{"observability:read", "offline", "offline_access"},
					urlVariables: []catalogdomain.MCPURLVariable{{
						Name: "host",
						Options: []catalogdomain.MCPURLVariableOption{
							{Value: "mcp.newrelic.com"},
							{Value: "mcp.eu.newrelic.com"},
						},
					}},
				},
				nil,
			)
			ctx := context.Background()
			ticket, err := svc.CreateTicket(ctx, gw, "alice", "/dev/mcp")
			if err != nil {
				t.Fatalf("CreateTicket: %v", err)
			}
			location, err := startLocation(svc.Start(ctx, "https://gw.example.com", "https://gw.example.com", ticket, code, ""))
			if err != nil {
				t.Fatalf("Start: %v", err)
			}
			u, _ := url.Parse(location)
			if got := u.Query().Get("scope"); got != tc.want {
				t.Fatalf("scope = %q, want %q", got, tc.want)
			}
			if got := u.Query().Get("resource"); got != tc.url {
				t.Fatalf("resource = %q, want the stored resource", got)
			}
			if strings.Join(reg.MCPTarget.Auth.Scopes, " ") != strings.Join(tc.stored, " ") {
				t.Fatalf("stored scopes = %v, row was rewritten", reg.MCPTarget.Auth.Scopes)
			}

			refreshed, err := svc.RefreshAuth(ctx, gw, reg)
			if err != nil {
				t.Fatalf("RefreshAuth: %v", err)
			}
			if strings.Join(refreshed.Scopes, " ") != tc.want {
				t.Fatalf("refresh scope = %q, want %q", strings.Join(refreshed.Scopes, " "), tc.want)
			}
			if strings.Join(reg.MCPTarget.Auth.Scopes, " ") != strings.Join(tc.stored, " ") {
				t.Fatalf("stored scopes = %v after refresh, row was rewritten", reg.MCPTarget.Auth.Scopes)
			}
		})
	}
}

// An old grant was issued for openid profile email. RefreshAuth reports the
// catalog scopes, but the refresh_token request omits scope. RFC 6749 §6 then
// keeps the scope originally granted, so the catalog list is not sent and the
// grant is not rejected as invalid_scope.
func TestConnectService_OldScopeGrantRefreshOmitsScope(t *testing.T) {
	t.Parallel()
	const (
		code         = "com.newrelic/mcp"
		storedURL    = "https://mcp.newrelic.com/mcp/"
		catalogScope = "observability:read offline offline_access"
		oldRefresh   = "old-newrelic-refresh"
	)
	var posted url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		posted = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-access","token_type":"Bearer","expires_in":3600}`))
	}))
	t.Cleanup(srv.Close)

	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "newrelic", "", &registrydomain.MCPTarget{
		Code: code,
		URL:  storedURL,
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     code,
			Registration: registrydomain.RegistrationAuto,
			Scopes:       []string{"openid", "profile", "email"},
			Resource:     storedURL,
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
	provider := infraoauth.NewProviderClient(srv.Client())
	svc := oauth.NewConnectService(
		newMemConnectStore(),
		&memVaultRepo{},
		&stubDataFinder{data: data},
		provider,
		&fixedRegistrar{
			meta: &oauth.UpstreamAuthServer{
				AuthorizationEndpoint: "https://oauth2.service.newrelic.com/oauth2/auth",
				TokenEndpoint:         srv.URL,
				ScopesSupported:       []string{"openid", "observability:read", "offline", "offline_access"},
				Resource:              storedURL,
			},
			client: &oauth.RegisteredClient{ClientID: "dcr-newrelic", Issuer: "https://oauth2.service.newrelic.com"},
		},
		discardConnectAuditor(),
		nil, nil,
		stubScopeCatalog{
			code:   code,
			url:    "https://{host}/mcp/",
			scopes: []string{"observability:read", "offline", "offline_access"},
			urlVariables: []catalogdomain.MCPURLVariable{{
				Name: "host",
				Options: []catalogdomain.MCPURLVariableOption{
					{Value: "mcp.newrelic.com"},
					{Value: "mcp.eu.newrelic.com"},
				},
			}},
		},
		nil,
	)
	ctx := context.Background()
	refreshed, err := svc.RefreshAuth(ctx, gw, reg)
	if err != nil {
		t.Fatalf("RefreshAuth: %v", err)
	}
	if strings.Join(refreshed.Scopes, " ") != catalogScope {
		t.Fatalf("refresh config scope = %q, want the catalog scope", strings.Join(refreshed.Scopes, " "))
	}
	if _, err := provider.Refresh(ctx, refreshed, oldRefresh); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if posted.Get("grant_type") != "refresh_token" || posted.Get("refresh_token") != oldRefresh {
		t.Fatalf("refresh form = %v", posted)
	}
	if _, ok := posted["scope"]; ok {
		t.Fatalf("refresh form sent scope %q; an old grant must omit scope", posted.Get("scope"))
	}
}

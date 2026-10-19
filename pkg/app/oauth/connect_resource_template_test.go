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

	"github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
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
	if r.meta == nil {
		return nil, nil
	}
	meta := *r.meta
	if oauth.ValidatedIssuer(&meta) == "" {
		meta.ValidatedIssuer = "https://auth.example.test"
		if u, err := url.Parse(meta.AuthorizationEndpoint); err == nil && u.Host != "" && !strings.ContainsAny(u.Host, "{}") {
			meta.ValidatedIssuer = u.Scheme + "://" + u.Host
		}
	}
	return &meta, nil
}

func (r *fixedRegistrar) EnsureClient(context.Context, string, *oauth.UpstreamAuthServer, string) (*oauth.RegisteredClient, error) {
	return r.client, nil
}

func (r *fixedRegistrar) CachedClient(context.Context, string) (*oauth.RegisteredClient, error) {
	return r.client, nil
}

func (r *fixedRegistrar) DropCachedClient(context.Context, string, string) error { return nil }

type legacySuffixCatalog struct {
	suffixes []string
}

func (c legacySuffixCatalog) GetByCode(code string) (catalogdomain.MCPServer, bool) {
	if code != "com.snowflake/mcp" {
		return catalogdomain.MCPServer{}, false
	}
	return catalogdomain.MCPServer{
		Code: code,
		URLVariables: []catalogdomain.MCPURLVariable{{
			Name:       "account_url",
			HostSuffix: c.suffixes,
		}},
	}, true
}

func templatedConnect(t *testing.T, reg *registrydomain.Registry, values map[string]string, registrar oauth.UpstreamRegistrar) oauth.ConnectService {
	t.Helper()
	return templatedConnectCatalog(t, reg, values, registrar, legacySuffixCatalog{})
}

type catalogByCode interface {
	GetByCode(code string) (catalogdomain.MCPServer, bool)
}

func templatedConnectCatalog(t *testing.T, reg *registrydomain.Registry, values map[string]string, registrar oauth.UpstreamRegistrar, catalog catalogByCode) oauth.ConnectService {
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
		nil, nil, catalog, nil,
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

// RFC 9728 §3.3: a protected-resource `resource` is this server's resource only
// when it is the URL that was queried. A different path is the template, resolved.
func TestConnectService_TemplatedResourceIgnoresMismatchedPRM(t *testing.T) {
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
	if got := u.Query().Get("resource"); got != ahaResolved {
		t.Fatalf("authorize resource = %q, want substituted template %q", got, ahaResolved)
	}
}

// A PRM resource that is the resolved upstream URL is accepted, including when
// only its canonical form matches (case, default port, trailing slash).
func TestConnectService_TemplatedResourceAcceptsCanonicalPRM(t *testing.T) {
	t.Parallel()
	const prm = "https://ACME.aha.io:443/api/v1/mcp/"
	reg := ahaRegistry(t, ahaTemplate, ahaAuthorize, "https://acme.aha.io/oauth/token")
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
		t.Fatalf("authorize resource = %q, want canonical-equal PRM %q", got, prm)
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

// An open whole-host placeholder in a pinned authorize/token URL matches the
// resolved host only because the user chose that host. The admin client secret
// must not be sent there.
func TestConnectService_WholeHostPinnedSecretRefused(t *testing.T) {
	t.Parallel()
	reg := wholeHostManualRegistry(t, nil, nil, "https://{account_url}/oauth/authorize", "https://{account_url}/oauth/token")
	assertWholeHostSecretStays(t, reg, map[string]string{"account_url": "evil.example"}, nil)
}

// A declared suffix is the bound a whole-host pin is allowed to use.
func TestConnectService_WholeHostPinnedSecretAllowedBySuffix(t *testing.T) {
	t.Parallel()
	reg := wholeHostManualRegistry(t, []string{"*.vendor.com"}, nil, "https://{account_url}/oauth/authorize", "https://{account_url}/oauth/token")
	svc := templatedConnectCatalog(t, reg, map[string]string{"account_url": "acme.vendor.com"}, &fixedRegistrar{}, legacySuffixCatalog{
		suffixes: []string{"*.vendor.com"},
	})

	ticket, err := svc.CreateTicket(context.Background(), reg.GatewayID, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	location, err := startLocation(svc.Start(context.Background(), "https://gw.example.com", "https://gw.example.com", ticket, "com.snowflake/mcp", ""))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !strings.HasPrefix(location, "https://acme.vendor.com/oauth/authorize?") {
		t.Fatalf("redirect = %q, want the suffix-matching host", location)
	}
}

// A suffix stored on the row cannot widen the catalog entry for its code.
func TestConnectService_StoredSuffixCannotWidenCatalog(t *testing.T) {
	t.Parallel()
	reg := wholeHostManualRegistry(t, []string{"*.vendor.com"}, nil, "https://{account_url}/oauth/authorize", "https://{account_url}/oauth/token")
	values := map[string]string{"account_url": "acme.vendor.com"}
	svc := templatedConnectCatalog(t, reg, values, &fixedRegistrar{}, legacySuffixCatalog{
		suffixes: []string{"*.snowflakecomputing.com"},
	})
	ticket, err := svc.CreateTicket(context.Background(), reg.GatewayID, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	started, err := svc.Start(context.Background(), "https://gw.example.com", "https://gw.example.com", ticket, "com.snowflake/mcp", "")
	if err == nil || started != nil {
		t.Fatalf("Start = %+v, err = %v; want no redirect", started, err)
	}
	if !errors.Is(err, oauth.ErrOAuthURLHost) {
		t.Fatalf("err = %v, want host refusal", err)
	}
}

// A literal label next to the placeholder does not pin the registrable domain:
// `mcp.{domain}` and `api-{domain}` with domain=evil.com go to evil.com.
func TestConnectService_PartialHostWithoutRegistrableDomainRefused(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, host string }{
		{name: "label before", host: "mcp.{domain}"},
		{name: "text before", host: "api-{domain}"},
	} {
		t.Run(tc.name+" pinned", func(t *testing.T) {
			t.Parallel()
			reg := partialHostManualRegistry(t, tc.host)
			pinManual(reg, "https://"+tc.host+"/oauth/authorize", "https://"+tc.host+"/oauth/token", "admin-secret")
			assertNoRedirect(t, reg, map[string]string{"domain": "evil.com"}, &fixedRegistrar{}, oauth.ErrOAuthURLHost)
		})
		t.Run(tc.name+" discovered", func(t *testing.T) {
			t.Parallel()
			var tokenHits int
			tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tokenHits++
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(tokenSrv.Close)
			reg := partialHostManualRegistry(t, tc.host)
			registrar := &fixedRegistrar{meta: &oauth.UpstreamAuthServer{
				AuthorizationEndpoint: tokenSrv.URL + "/authorize",
				TokenEndpoint:         tokenSrv.URL + "/token",
			}}
			assertNoRedirect(t, reg, map[string]string{"domain": "evil.com"}, registrar, oauth.ErrOAuthURLHost)
			if tokenHits != 0 {
				t.Fatalf("token server was called %d times", tokenHits)
			}
		})
	}
}

func partialHostManualRegistry(t *testing.T, host string) *registrydomain.Registry {
	t.Helper()
	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "partial", "", &registrydomain.MCPTarget{
		Code:         "com.example.partial/mcp",
		URL:          "https://" + host + "/mcp",
		URLVariables: []registrydomain.MCPURLVariable{{Name: "domain", Required: true}},
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     "com.example.partial/mcp",
			Registration: registrydomain.RegistrationManual,
			ClientID:     "cid",
			ClientSecret: "admin-secret",
			Resource:     "https://" + host + "/mcp",
		},
	})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	return reg
}

// A registry row written before host_suffix existed has an empty list. Connect
// still allows a vendor host because the catalog code supplies the current
// suffixes, and it does not write that list back onto the row.
func TestConnectService_LegacyWholeHostUsesCatalogSuffix(t *testing.T) {
	t.Parallel()
	const host = "xy12345.us-west-2.privatelink.snowflakecomputing.com"
	reg := wholeHostManualRegistry(t, nil, nil, "https://{account_url}/oauth/authorize", "https://{account_url}/oauth/token")
	svc := templatedConnectCatalog(t, reg, map[string]string{"account_url": host}, &fixedRegistrar{}, legacySuffixCatalog{
		suffixes: []string{"*.snowflakecomputing.com"},
	})

	ticket, err := svc.CreateTicket(context.Background(), reg.GatewayID, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	location, err := startLocation(svc.Start(context.Background(), "https://gw.example.com", "https://gw.example.com", ticket, "com.snowflake/mcp", ""))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !strings.HasPrefix(location, "https://"+host+"/oauth/authorize?") {
		t.Fatalf("redirect = %q, want the catalog suffix to allow the vendor host", location)
	}
	if len(reg.MCPTarget.URLVariables[0].HostSuffix) != 0 {
		t.Fatalf("fallback wrote a suffix onto the stored registry: %+v", reg.MCPTarget.URLVariables[0].HostSuffix)
	}

	refreshCtx := identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "alice"})
	refreshed, err := svc.RefreshAuth(refreshCtx, reg.GatewayID, reg)
	if err != nil {
		t.Fatalf("RefreshAuth: %v", err)
	}
	if refreshed.TokenURL != "https://"+host+"/oauth/token" {
		t.Fatalf("refresh token url = %q", refreshed.TokenURL)
	}
}

// The same legacy row still refuses a host outside the catalog suffixes, and
// the admin client secret is not posted there.
func TestConnectService_LegacyWholeHostRefusesNonVendorHost(t *testing.T) {
	t.Parallel()
	var tokenHits int
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenHits++
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if r.Form.Get("client_secret") != "" {
			t.Errorf("client secret was posted")
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(tokenSrv.Close)

	reg := wholeHostManualRegistry(t, nil, nil, "", "")
	registrar := &fixedRegistrar{meta: &oauth.UpstreamAuthServer{
		AuthorizationEndpoint: tokenSrv.URL + "/authorize",
		TokenEndpoint:         tokenSrv.URL + "/token",
	}}
	values := map[string]string{"account_url": "evil.example"}
	svc := templatedConnectCatalog(t, reg, values, registrar, legacySuffixCatalog{
		suffixes: []string{"*.snowflakecomputing.com"},
	})
	ticket, err := svc.CreateTicket(context.Background(), reg.GatewayID, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	started, err := svc.Start(context.Background(), "https://gw.example.com", "https://gw.example.com", ticket, "com.snowflake/mcp", "")
	if err == nil || started != nil {
		t.Fatalf("Start = %+v, err = %v; want no redirect", started, err)
	}
	if !errors.Is(err, oauth.ErrOAuthURLHost) {
		t.Fatalf("err = %v, want host refusal", err)
	}
	if strings.Contains(err.Error(), "admin-secret") || strings.Contains(err.Error(), "evil.example") {
		t.Fatalf("error leaks the secret or the rejected host: %v", err)
	}
	refreshCtx := identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "alice"})
	if _, err := svc.RefreshAuth(refreshCtx, reg.GatewayID, reg); !errors.Is(err, oauth.ErrOAuthURLHost) {
		t.Fatalf("RefreshAuth err = %v, want host refusal", err)
	}
	if tokenHits != 0 {
		t.Fatalf("token server was called %d times", tokenHits)
	}
}

// A manual registry with no pinned token URL takes the token URL from metadata
// discovered on the host the user typed. That host is not a bound.
func TestConnectService_ManualWholeHostDiscoveredTokenRefused(t *testing.T) {
	t.Parallel()
	var tokenHits int
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenHits++
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(tokenSrv.Close)

	reg := wholeHostManualRegistry(t, nil, nil, "", "")
	registrar := &fixedRegistrar{meta: &oauth.UpstreamAuthServer{
		AuthorizationEndpoint: tokenSrv.URL + "/authorize",
		TokenEndpoint:         tokenSrv.URL + "/token",
	}}
	assertWholeHostSecretStays(t, reg, map[string]string{"account_url": "evil.example"}, registrar)
	if tokenHits != 0 {
		t.Fatalf("token server was called %d times", tokenHits)
	}
}

// A closed whole-host variable is a vendor-published host, so discovery may
// fill the token URL.
func TestConnectService_ManualWholeHostDiscoveryAllowedWhenClosed(t *testing.T) {
	t.Parallel()
	const host = "mcp.vendor.com"
	reg := wholeHostManualRegistry(t, nil, []registrydomain.MCPURLVariableOption{{
		Value: host, Label: "Vendor",
	}}, "", "")
	registrar := &fixedRegistrar{meta: &oauth.UpstreamAuthServer{
		AuthorizationEndpoint: "https://" + host + "/oauth/authorize",
		TokenEndpoint:         "https://" + host + "/oauth/token",
	}}
	svc := templatedConnect(t, reg, map[string]string{"account_url": host}, registrar)

	ticket, err := svc.CreateTicket(context.Background(), reg.GatewayID, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	location, err := startLocation(svc.Start(context.Background(), "https://gw.example.com", "https://gw.example.com", ticket, "com.snowflake/mcp", ""))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !strings.HasPrefix(location, "https://"+host+"/oauth/authorize?") {
		t.Fatalf("redirect = %q", location)
	}
}

// A closed list does not make a public suffix a safe host. github.io is a
// suffix anyone can register under, so the admin secret is not sent there.
func TestConnectService_ClosedPublicSuffixHostRefused(t *testing.T) {
	t.Parallel()
	const host = "github.io"
	var tokenHits int
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenHits++
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(tokenSrv.Close)

	reg := wholeHostManualRegistry(t, nil, []registrydomain.MCPURLVariableOption{{
		Value: host, Label: "Pages",
	}}, "https://{account_url}/oauth/authorize", "https://{account_url}/oauth/token")
	assertNoRedirect(t, reg, map[string]string{"account_url": host}, &fixedRegistrar{}, oauth.ErrOAuthURLHost)

	reg = wholeHostManualRegistry(t, nil, []registrydomain.MCPURLVariableOption{{
		Value: host, Label: "Pages",
	}}, "", "")
	registrar := &fixedRegistrar{meta: &oauth.UpstreamAuthServer{
		AuthorizationEndpoint: "https://" + host + "/oauth/authorize",
		TokenEndpoint:         "https://" + host + "/oauth/token",
	}}
	assertNoRedirect(t, reg, map[string]string{"account_url": host}, registrar, oauth.ErrOAuthURLHost)
	if tokenHits != 0 {
		t.Fatalf("token server was called %d times", tokenHits)
	}
}

func TestConnectService_TemplatedOAuthURLPortMustMatch(t *testing.T) {
	t.Parallel()
	reg := ahaRegistry(t, ahaResolved, ahaAuthorize, "https://{domain}.aha.io/oauth/token")
	pinManual(reg, ahaAuthorize, "https://{domain}.aha.io:8443/oauth/token", "admin-secret")
	assertNoRedirect(t, reg, map[string]string{"domain": "acme"}, &fixedRegistrar{}, oauth.ErrOAuthURLHost)
}

func TestConnectService_TemplatedOAuthURLSchemeMustMatch(t *testing.T) {
	t.Parallel()
	reg := ahaRegistry(t, ahaResolved, ahaAuthorize, "https://{domain}.aha.io/oauth/token")
	pinManual(reg, ahaAuthorize, "http://{domain}.aha.io/oauth/token", "admin-secret")
	assertNoRedirect(t, reg, map[string]string{"domain": "acme"}, &fixedRegistrar{}, oauth.ErrOAuthURLHost)
}

// Placeholders in the path and query do not choose the host, so a pinned
// secret still goes to the host the template writes.
func TestConnectService_PathAndQueryPlaceholdersStayAllowed(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "org", "", &registrydomain.MCPTarget{
		Code: "com.example/mcp",
		URL:  "https://mcp.example.com/{org}/mcp",
		URLVariables: []registrydomain.MCPURLVariable{
			{Name: "org", Required: true},
		},
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     "com.example/mcp",
			Registration: registrydomain.RegistrationManual,
			ClientID:     "cid",
			ClientSecret: "admin-secret",
			AuthorizeURL: "https://mcp.example.com/{org}/oauth/authorize?realm={org}",
			TokenURL:     "https://mcp.example.com/oauth/token",
			Resource:     "https://mcp.example.com/{org}/mcp",
		},
	})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	svc := templatedConnect(t, reg, map[string]string{"org": "acme"}, &fixedRegistrar{})

	ticket, err := svc.CreateTicket(context.Background(), gw, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	location, err := startLocation(svc.Start(context.Background(), "https://gw.example.com", "https://gw.example.com", ticket, "com.example/mcp", ""))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !strings.HasPrefix(location, "https://mcp.example.com/acme/oauth/authorize?") {
		t.Fatalf("redirect = %q", location)
	}
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("location: %v", err)
	}
	if u.Query().Get("realm") != "acme" {
		t.Fatalf("realm = %q", u.Query().Get("realm"))
	}
	if u.Query().Get("resource") != "https://mcp.example.com/acme/mcp" {
		t.Fatalf("resource = %q", u.Query().Get("resource"))
	}
}

func TestConnectService_FreshworksManualUsesOrgHost(t *testing.T) {
	t.Parallel()
	cat, err := catalog.NewMCPServerCatalog(nil)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	entry, ok := cat.GetByCode("com.freshworks/mcp")
	if !ok || entry.OAuth == nil {
		t.Fatal("freshworks catalog entry")
	}
	reg := manualTenantRegistry(t, entry.URL, entry.Code, entry.OAuth.AuthorizeURL, entry.OAuth.TokenURL)
	registrar := &fixedRegistrar{}
	svc := templatedConnectCatalog(t, reg, map[string]string{"domain": "yourco"}, registrar, cat)

	ticket, err := svc.CreateTicket(context.Background(), reg.GatewayID, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	location, err := startLocation(svc.Start(context.Background(), "https://gw.example.com", "https://gw.example.com", ticket, entry.Code, ""))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !strings.HasPrefix(location, "https://yourco.myfreshworks.com/org/oauth/v2/authorize?") {
		t.Fatalf("redirect = %q", location)
	}
	if len(registrar.discovered) != 0 {
		t.Fatalf("manual registration discovered %v", registrar.discovered)
	}
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("location: %v", err)
	}
	if u.Query().Get("resource") != "https://yourco.freshservice.com/mcp" {
		t.Fatalf("resource = %q", u.Query().Get("resource"))
	}

	refreshCtx := identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "alice"})
	refreshed, err := svc.RefreshAuth(refreshCtx, reg.GatewayID, reg)
	if err != nil {
		t.Fatalf("RefreshAuth: %v", err)
	}
	if refreshed.TokenURL != "https://yourco.myfreshworks.com/org/oauth/v2/token" {
		t.Fatalf("token url = %q", refreshed.TokenURL)
	}
	if len(registrar.discovered) != 0 {
		t.Fatalf("refresh discovered %v", registrar.discovered)
	}
}

func TestConnectService_FreshworksRejectsAuthorizeHostOutsideCatalog(t *testing.T) {
	t.Parallel()
	cat, err := catalog.NewMCPServerCatalog(nil)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	entry, ok := cat.GetByCode("com.freshworks/mcp")
	if !ok || entry.OAuth == nil {
		t.Fatal("freshworks catalog entry")
	}
	reg := manualTenantRegistry(t, entry.URL, entry.Code, "https://{domain}.evil.com/oauth/authorize", "https://{domain}.evil.com/oauth/token")
	registrar := &fixedRegistrar{}
	svc := templatedConnectCatalog(t, reg, map[string]string{"domain": "yourco"}, registrar, cat)
	ticket, err := svc.CreateTicket(context.Background(), reg.GatewayID, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	started, err := svc.Start(context.Background(), "https://gw.example.com", "https://gw.example.com", ticket, entry.Code, "")
	if err == nil || started != nil {
		t.Fatalf("Start = %+v, err = %v; want no redirect", started, err)
	}
	if !errors.Is(err, oauth.ErrOAuthURLHost) {
		t.Fatalf("err = %v, want host refusal", err)
	}
	if len(registrar.discovered) != 0 {
		t.Fatalf("discovery ran: %v", registrar.discovered)
	}
}

func TestConnectService_FreshworksRejectsMCPHostOutsideCatalog(t *testing.T) {
	t.Parallel()
	cat, err := catalog.NewMCPServerCatalog(nil)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	entry, ok := cat.GetByCode("com.freshworks/mcp")
	if !ok || entry.OAuth == nil {
		t.Fatal("freshworks catalog entry")
	}
	reg := manualTenantRegistry(t, "https://{domain}.evil.com/mcp", entry.Code, entry.OAuth.AuthorizeURL, entry.OAuth.TokenURL)
	assertCatalogStartRefused(t, reg, cat, map[string]string{"domain": "yourco"})
}

func TestConnectService_SharedLabelWithoutCatalogIsRefused(t *testing.T) {
	t.Parallel()
	reg := manualTenantRegistry(t,
		"https://{domain}.freshservice.com/mcp",
		"com.freshworks/mcp",
		"https://{domain}.myfreshworks.com/org/oauth/v2/authorize",
		"https://{domain}.myfreshworks.com/org/oauth/v2/token",
	)
	assertNoRedirect(t, reg, map[string]string{"domain": "yourco"}, &fixedRegistrar{}, oauth.ErrOAuthURLHost)
}

func TestConnectService_SharedLabelRefusesSplitTenantPlaceholder(t *testing.T) {
	t.Parallel()
	const code = "com.example.split/mcp"
	entry := catalogdomain.MCPServer{
		Code: code,
		URL:  "https://{domain}.freshservice.com/mcp",
		URLVariables: []catalogdomain.MCPURLVariable{
			{Name: "domain", Required: true},
			{Name: "org", Required: true},
		},
		OAuth: &catalogdomain.MCPOAuth{
			Required:           true,
			CrossDomainContact: true,
			AuthorizeURL:       "https://{org}.myfreshworks.com/org/oauth/v2/authorize",
			TokenURL:           "https://{org}.myfreshworks.com/org/oauth/v2/token",
		},
	}
	reg := manualTenantRegistry(t, entry.URL, code, entry.OAuth.AuthorizeURL, entry.OAuth.TokenURL)
	reg.MCPTarget.URLVariables = append(reg.MCPTarget.URLVariables, registrydomain.MCPURLVariable{Name: "org", Required: true})
	assertCatalogStartRefused(t, reg, staticCatalog{entry: entry}, map[string]string{"domain": "yourco", "org": "other"})
}

type staticCatalog struct {
	entry catalogdomain.MCPServer
}

func (c staticCatalog) GetByCode(code string) (catalogdomain.MCPServer, bool) {
	if code != c.entry.Code {
		return catalogdomain.MCPServer{}, false
	}
	return c.entry, true
}

func manualTenantRegistry(t *testing.T, urlTemplate, code, authorize, token string) *registrydomain.Registry {
	t.Helper()
	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "tenant", "", &registrydomain.MCPTarget{
		Code:         code,
		URL:          urlTemplate,
		URLVariables: []registrydomain.MCPURLVariable{{Name: "domain", Required: true}},
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     code,
			Registration: registrydomain.RegistrationManual,
			ClientID:     "cid",
			ClientSecret: "admin-secret",
			AuthorizeURL: authorize,
			TokenURL:     token,
			Resource:     urlTemplate,
		},
	})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	return reg
}

func assertCatalogStartRefused(t *testing.T, reg *registrydomain.Registry, cat catalogByCode, values map[string]string) {
	t.Helper()
	registrar := &fixedRegistrar{}
	svc := templatedConnectCatalog(t, reg, values, registrar, cat)
	ticket, err := svc.CreateTicket(context.Background(), reg.GatewayID, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	started, err := svc.Start(context.Background(), "https://gw.example.com", "https://gw.example.com", ticket, reg.MCPTarget.Auth.Provider, "")
	if err == nil || started != nil {
		t.Fatalf("Start = %+v, err = %v; want no redirect", started, err)
	}
	if !errors.Is(err, oauth.ErrOAuthURLHost) {
		t.Fatalf("err = %v, want host refusal", err)
	}
	if len(registrar.discovered) != 0 {
		t.Fatalf("discovery ran: %v", registrar.discovered)
	}
}

func wholeHostManualRegistry(t *testing.T, suffix []string, options []registrydomain.MCPURLVariableOption, authorize, token string) *registrydomain.Registry {
	t.Helper()
	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "snowflake", "", &registrydomain.MCPTarget{
		Code: "com.snowflake/mcp",
		URL:  "https://{account_url}/mcp",
		URLVariables: []registrydomain.MCPURLVariable{{
			Name:       "account_url",
			Required:   true,
			HostSuffix: suffix,
			Options:    options,
		}},
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     "com.snowflake/mcp",
			Registration: registrydomain.RegistrationManual,
			ClientID:     "cid",
			ClientSecret: "admin-secret",
			Resource:     "https://{account_url}/mcp",
		},
	})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	pinManual(reg, authorize, token, "admin-secret")
	return reg
}

func pinManual(reg *registrydomain.Registry, authorize, token, secret string) {
	reg.MCPTarget.Auth.Registration = registrydomain.RegistrationManual
	reg.MCPTarget.Auth.ClientID = "cid"
	reg.MCPTarget.Auth.ClientSecret = secret
	reg.MCPTarget.Auth.AuthorizeURL = authorize
	reg.MCPTarget.Auth.TokenURL = token
}

func assertWholeHostSecretStays(t *testing.T, reg *registrydomain.Registry, values map[string]string, registrar oauth.UpstreamRegistrar) {
	t.Helper()
	if registrar == nil {
		registrar = &fixedRegistrar{}
	}
	assertNoRedirect(t, reg, values, registrar, oauth.ErrOAuthURLHost)

	refreshCtx := identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "alice"})
	svc := templatedConnect(t, reg, values, registrar)
	refreshed, err := svc.RefreshAuth(refreshCtx, reg.GatewayID, reg)
	if err == nil || refreshed != nil {
		t.Fatalf("RefreshAuth = %+v, err = %v; want no config", refreshed, err)
	}
	if !errors.Is(err, oauth.ErrOAuthURLHost) {
		t.Fatalf("RefreshAuth err = %v, want host refusal", err)
	}
	if strings.Contains(err.Error(), "admin-secret") || strings.Contains(err.Error(), "evil.example") {
		t.Fatalf("error leaks the secret or the rejected host: %v", err)
	}
}

func assertNoRedirect(t *testing.T, reg *registrydomain.Registry, values map[string]string, registrar oauth.UpstreamRegistrar, want error) {
	t.Helper()
	svc := templatedConnect(t, reg, values, registrar)
	ticket, err := svc.CreateTicket(context.Background(), reg.GatewayID, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	started, err := svc.Start(context.Background(), "https://gw.example.com", "https://gw.example.com", ticket, reg.MCPTarget.Auth.Provider, "")
	if err == nil || started != nil {
		loc := ""
		if started != nil {
			loc = started.Location
		}
		t.Fatalf("Start = %q, err = %v; want no redirect", loc, err)
	}
	if !errors.Is(err, want) || !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("err = %v, want %v", err, want)
	}
	if strings.Contains(err.Error(), "admin-secret") || strings.Contains(err.Error(), "evil.example") || strings.Contains(err.Error(), "evil.test") {
		t.Fatalf("error leaks the secret or the rejected host: %v", err)
	}
}

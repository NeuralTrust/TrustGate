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
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// flippingURLValues returns a different install map on every read. A flow that
// resolves the upstream once sees only the first map; a second read would see
// the host that launders the suffix check (ENG-2238).
type flippingURLValues struct {
	values []map[string]string
	calls  int
}

func (f *flippingURLValues) Values(context.Context, ids.GatewayID, string, *registrydomain.Registry) (map[string]string, error) {
	i := f.calls
	f.calls++
	if i >= len(f.values) {
		i = len(f.values) - 1
	}
	src := f.values[i]
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out, nil
}

// discoveredHostRegistrar records the upstream discovery was asked for and, when
// that host is the sink, points the token and revocation endpoints at a local
// server that fails the test if a client secret is posted.
type discoveredHostRegistrar struct {
	discovered []string
	sinkHost   string
	sink       *httptest.Server
	cached     *RegisteredClient
	hits       int
	posted     string
}

func (r *discoveredHostRegistrar) Discover(_ context.Context, upstream string) (*UpstreamAuthServer, error) {
	r.discovered = append(r.discovered, upstream)
	host := upstreamHost(upstream)
	authorize := "https://" + host + "/authorize"
	token := "https://" + host + "/token"
	revoke := "https://" + host + "/revoke"
	if r.sink != nil && host == r.sinkHost {
		authorize = r.sink.URL + "/authorize"
		token = r.sink.URL + "/token"
		revoke = r.sink.URL + "/revoke"
	}
	return &UpstreamAuthServer{
		AuthorizationEndpoint: authorize,
		TokenEndpoint:         token,
		RevocationEndpoint:    revoke,
		ValidatedIssuer:       "https://" + host,
	}, nil
}

func (r *discoveredHostRegistrar) EnsureClient(context.Context, string, *UpstreamAuthServer, string) (*RegisteredClient, error) {
	return nil, errors.New("resolve-once test must not register a client")
}

func (r *discoveredHostRegistrar) CachedClient(context.Context, string) (*RegisteredClient, error) {
	return r.cached, nil
}

func (r *discoveredHostRegistrar) DropCachedClient(context.Context, string, string) error {
	return nil
}

func (r *discoveredHostRegistrar) handler(w http.ResponseWriter, req *http.Request) {
	r.hits++
	if err := req.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if secret := req.Form.Get("client_secret"); secret != "" {
		r.posted = secret
	}
	if _, password, ok := req.BasicAuth(); ok && password != "" {
		r.posted = password
	}
	w.WriteHeader(http.StatusOK)
}

func upstreamHost(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil {
		return ""
	}
	return parsed.Hostname()
}

func flippingManualRegistry() *registrydomain.Registry {
	return &registrydomain.Registry{Type: registrydomain.TypeMCP, MCPTarget: &registrydomain.MCPTarget{
		Code:         "com.snowflake/mcp",
		URL:          "https://{account_url}/mcp",
		URLVariables: []registrydomain.MCPURLVariable{{Name: "account_url", Required: true}},
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     "com.snowflake/mcp",
			Registration: registrydomain.RegistrationManual,
			ClientID:     "admin-id",
			ClientSecret: "admin-secret",
		},
	}}
}

func flippingAutoRegistry() *registrydomain.Registry {
	reg := flippingManualRegistry()
	reg.MCPTarget.Auth.Registration = registrydomain.RegistrationAuto
	reg.MCPTarget.Auth.ClientID = ""
	reg.MCPTarget.Auth.ClientSecret = ""
	return reg
}

type resolvedFlow struct {
	name string
	run  func(s *connectService, ctx context.Context, gw ids.GatewayID, reg *registrydomain.Registry) (secret, contacted string, err error)
}

func manualResolveFlows() []resolvedFlow {
	return []resolvedFlow{
		{
			name: "connect",
			run: func(s *connectService, ctx context.Context, gw ids.GatewayID, reg *registrydomain.Registry) (string, string, error) {
				auth, err := s.effectiveAuth(ctx, "https://gw.example.com", gw, "alice", reg)
				if auth == nil {
					return "", "", err
				}
				return auth.ClientSecret, auth.TokenURL, err
			},
		},
		{
			name: "exchange",
			run: func(s *connectService, ctx context.Context, gw ids.GatewayID, reg *registrydomain.Registry) (string, string, error) {
				auth, err := s.exchangeAuth(ctx, "https://gw.example.com", gw, "alice", reg, "admin-id")
				if auth == nil {
					return "", "", err
				}
				return auth.ClientSecret, auth.TokenURL, err
			},
		},
		{
			name: "refresh",
			run: func(s *connectService, ctx context.Context, gw ids.GatewayID, reg *registrydomain.Registry) (string, string, error) {
				auth, err := s.RefreshAuth(ctx, gw, reg)
				if auth == nil {
					return "", "", err
				}
				return auth.ClientSecret, auth.TokenURL, err
			},
		},
		{
			name: "revocation",
			run: func(s *connectService, ctx context.Context, gw ids.GatewayID, reg *registrydomain.Registry) (string, string, error) {
				material, err := s.RevocationMaterial(ctx, gw, "alice", reg)
				if material == nil {
					return "", "", err
				}
				return material.ClientSecret, material.RevocationEndpoint, err
			},
		},
	}
}

func newFlippingService(reg *registrydomain.Registry, first, second string, cached *RegisteredClient) (*connectService, *flippingURLValues, *discoveredHostRegistrar) {
	flip := &flippingURLValues{values: []map[string]string{
		{"account_url": first},
		{"account_url": second},
	}}
	registrar := &discoveredHostRegistrar{cached: cached}
	registrar.sink = httptest.NewServer(http.HandlerFunc(registrar.handler))
	// The sink stands in for the host that must not receive the secret: the
	// second read. Discovery of that host rewrites its endpoints onto the sink.
	registrar.sinkHost = second
	svc := &connectService{
		registrar: registrar,
		urlValues: flip,
		catalog:   snowflakeSuffixCatalog("*.snowflakecomputing.com"),
	}
	return svc, flip, registrar
}

// The first install value is an unbound host. The second is a catalog suffix
// that would let the host check pass. Discovery and the check must share the
// first resolution, so the secret is not returned and nothing is posted to the
// host from the second read.
func TestInstallValuesCannotRetargetAfterDiscovery(t *testing.T) {
	t.Parallel()
	const (
		first  = "evil.example"
		second = "acme.snowflakecomputing.com"
		secret = "admin-secret"
	)
	for _, flow := range manualResolveFlows() {
		t.Run(flow.name, func(t *testing.T) {
			t.Parallel()
			reg := flippingManualRegistry()
			svc, flip, registrar := newFlippingService(reg, first, second, nil)
			t.Cleanup(registrar.sink.Close)
			ctx := identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "alice"})

			gotSecret, contacted, err := flow.run(svc, ctx, ids.New[ids.GatewayKind](), reg)
			if !errors.Is(err, ErrUpstreamSetupRequired) || gotSecret != "" || contacted != "" {
				t.Fatalf("secret = %q, contacted = %q, err = %v; want the employee host ignored", gotSecret, contacted, err)
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), second) || strings.Contains(err.Error(), first) {
				t.Fatalf("error leaks the secret or a host: %v", err)
			}
			if flip.calls != 1 {
				t.Fatalf("install values read %d times, want the first resolution only", flip.calls)
			}
			if len(registrar.discovered) != 0 {
				t.Fatalf("discovered %v, want the employee host never contacted", registrar.discovered)
			}
			if registrar.hits != 0 || registrar.posted != "" {
				t.Fatalf("second host saw %d requests, posted secret %q", registrar.hits, registrar.posted)
			}
		})
	}
}

// The first value is the vendor host the catalog allows. A later read names an
// unbound host. The flow keeps the first host: the secret is not aimed at the
// second one, and that host is not discovered.
func TestInstallValuesKeepTheFirstResolution(t *testing.T) {
	t.Parallel()
	const (
		first  = "acme.snowflakecomputing.com"
		second = "evil.example"
		secret = "admin-secret"
	)
	for _, flow := range manualResolveFlows() {
		t.Run(flow.name, func(t *testing.T) {
			t.Parallel()
			reg := flippingManualRegistry()
			reg.MCPTarget.URL = "https://" + first + "/mcp"
			svc, flip, registrar := newFlippingService(reg, first, second, nil)
			t.Cleanup(registrar.sink.Close)
			ctx := identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "alice"})

			gotSecret, contacted, err := flow.run(svc, ctx, ids.New[ids.GatewayKind](), reg)
			if err != nil {
				t.Fatalf("flow: %v", err)
			}
			if gotSecret != secret {
				t.Fatalf("secret = %q", gotSecret)
			}
			if upstreamHost(contacted) != first {
				t.Fatalf("contacted %q, want the first host", contacted)
			}
			if strings.Contains(contacted, second) {
				t.Fatalf("secret aimed at the second host: %s", contacted)
			}
			if flip.calls != 1 {
				t.Fatalf("install values read %d times, want the first resolution only", flip.calls)
			}
			if len(registrar.discovered) != 1 || registrar.discovered[0] != "https://"+first+"/mcp" {
				t.Fatalf("discovered %v, want only the first host", registrar.discovered)
			}
			if registrar.hits != 0 || registrar.posted != "" {
				t.Fatalf("second host saw %d requests, posted secret %q", registrar.hits, registrar.posted)
			}
		})
	}
}

// Dynamic registration skips the host check on connect and refresh. Revocation
// still refuses an unbound host, and that check has to use the resolution
// discovery used. A second read of a vendor suffix must not release the cached
// secret toward the host discovered first.
func TestRevocationUsesTheDiscoveryResolution(t *testing.T) {
	t.Parallel()
	const (
		first  = "evil.example"
		second = "acme.snowflakecomputing.com"
		secret = "dcr-secret"
	)
	reg := flippingAutoRegistry()
	svc, flip, registrar := newFlippingService(reg, first, second, &RegisteredClient{
		ClientID:     "dcr-id",
		ClientSecret: secret,
	})
	t.Cleanup(registrar.sink.Close)

	material, err := svc.RevocationMaterial(context.Background(), ids.New[ids.GatewayKind](), "alice", reg)
	if !errors.Is(err, ErrUpstreamSetupRequired) || material != nil {
		t.Fatalf("material = %+v, err = %v; want the employee host ignored", material, err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), second) || strings.Contains(err.Error(), first) {
		t.Fatalf("error leaks the secret or a host: %v", err)
	}
	if flip.calls != 1 {
		t.Fatalf("install values read %d times, want the first resolution only", flip.calls)
	}
	if len(registrar.discovered) != 0 {
		t.Fatalf("discovered %v, want the employee host never contacted", registrar.discovered)
	}
	if registrar.hits != 0 || registrar.posted != "" {
		t.Fatalf("second host saw %d requests, posted secret %q", registrar.hits, registrar.posted)
	}
}

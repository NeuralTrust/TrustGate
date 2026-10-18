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
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/app/mcpoauth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type revocationRegistrar struct {
	meta       *UpstreamAuthServer
	cached     *RegisteredClient
	discovered []string
	ensured    int
}

func (r *revocationRegistrar) Discover(_ context.Context, upstream string) (*UpstreamAuthServer, error) {
	r.discovered = append(r.discovered, upstream)
	return r.meta, nil
}

func (r *revocationRegistrar) EnsureClient(context.Context, string, *UpstreamAuthServer, string) (*RegisteredClient, error) {
	r.ensured++
	return nil, errors.New("revocation must not register a client")
}

func (r *revocationRegistrar) CachedClient(context.Context, string) (*RegisteredClient, error) {
	return r.cached, nil
}

func (r *revocationRegistrar) DropCachedClient(context.Context, string, string) error {
	return nil
}

func gmailRegistry(auth *registrydomain.MCPAuth) *registrydomain.Registry {
	return &registrydomain.Registry{
		Type: registrydomain.TypeMCP,
		MCPTarget: &registrydomain.MCPTarget{
			Code: mcpoauth.GmailCode,
			URL:  "https://gmail.example/mcp",
			Auth: auth,
		},
	}
}

// Pinned registries do not revoke. The registry config has no revocation URL,
// and uninstall does not discover one from the upstream.
func TestRevocationMaterialPinnedEndpointsSkipDiscovery(t *testing.T) {
	registrar := &revocationRegistrar{meta: &UpstreamAuthServer{
		TokenEndpoint:      "https://evil.example/token",
		RevocationEndpoint: "https://evil.example/revoke",
	}}
	s := &connectService{registrar: registrar, sharedOAuth: mcpoauth.NewGoogleWorkspace("platform-id", "platform-secret")}
	reg := gmailRegistry(&registrydomain.MCPAuth{
		Mode:         registrydomain.MCPAuthModeForwarded,
		Provider:     mcpoauth.GmailCode,
		ClientID:     "configured-id",
		ClientSecret: "configured-secret",
		AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
	})

	material, err := s.RevocationMaterial(context.Background(), ids.New[ids.GatewayKind](), "ana", reg)
	if err != nil {
		t.Fatalf("RevocationMaterial: %v", err)
	}
	if len(registrar.discovered) != 0 {
		t.Fatalf("pinned endpoints discovered %v", registrar.discovered)
	}
	if material.RevocationEndpoint != "" {
		t.Fatalf("pinned endpoints produced revocation endpoint %q", material.RevocationEndpoint)
	}
	if material.TokenURL != "https://oauth2.googleapis.com/token" {
		t.Fatalf("token url = %q", material.TokenURL)
	}
	if material.ClientSecret != "configured-secret" {
		t.Fatalf("client secret = %q", material.ClientSecret)
	}
}

func TestRevocationMaterialWithholdsSharedSecret(t *testing.T) {
	registrar := &revocationRegistrar{meta: &UpstreamAuthServer{
		AuthorizationEndpoint: "https://evil.example/authorize",
		TokenEndpoint:         "https://evil.example/token",
		RevocationEndpoint:    "https://evil.example/revoke",
	}}
	s := &connectService{registrar: registrar, sharedOAuth: mcpoauth.NewGoogleWorkspace("platform-id", "platform-secret")}
	reg := gmailRegistry(&registrydomain.MCPAuth{
		Mode:     registrydomain.MCPAuthModeForwarded,
		Provider: mcpoauth.GmailCode,
	})

	material, err := s.RevocationMaterial(context.Background(), ids.New[ids.GatewayKind](), "ana", reg)
	if err != nil {
		t.Fatalf("RevocationMaterial: %v", err)
	}
	if len(registrar.discovered) != 1 || registrar.discovered[0] != "https://gmail.example/mcp" {
		t.Fatalf("discovered %v", registrar.discovered)
	}
	if material.ClientSecret != "" {
		t.Fatalf("shared secret = %q, want it withheld", material.ClientSecret)
	}
	if material.ClientID != "platform-id" {
		t.Fatalf("client id = %q", material.ClientID)
	}
	if material.TokenURL != "https://evil.example/token" || material.RevocationEndpoint != "https://evil.example/revoke" {
		t.Fatalf("material = %+v", material)
	}
}

// Uninstall posts the admin client secret to the discovered revocation
// endpoint, so a user-chosen host is refused here as it is on refresh.
func TestRevocationMaterialRefusesAUserChosenHost(t *testing.T) {
	registrar := &revocationRegistrar{meta: &UpstreamAuthServer{
		AuthorizationEndpoint: "https://evil.example/authorize",
		TokenEndpoint:         "https://evil.example/token",
		RevocationEndpoint:    "https://evil.example/revoke",
	}}
	s := &connectService{registrar: registrar}
	reg := &registrydomain.Registry{Type: registrydomain.TypeMCP, MCPTarget: &registrydomain.MCPTarget{
		URL:            "https://{account_url}/mcp",
		URLVariables:   []registrydomain.MCPURLVariable{{Name: "account_url", Required: true}},
		InstanceConfig: map[string]string{"account_url": "evil.example"},
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     "com.snowflake/mcp",
			Registration: registrydomain.RegistrationManual,
			ClientID:     "admin-id",
			ClientSecret: "admin-secret",
		},
	}}

	material, err := s.RevocationMaterial(context.Background(), ids.New[ids.GatewayKind](), "", reg)
	if !errors.Is(err, ErrOAuthURLHost) || material != nil {
		t.Fatalf("material = %+v, err = %v; want host refusal", material, err)
	}
}

// Dynamic registration skips the host check on connect and refresh: that
// client was minted by the server discovery found. Revocation posts the cached
// secret to the endpoint that document names, so an unbound user-chosen host
// is refused and the secret is not returned.
func TestRevocationMaterialRefusesDCRSecretOnUserChosenHost(t *testing.T) {
	registrar := &revocationRegistrar{
		meta: &UpstreamAuthServer{
			AuthorizationEndpoint: "https://evil.example/authorize",
			TokenEndpoint:         "https://evil.example/token",
			RevocationEndpoint:    "https://evil.example/revoke",
			ValidatedIssuer:       "https://evil.example",
		},
		cached: &RegisteredClient{ClientID: "dcr-id", ClientSecret: "dcr-secret"},
	}
	s := &connectService{registrar: registrar}
	reg := wholeHostAutoRegistry("evil.example")

	material, err := s.RevocationMaterial(context.Background(), ids.New[ids.GatewayKind](), "", reg)
	if !errors.Is(err, ErrOAuthURLHost) || material != nil {
		t.Fatalf("material = %+v, err = %v; want host refusal", material, err)
	}
	if strings.Contains(err.Error(), "dcr-secret") || strings.Contains(err.Error(), "evil.example") {
		t.Fatalf("error leaks the secret or the rejected host: %v", err)
	}

	auth, refreshErr := s.RefreshAuth(context.Background(), ids.New[ids.GatewayKind](), reg)
	if refreshErr != nil {
		t.Fatalf("RefreshAuth: %v", refreshErr)
	}
	if auth.ClientSecret != "dcr-secret" || auth.TokenURL != "https://evil.example/token" {
		t.Fatalf("refresh auth = %+v", auth)
	}
}

// A catalog suffix is a bound, so revocation of a dynamically registered
// client on that vendor host still returns the secret and the endpoint.
func TestRevocationMaterialAllowsDCROnCatalogSuffix(t *testing.T) {
	const host = "acme.snowflakecomputing.com"
	registrar := &revocationRegistrar{
		meta: &UpstreamAuthServer{
			AuthorizationEndpoint: "https://" + host + "/authorize",
			TokenEndpoint:         "https://" + host + "/token",
			RevocationEndpoint:    "https://" + host + "/revoke",
			ValidatedIssuer:       "https://" + host,
		},
		cached: &RegisteredClient{ClientID: "dcr-id", ClientSecret: "dcr-secret"},
	}
	s := &connectService{registrar: registrar, catalog: snowflakeSuffixCatalog("*.snowflakecomputing.com")}
	reg := wholeHostAutoRegistry(host)
	reg.MCPTarget.Code = "com.snowflake/mcp"

	material, err := s.RevocationMaterial(context.Background(), ids.New[ids.GatewayKind](), "", reg)
	if err != nil {
		t.Fatalf("RevocationMaterial: %v", err)
	}
	if material.ClientSecret != "dcr-secret" || material.RevocationEndpoint != "https://"+host+"/revoke" {
		t.Fatalf("material = %+v", material)
	}
}

// A literal registrable domain is not a user-chosen host, so revocation
// proceeds on the scheme, host, and port check alone.
func TestRevocationMaterialAllowsDCROnPinnedRegistrableDomain(t *testing.T) {
	registrar := &revocationRegistrar{
		meta: &UpstreamAuthServer{
			AuthorizationEndpoint: "https://acme.aha.io/oauth/authorize",
			TokenEndpoint:         "https://acme.aha.io/oauth/token",
			RevocationEndpoint:    "https://acme.aha.io/oauth/revoke",
			ValidatedIssuer:       "https://acme.aha.io",
		},
		cached: &RegisteredClient{ClientID: "dcr-id", ClientSecret: "dcr-secret"},
	}
	s := &connectService{registrar: registrar}
	reg := &registrydomain.Registry{Type: registrydomain.TypeMCP, MCPTarget: &registrydomain.MCPTarget{
		URL:            "https://{domain}.aha.io/api/v1/mcp",
		URLVariables:   []registrydomain.MCPURLVariable{{Name: "domain", Required: true}},
		InstanceConfig: map[string]string{"domain": "acme"},
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     "io.aha/mcp",
			Registration: registrydomain.RegistrationAuto,
		},
	}}

	material, err := s.RevocationMaterial(context.Background(), ids.New[ids.GatewayKind](), "", reg)
	if err != nil {
		t.Fatalf("RevocationMaterial: %v", err)
	}
	if material.RevocationEndpoint != "https://acme.aha.io/oauth/revoke" || material.ClientSecret != "dcr-secret" {
		t.Fatalf("material = %+v", material)
	}
}

func wholeHostAutoRegistry(host string) *registrydomain.Registry {
	return &registrydomain.Registry{Type: registrydomain.TypeMCP, MCPTarget: &registrydomain.MCPTarget{
		URL:            "https://{account_url}/mcp",
		URLVariables:   []registrydomain.MCPURLVariable{{Name: "account_url", Required: true}},
		InstanceConfig: map[string]string{"account_url": host},
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     "com.snowflake/mcp",
			Registration: registrydomain.RegistrationAuto,
		},
	}}
}

func TestRevocationMaterialAutoUsesCachedClientOnly(t *testing.T) {
	registrar := &revocationRegistrar{
		meta: &UpstreamAuthServer{
			TokenEndpoint:      "https://as.example/token",
			RevocationEndpoint: "https://as.example/revoke",
			ValidatedIssuer:    "https://as.example",
		},
		cached: &RegisteredClient{ClientID: "dcr-client", ClientSecret: "dcr-secret"},
	}
	s := &connectService{registrar: registrar}
	reg := gmailRegistry(&registrydomain.MCPAuth{
		Mode:         registrydomain.MCPAuthModeForwarded,
		Provider:     mcpoauth.GmailCode,
		Registration: registrydomain.RegistrationAuto,
		ClientID:     "admin-id",
		ClientSecret: "admin-secret",
	})
	gw := ids.New[ids.GatewayKind]()

	material, err := s.RevocationMaterial(context.Background(), gw, "ana", reg)
	if err != nil {
		t.Fatalf("RevocationMaterial: %v", err)
	}
	if registrar.ensured != 0 {
		t.Fatal("auto revocation registered a client")
	}
	if material.ClientID != "dcr-client" || material.ClientSecret != "dcr-secret" {
		t.Fatalf("material client = %s / %s", material.ClientID, material.ClientSecret)
	}
	if material.ClientSecret == "admin-secret" {
		t.Fatal("admin client secret was used")
	}

	registrar.cached = nil
	if _, err := s.RevocationMaterial(context.Background(), gw, "ana", reg); !errors.Is(err, ErrNoRegisteredClient) {
		t.Fatalf("cache miss = %v, want ErrNoRegisteredClient", err)
	}
}

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

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

type fakeCredentialFinder struct {
	oauth2 []*authdomain.Auth
	err    error
}

func (f *fakeCredentialFinder) OAuth2Auths(context.Context) ([]*authdomain.Auth, error) {
	return f.oauth2, f.err
}

func (f *fakeCredentialFinder) OAuth2AuthsForGateway(_ context.Context, gatewayID ids.GatewayID) ([]*authdomain.Auth, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make([]*authdomain.Auth, 0, len(f.oauth2))
	for _, a := range f.oauth2 {
		if a.GatewayID == gatewayID {
			out = append(out, a)
		}
	}
	return out, nil
}

func (f *fakeCredentialFinder) MTLSAuths(context.Context) ([]*authdomain.Auth, error) {
	return nil, nil
}

func oauth2Auth(t *testing.T, cfg authdomain.OAuth2Config) *authdomain.Auth {
	t.Helper()
	c := cfg
	if c.JWKSURL == "" {
		c.JWKSURL = c.Issuer + "/jwks"
	}
	return &authdomain.Auth{Config: authdomain.Config{OAuth2: &c}}
}

func TestProtectedResourceMetadata(t *testing.T) {
	t.Parallel()
	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{
		oauth2Auth(t, authdomain.OAuth2Config{Issuer: "https://idp-a.example.com", RequiredScopes: []string{"mcp:use", "openid"}}),
		oauth2Auth(t, authdomain.OAuth2Config{Issuer: "https://idp-b.example.com", RequiredScopes: []string{"mcp:use"}}),
	}}
	svc := NewMetadataService(finder, nil, nil, newMemFlowStore())

	meta, err := svc.ProtectedResource(context.Background(), "https://gw.example.com", "https://gw.example.com/v1/mcp/dev")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.Resource != "https://gw.example.com/v1/mcp/dev" {
		t.Fatalf("unexpected resource: %s", meta.Resource)
	}
	// The gateway brokers the flow, so it advertises itself as the AS.
	if len(meta.AuthorizationServers) != 1 || meta.AuthorizationServers[0] != "https://gw.example.com" {
		t.Fatalf("expected the gateway as authorization server, got %v", meta.AuthorizationServers)
	}
	if len(meta.ScopesSupported) != 2 {
		t.Fatalf("expected deduplicated scopes [mcp:use openid], got %v", meta.ScopesSupported)
	}
	if meta.BearerMethodsSupported[0] != "header" {
		t.Fatalf("expected header bearer method, got %v", meta.BearerMethodsSupported)
	}
}

// A resource that maps to a consumer advertises only that consumer's scopes,
// not the union across tenants.
func TestProtectedResourceMetadataScopedByResource(t *testing.T) {
	t.Parallel()
	authA := enabledOAuth2Auth(t, authdomain.OAuth2Config{Issuer: "https://idp-a.example.com", RequiredScopes: []string{"tenant-a:use"}})
	authB := enabledOAuth2Auth(t, authdomain.OAuth2Config{Issuer: "https://idp-b.example.com", RequiredScopes: []string{"tenant-b:use"}})
	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{authA, authB}}
	paths := &fakePathResolver{byPath: map[string][]appconsumer.PathMatch{
		"/v1/mcp/tenant-b": {{GatewayID: authB.GatewayID, Auths: []*authdomain.Auth{authB}}},
	}}
	svc := NewMetadataService(finder, paths, nil, newMemFlowStore())

	meta, err := svc.ProtectedResource(context.Background(), "https://gw.example.com", "https://gw.example.com/v1/mcp/tenant-b")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(meta.ScopesSupported) != 1 || meta.ScopesSupported[0] != "tenant-b:use" {
		t.Fatalf("expected tenant B's scopes only, got %v", meta.ScopesSupported)
	}

	// Unknown path: fall back to the union.
	meta, err = svc.ProtectedResource(context.Background(), "https://gw.example.com", "https://gw.example.com/v1/mcp/unknown")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(meta.ScopesSupported) != 2 {
		t.Fatalf("expected union of scopes for unknown resource, got %v", meta.ScopesSupported)
	}
}

func TestProtectedResourceMetadataWithoutIdP(t *testing.T) {
	t.Parallel()
	svc := NewMetadataService(&fakeCredentialFinder{}, nil, nil, newMemFlowStore())
	meta, err := svc.ProtectedResource(context.Background(), "https://gw.example.com", "https://gw.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(meta.AuthorizationServers) != 0 {
		t.Fatalf("expected no authorization servers, got %v", meta.AuthorizationServers)
	}
}

func TestAuthorizationServerMetadataIsGatewayFacade(t *testing.T) {
	t.Parallel()
	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{
		oauth2Auth(t, authdomain.OAuth2Config{Issuer: "https://idp.example.com", RequiredScopes: []string{"mcp.access"}}),
	}}
	svc := NewMetadataService(finder, nil, nil, newMemFlowStore())

	doc, err := svc.AuthorizationServer(context.Background(), "https://gw.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc["issuer"] != "https://gw.example.com" {
		t.Fatalf("expected gateway issuer, got %v", doc["issuer"])
	}
	if doc["authorization_endpoint"] != "https://gw.example.com/oauth/authorize" {
		t.Fatalf("unexpected authorization_endpoint: %v", doc["authorization_endpoint"])
	}
	if doc["token_endpoint"] != "https://gw.example.com/oauth/token" {
		t.Fatalf("unexpected token_endpoint: %v", doc["token_endpoint"])
	}
	if doc["registration_endpoint"] != "https://gw.example.com/oauth/register" {
		t.Fatalf("unexpected registration_endpoint: %v", doc["registration_endpoint"])
	}
}

func TestAuthorizationServerMetadataErrors(t *testing.T) {
	t.Parallel()

	svc := NewMetadataService(&fakeCredentialFinder{}, nil, nil, newMemFlowStore())
	if _, err := svc.AuthorizationServer(context.Background(), "https://gw.example.com"); !errors.Is(err, ErrNoAuthorizationServer) {
		t.Fatalf("expected ErrNoAuthorizationServer, got %v", err)
	}

	// Multiple issuers no longer block the document: the gateway's own
	// endpoints are IdP-independent and the resource indicator selects the
	// IdP per request.
	svc = NewMetadataService(&fakeCredentialFinder{oauth2: []*authdomain.Auth{
		oauth2Auth(t, authdomain.OAuth2Config{Issuer: "https://idp-a.example.com"}),
		oauth2Auth(t, authdomain.OAuth2Config{Issuer: "https://idp-b.example.com"}),
	}}, nil, nil, newMemFlowStore())
	doc, err := svc.AuthorizationServer(context.Background(), "https://gw.example.com")
	if err != nil {
		t.Fatalf("expected metadata with multiple issuers, got %v", err)
	}
	if doc["issuer"] != "https://gw.example.com" {
		t.Fatalf("unexpected issuer: %v", doc["issuer"])
	}
}

func TestRegisterClient(t *testing.T) {
	t.Parallel()
	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{
		oauth2Auth(t, authdomain.OAuth2Config{Issuer: "https://idp-a.example.com"}), // no client_id, skipped
		oauth2Auth(t, authdomain.OAuth2Config{Issuer: "https://idp-b.example.com", ClientID: "mcp-public-client"}),
	}}
	store := newMemFlowStore()
	svc := NewMetadataService(finder, nil, nil, store)

	res, err := svc.RegisterClient(context.Background(), RegisterRequest{
		RedirectURIs: []string{"cursor://anysphere.cursor-mcp/oauth/callback"},
		ClientName:   "Cursor",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(res.ClientID, "agw-") {
		t.Fatalf("expected a gateway-issued client_id, got %s", res.ClientID)
	}
	if res.TokenEndpointAuthMethod != "none" {
		t.Fatalf("expected public client, got %s", res.TokenEndpointAuthMethod)
	}
	if len(res.RedirectURIs) != 1 || res.RedirectURIs[0] != "cursor://anysphere.cursor-mcp/oauth/callback" {
		t.Fatalf("expected redirect_uris echoed, got %v", res.RedirectURIs)
	}
	saved, err := store.GetGatewayClient(context.Background(), res.ClientID)
	if err != nil || saved == nil {
		t.Fatalf("expected persisted registration, got %v (err %v)", saved, err)
	}
	if saved.RedirectURIs[0] != "cursor://anysphere.cursor-mcp/oauth/callback" {
		t.Fatalf("persisted redirect_uris = %v", saved.RedirectURIs)
	}
}

func TestRegisterClientRejectsUnsafeRedirects(t *testing.T) {
	t.Parallel()
	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{
		oauth2Auth(t, authdomain.OAuth2Config{Issuer: "https://idp.example.com", ClientID: "mcp-public-client"}),
	}}
	svc := NewMetadataService(finder, nil, nil, newMemFlowStore())

	for _, uri := range []string{
		"http://attacker.example.com/cb",
		"javascript:alert(1)",
		"https://ok.example.com/cb#frag",
		"",
	} {
		if _, err := svc.RegisterClient(context.Background(), RegisterRequest{RedirectURIs: []string{uri}}); err == nil {
			t.Fatalf("expected rejection for redirect uri %q", uri)
		}
	}
}

func TestRegisterClientUnavailable(t *testing.T) {
	t.Parallel()
	svc := NewMetadataService(&fakeCredentialFinder{oauth2: []*authdomain.Auth{
		oauth2Auth(t, authdomain.OAuth2Config{Issuer: "https://idp.example.com"}),
	}}, nil, nil, newMemFlowStore())
	if _, err := svc.RegisterClient(context.Background(), RegisterRequest{}); !errors.Is(err, ErrRegistrationUnavailable) {
		t.Fatalf("expected ErrRegistrationUnavailable, got %v", err)
	}
}

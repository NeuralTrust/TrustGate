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
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
)

type stubRegistrar struct {
	meta       *appoauth.UpstreamAuthServer
	err        error
	cached     *appoauth.RegisteredClient
	ensured    int
	discovered []string
}

func (s *stubRegistrar) Discover(_ context.Context, upstream string) (*appoauth.UpstreamAuthServer, error) {
	s.discovered = append(s.discovered, upstream)
	if s.err != nil {
		return nil, s.err
	}
	return s.meta, nil
}

func (s *stubRegistrar) EnsureClient(context.Context, string, *appoauth.UpstreamAuthServer, string) (*appoauth.RegisteredClient, error) {
	s.ensured++
	return nil, errors.New("uninstall must not register a client")
}

func (s *stubRegistrar) CachedClient(context.Context, string) (*appoauth.RegisteredClient, error) {
	return s.cached, nil
}

type revokeCall struct {
	hint   string
	token  string
	user   string
	secret string
	form   url.Values
}

func revokeServer(t *testing.T, status int, calls *[]revokeCall) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
			t.Errorf("content-type = %s", ct)
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			t.Errorf("parse form: %v", err)
		}
		user, secret, _ := r.BasicAuth()
		*calls = append(*calls, revokeCall{
			hint:   form.Get("token_type_hint"),
			token:  form.Get("token"),
			user:   user,
			secret: secret,
			form:   form,
		})
		w.WriteHeader(status)
	}))
}

func revokeRegistry(rawURL string, auth *registrydomain.MCPAuth) *registrydomain.Registry {
	reg := &registrydomain.Registry{
		ID:   ids.New[ids.RegistryKind](),
		Type: registrydomain.TypeMCP,
		MCPTarget: &registrydomain.MCPTarget{
			URL:  rawURL,
			Code: "com.airtable/mcp",
			Auth: auth,
		},
	}
	return reg
}

func TestTokenRevokerSupportedProvider(t *testing.T) {
	t.Parallel()
	var calls []revokeCall
	srv := revokeServer(t, http.StatusOK, &calls)
	defer srv.Close()

	reg := revokeRegistry("https://mcp.airtable.com/mcp", &registrydomain.MCPAuth{
		Mode:         registrydomain.MCPAuthModeForwarded,
		Provider:     "com.airtable/mcp",
		ClientID:     "manual-client",
		ClientSecret: "manual-secret",
	})
	gw := ids.New[ids.GatewayKind]()
	cred, err := vaultdomain.NewCredential(gw, "ana", "com.airtable/mcp", "", "access-token", "refresh-token", nil, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	registrar := &stubRegistrar{meta: &appoauth.UpstreamAuthServer{RevocationEndpoint: srv.URL + "/revoke"}}
	err = NewTokenRevoker(registrar, srv.Client()).Revoke(context.Background(), gw, "ana", reg, cred)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if registrar.ensured != 0 {
		t.Fatal("revocation must not register a dynamic client")
	}
	if len(registrar.discovered) != 1 || registrar.discovered[0] != "https://mcp.airtable.com/mcp" {
		t.Fatalf("discovered = %v", registrar.discovered)
	}
	if len(calls) != 2 {
		t.Fatalf("revoke calls = %d, want refresh then access", len(calls))
	}
	if calls[0].hint != "refresh_token" || calls[0].token != "refresh-token" || calls[0].user != "manual-client" || calls[0].secret != "manual-secret" {
		t.Fatalf("refresh call = %+v", calls[0])
	}
	if calls[1].hint != "access_token" || calls[1].token != "access-token" {
		t.Fatalf("access call = %+v", calls[1])
	}

	t.Run("dynamic client is read from the cache", func(t *testing.T) {
		var cachedCalls []revokeCall
		cachedSrv := revokeServer(t, http.StatusOK, &cachedCalls)
		defer cachedSrv.Close()
		auto := revokeRegistry("https://mcp.amplitude.com/mcp", &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     "com.amplitude/mcp",
			Registration: registrydomain.RegistrationAuto,
		})
		cached := &stubRegistrar{
			meta:   &appoauth.UpstreamAuthServer{RevocationEndpoint: cachedSrv.URL},
			cached: &appoauth.RegisteredClient{ClientID: "dcr-client"},
		}
		accessOnly, err := vaultdomain.NewCredential(gw, "ana", "com.amplitude/mcp", "", "only-access", "", nil, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if err := NewTokenRevoker(cached, cachedSrv.Client()).Revoke(context.Background(), gw, "ana", auto, accessOnly); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		if cached.ensured != 0 {
			t.Fatal("cached dynamic client must not be re-registered or deleted")
		}
		if len(cachedCalls) != 1 || cachedCalls[0].hint != "access_token" || cachedCalls[0].token != "only-access" {
			t.Fatalf("calls = %+v", cachedCalls)
		}
		if cachedCalls[0].form.Get("client_id") != "dcr-client" || cachedCalls[0].user != "" {
			t.Fatalf("public client call = %+v", cachedCalls[0])
		}
	})
}

func TestTokenRevokerUnsupportedProvider(t *testing.T) {
	t.Parallel()
	var calls []revokeCall
	srv := revokeServer(t, http.StatusOK, &calls)
	defer srv.Close()
	reg := revokeRegistry("https://mcp.apify.com/mcp", &registrydomain.MCPAuth{
		Mode:     registrydomain.MCPAuthModeForwarded,
		Provider: "com.apify/mcp",
	})
	gw := ids.New[ids.GatewayKind]()
	cred, err := vaultdomain.NewCredential(gw, "ana", "com.apify/mcp", "", "access-token", "refresh-token", nil, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	registrar := &stubRegistrar{meta: &appoauth.UpstreamAuthServer{
		AuthorizationEndpoint: "https://auth.example.com/authorize",
		TokenEndpoint:         "https://auth.example.com/token",
	}}
	if err := NewTokenRevoker(registrar, srv.Client()).Revoke(context.Background(), gw, "ana", reg, cred); err != nil {
		t.Fatalf("unsupported provider must not fail: %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("unsupported provider posted %d revocations", len(calls))
	}
	if registrar.ensured != 0 {
		t.Fatal("unsupported provider must not register a client")
	}

	var doc appoauth.UpstreamAuthServer
	if err := json.Unmarshal([]byte(`{"revocation_endpoint":"https://auth.example.com/oauth/revoke"}`), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.RevocationEndpoint != "https://auth.example.com/oauth/revoke" {
		t.Fatalf("revocation_endpoint = %q", doc.RevocationEndpoint)
	}
}

func TestTokenRevokerVendorError(t *testing.T) {
	t.Parallel()
	var calls []revokeCall
	srv := revokeServer(t, http.StatusInternalServerError, &calls)
	defer srv.Close()
	reg := revokeRegistry("https://mcp.airtable.com/mcp", &registrydomain.MCPAuth{
		Mode:     registrydomain.MCPAuthModeForwarded,
		Provider: "com.airtable/mcp",
		ClientID: "manual-client",
	})
	gw := ids.New[ids.GatewayKind]()
	cred, err := vaultdomain.NewCredential(gw, "ana", providerFor(reg), "", "access-token", "refresh-token", nil, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	registrar := &stubRegistrar{meta: &appoauth.UpstreamAuthServer{RevocationEndpoint: srv.URL}}
	err = NewTokenRevoker(registrar, srv.Client()).Revoke(context.Background(), gw, "ana", reg, cred)
	if err == nil {
		t.Fatal("vendor error must be returned")
	}
	if strings.Contains(err.Error(), "access-token") || strings.Contains(err.Error(), "refresh-token") {
		t.Fatalf("vendor error leaked a token: %v", err)
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("error = %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("a failed refresh must not skip the access token, calls=%d", len(calls))
	}

	t.Run("discovery failure", func(t *testing.T) {
		broken := &stubRegistrar{err: errors.New("metadata unavailable")}
		err := NewTokenRevoker(broken, srv.Client()).Revoke(context.Background(), gw, "ana", reg, cred)
		if err == nil || !strings.Contains(err.Error(), "metadata unavailable") {
			t.Fatalf("discovery error = %v", err)
		}
		if strings.Contains(err.Error(), "access-token") {
			t.Fatalf("discovery error leaked a token: %v", err)
		}
	})
}

func providerFor(reg *registrydomain.Registry) string {
	return registrydomain.ForwardedVaultProvider(reg)
}

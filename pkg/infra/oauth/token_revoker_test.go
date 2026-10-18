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
	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard"
)

type stubRevocationAuth struct {
	material *appoauth.RevocationMaterial
	err      error
}

func (s *stubRevocationAuth) RevocationMaterial(context.Context, ids.GatewayID, string, *registrydomain.Registry) (*appoauth.RevocationMaterial, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.material, nil
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
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recordRevoke(t, w, r, status, calls)
	}))
}

func recordRevoke(t *testing.T, w http.ResponseWriter, r *http.Request, status int, calls *[]revokeCall) {
	t.Helper()
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
}

func materialFor(srv *httptest.Server, clientID, secret, method string) *appoauth.RevocationMaterial {
	return &appoauth.RevocationMaterial{
		ClientID:                clientID,
		ClientSecret:            secret,
		TokenEndpointAuthMethod: method,
		TokenURL:                srv.URL + "/token",
		RevocationEndpoint:      srv.URL + "/revoke",
	}
}

func revokeRegistry() *registrydomain.Registry {
	return &registrydomain.Registry{
		ID:   ids.New[ids.RegistryKind](),
		Type: registrydomain.TypeMCP,
		MCPTarget: &registrydomain.MCPTarget{
			URL:  "https://mcp.airtable.com/mcp",
			Code: "com.airtable/mcp",
			Auth: &registrydomain.MCPAuth{
				Mode:     registrydomain.MCPAuthModeForwarded,
				Provider: "com.airtable/mcp",
			},
		},
	}
}

func TestTokenRevokerSupportedProvider(t *testing.T) {
	t.Parallel()
	var calls []revokeCall
	srv := revokeServer(t, http.StatusOK, &calls)
	defer srv.Close()

	gw := ids.New[ids.GatewayKind]()
	cred, err := vaultdomain.NewCredential(gw, "ana", "com.airtable/mcp", "", "access-token", "refresh-token", nil, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	auth := &stubRevocationAuth{material: materialFor(srv, "manual-client", "manual-secret", "")}
	err = NewTokenRevoker(auth, srv.Client()).Revoke(context.Background(), gw, "ana", revokeRegistry(), cred)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
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

	t.Run("dynamic client is presented without a secret", func(t *testing.T) {
		var cachedCalls []revokeCall
		cachedSrv := revokeServer(t, http.StatusOK, &cachedCalls)
		defer cachedSrv.Close()
		accessOnly, err := vaultdomain.NewCredential(gw, "ana", "com.amplitude/mcp", "", "only-access", "", nil, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		cached := &stubRevocationAuth{material: materialFor(cachedSrv, "dcr-client", "", "")}
		if err := NewTokenRevoker(cached, cachedSrv.Client()).Revoke(context.Background(), gw, "ana", revokeRegistry(), accessOnly); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		if len(cachedCalls) != 1 || cachedCalls[0].hint != "access_token" || cachedCalls[0].token != "only-access" {
			t.Fatalf("calls = %+v", cachedCalls)
		}
		if cachedCalls[0].form.Get("client_id") != "dcr-client" || cachedCalls[0].user != "" || cachedCalls[0].form.Get("client_secret") != "" {
			t.Fatalf("public client call = %+v", cachedCalls[0])
		}
	})
}

func TestTokenRevokerUnsupportedProvider(t *testing.T) {
	t.Parallel()
	var calls []revokeCall
	srv := revokeServer(t, http.StatusOK, &calls)
	defer srv.Close()
	gw := ids.New[ids.GatewayKind]()
	cred, err := vaultdomain.NewCredential(gw, "ana", "com.apify/mcp", "", "access-token", "refresh-token", nil, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	auth := &stubRevocationAuth{material: &appoauth.RevocationMaterial{
		TokenURL: srv.URL + "/token",
	}}
	if err := NewTokenRevoker(auth, srv.Client()).Revoke(context.Background(), gw, "ana", revokeRegistry(), cred); err != nil {
		t.Fatalf("unsupported provider must not fail: %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("unsupported provider posted %d revocations", len(calls))
	}

	var doc appoauth.UpstreamAuthServer
	if err := json.Unmarshal([]byte(`{"revocation_endpoint":"https://auth.example.com/oauth/revoke"}`), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.RevocationEndpoint != "https://auth.example.com/oauth/revoke" {
		t.Fatalf("revocation_endpoint = %q", doc.RevocationEndpoint)
	}
}

func TestTokenRevokerSkipsOriginMismatch(t *testing.T) {
	t.Parallel()
	var calls []revokeCall
	srv := revokeServer(t, http.StatusOK, &calls)
	defer srv.Close()
	gw := ids.New[ids.GatewayKind]()
	cred, err := vaultdomain.NewCredential(gw, "ana", "com.airtable/mcp", "", "access-token", "refresh-token", nil, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	auth := &stubRevocationAuth{material: &appoauth.RevocationMaterial{
		ClientID:           "manual-client",
		ClientSecret:       "manual-secret",
		TokenURL:           "https://auth.example.com/token",
		RevocationEndpoint: srv.URL + "/revoke",
	}}
	if err := NewTokenRevoker(auth, srv.Client()).Revoke(context.Background(), gw, "ana", revokeRegistry(), cred); err != nil {
		t.Fatalf("origin mismatch must be skipped: %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("origin mismatch posted %d revocations", len(calls))
	}

	t.Run("neither the issuer nor the token endpoint", func(t *testing.T) {
		var missed []revokeCall
		miss := revokeServer(t, http.StatusOK, &missed)
		defer miss.Close()
		auth := &stubRevocationAuth{material: &appoauth.RevocationMaterial{
			ClientID:           "manual-client",
			ClientSecret:       "manual-secret",
			TokenURL:           "https://tokens.example/token",
			ValidatedIssuer:    "https://issuer.example",
			RevocationEndpoint: miss.URL + "/revoke",
		}}
		if err := NewTokenRevoker(auth, miss.Client()).Revoke(context.Background(), gw, "ana", revokeRegistry(), cred); err != nil {
			t.Fatalf("foreign origin must be skipped: %v", err)
		}
		if len(missed) != 0 {
			t.Fatalf("foreign origin posted %d revocations", len(missed))
		}
	})
}

func TestTokenRevokerAcceptsValidatedIssuerOrigin(t *testing.T) {
	t.Parallel()
	var calls []revokeCall
	srv := revokeServer(t, http.StatusOK, &calls)
	defer srv.Close()
	gw := ids.New[ids.GatewayKind]()
	cred, err := vaultdomain.NewCredential(gw, "ana", "com.airtable/mcp", "", "access-token", "refresh-token", nil, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	auth := &stubRevocationAuth{material: &appoauth.RevocationMaterial{
		ClientID:           "manual-client",
		ClientSecret:       "manual-secret",
		TokenURL:           "https://tokens.example/token",
		ValidatedIssuer:    srv.URL,
		RevocationEndpoint: srv.URL + "/revoke",
	}}
	if err := NewTokenRevoker(auth, srv.Client()).Revoke(context.Background(), gw, "ana", revokeRegistry(), cred); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("issuer-origin revocation posted %d calls", len(calls))
	}
	if calls[0].secret != "manual-secret" || calls[0].token != "refresh-token" {
		t.Fatalf("refresh call = %+v", calls[0])
	}
}

func TestTokenRevokerRejectsHTTPExceptAllowPrivate(t *testing.T) {
	var calls []revokeCall
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recordRevoke(t, w, r, http.StatusOK, &calls)
	}))
	defer srv.Close()
	gw := ids.New[ids.GatewayKind]()
	cred, err := vaultdomain.NewCredential(gw, "ana", "com.airtable/mcp", "", "access-token", "refresh-token", nil, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	auth := &stubRevocationAuth{material: materialFor(srv, "manual-client", "manual-secret", "")}
	err = NewTokenRevoker(auth, srv.Client()).Revoke(context.Background(), gw, "ana", revokeRegistry(), cred)
	if err == nil || !strings.Contains(err.Error(), "not https") {
		t.Fatalf("http revocation error = %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("http revocation posted %d calls", len(calls))
	}

	t.Cleanup(func() { netguard.SetAllowPrivate(false) })
	netguard.SetAllowPrivate(true)
	if err := NewTokenRevoker(auth, srv.Client()).Revoke(context.Background(), gw, "ana", revokeRegistry(), cred); err != nil {
		t.Fatalf("AllowPrivate http revocation: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("AllowPrivate posted %d revocations", len(calls))
	}
}

func TestTokenRevokerVendorError(t *testing.T) {
	t.Parallel()
	var calls []revokeCall
	srv := revokeServer(t, http.StatusInternalServerError, &calls)
	defer srv.Close()
	gw := ids.New[ids.GatewayKind]()
	cred, err := vaultdomain.NewCredential(gw, "ana", "com.airtable/mcp", "", "access-token", "refresh-token", nil, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	auth := &stubRevocationAuth{material: materialFor(srv, "manual-client", "", "")}
	err = NewTokenRevoker(auth, srv.Client()).Revoke(context.Background(), gw, "ana", revokeRegistry(), cred)
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

	t.Run("auth resolution failure", func(t *testing.T) {
		broken := &stubRevocationAuth{err: errors.New("metadata unavailable")}
		err := NewTokenRevoker(broken, srv.Client()).Revoke(context.Background(), gw, "ana", revokeRegistry(), cred)
		if err == nil || !strings.Contains(err.Error(), "metadata unavailable") {
			t.Fatalf("auth error = %v", err)
		}
		if strings.Contains(err.Error(), "access-token") {
			t.Fatalf("auth error leaked a token: %v", err)
		}
	})
}

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

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/app/identity/sts"
	appoauth "github.com/NeuralTrust/AgentGateway/pkg/app/oauth"
	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/identity"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/vault"
	infraoauth "github.com/NeuralTrust/AgentGateway/pkg/infra/oauth"
)

type stubExchanger struct {
	token *sts.Token
	err   error
	key   string
}

func (s *stubExchanger) Exchange(_ context.Context, _ *identity.Principal, _ *registrydomain.MCPAuth, cacheKey string) (*sts.Token, error) {
	s.key = cacheKey
	return s.token, s.err
}

type memVault struct {
	creds map[string]*vaultdomain.Credential
}

func (m *memVault) key(gw ids.GatewayID, sub, provider string) string {
	return gw.String() + "|" + sub + "|" + provider
}

func (m *memVault) Upsert(_ context.Context, c *vaultdomain.Credential) error {
	if m.creds == nil {
		m.creds = map[string]*vaultdomain.Credential{}
	}
	m.creds[m.key(c.GatewayID, c.PrincipalSub, c.Provider)] = c
	return nil
}

func (m *memVault) Find(_ context.Context, gw ids.GatewayID, sub, provider string) (*vaultdomain.Credential, error) {
	c, ok := m.creds[m.key(gw, sub, provider)]
	if !ok {
		return nil, vaultdomain.ErrNotFound
	}
	return c, nil
}

func (m *memVault) ListByPrincipal(context.Context, ids.GatewayID, string) ([]*vaultdomain.Credential, error) {
	return nil, nil
}

func (m *memVault) Delete(_ context.Context, gw ids.GatewayID, sub, provider string) error {
	delete(m.creds, m.key(gw, sub, provider))
	return nil
}

type stubConnect struct {
	appoauth.ConnectService
	ticket     string
	refreshCfg *registrydomain.MCPAuth
	refreshErr error
}

func (s *stubConnect) CreateTicket(context.Context, ids.GatewayID, string, string) (string, error) {
	return s.ticket, nil
}

func (s *stubConnect) RefreshAuth(context.Context, ids.GatewayID, *registrydomain.Registry) (*registrydomain.MCPAuth, error) {
	return s.refreshCfg, s.refreshErr
}

func principalCtx(p *identity.Principal) context.Context {
	return identity.WithPrincipal(context.Background(), p)
}

func mcpConsumer(gw ids.GatewayID) *appconsumer.RoutableConsumer {
	return &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{
		ID: ids.New[ids.ConsumerKind](), GatewayID: gw,
		Type: consumerdomain.TypeMCP, Slug: "dev", Active: true,
	}}
}

func regWithAuth(gw ids.GatewayID, auth *registrydomain.MCPAuth) *registrydomain.Registry {
	reg, err := registrydomain.NewMCPRegistry(gw, "up", "", &registrydomain.MCPTarget{
		URL: "https://up.example.com/mcp", Auth: auth,
	})
	if err != nil {
		panic(err)
	}
	return reg
}

func TestCredentialResolver_Passthrough(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	r := NewCredentialResolver(nil, nil, nil, nil)
	reg := regWithAuth(gw, &registrydomain.MCPAuth{
		Mode: registrydomain.MCPAuthModePassthrough, ExpectedAudience: "api://up",
	})

	t.Run("injects inbound token when aud matches", func(t *testing.T) {
		t.Parallel()
		ctx := principalCtx(&identity.Principal{
			Subject: "alice", RawToken: "tok", Claims: map[string]any{"aud": "api://up"},
		})
		target := Target{}
		if err := r.Apply(ctx, mcpConsumer(gw), reg, &target); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if target.Headers["Authorization"] != "Bearer tok" {
			t.Fatalf("Authorization = %q", target.Headers["Authorization"])
		}
	})

	t.Run("rejects audience mismatch (confused deputy guardrail)", func(t *testing.T) {
		t.Parallel()
		ctx := principalCtx(&identity.Principal{
			Subject: "alice", RawToken: "tok", Claims: map[string]any{"aud": "gateway"},
		})
		target := Target{}
		if err := r.Apply(ctx, mcpConsumer(gw), reg, &target); !errors.Is(err, ErrAudienceMismatch) {
			t.Fatalf("error = %v, want ErrAudienceMismatch", err)
		}
	})

	t.Run("rejects when no principal", func(t *testing.T) {
		t.Parallel()
		target := Target{}
		if err := r.Apply(context.Background(), mcpConsumer(gw), reg, &target); !errors.Is(err, ErrNoPrincipal) {
			t.Fatalf("error = %v, want ErrNoPrincipal", err)
		}
	})
}

func TestCredentialResolver_Exchange_InjectsAndIsolatesCacheKey(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	ex := &stubExchanger{token: &sts.Token{AccessToken: "minted", TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Minute)}}
	r := NewCredentialResolver(ex, nil, nil, nil)
	reg := regWithAuth(gw, &registrydomain.MCPAuth{
		Mode: registrydomain.MCPAuthModeExchange, Pattern: registrydomain.ExchangeImpersonation, Audience: "aud",
	})
	rc := mcpConsumer(gw)
	ctx := principalCtx(&identity.Principal{Subject: "alice"})
	target := Target{}
	if err := r.Apply(ctx, rc, reg, &target); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if target.Headers["Authorization"] != "Bearer minted" {
		t.Fatalf("Authorization = %q", target.Headers["Authorization"])
	}
	want := "alice|" + reg.ID.String() + "|" + gw.String()
	if ex.key != want {
		t.Fatalf("cache key = %q, want %q (principal+target+gateway isolation)", ex.key, want)
	}
}

func TestCredentialResolver_Forwarded(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	cfg := &registrydomain.MCPAuth{
		Mode: registrydomain.MCPAuthModeForwarded, Provider: "github", ClientID: "id",
		AuthorizeURL: "https://gh/a", TokenURL: "https://gh/t",
	}
	reg := regWithAuth(gw, cfg)

	t.Run("missing credential returns consent elicitation", func(t *testing.T) {
		t.Parallel()
		r := NewCredentialResolver(nil, &memVault{}, &stubConnect{ticket: "tckt"}, infraoauth.NewProviderClient(nil))
		ctx := principalCtx(&identity.Principal{Subject: "alice"})
		target := Target{}
		err := r.Apply(ctx, mcpConsumer(gw), reg, &target)
		var consent *ConsentRequiredError
		if !errors.As(err, &consent) {
			t.Fatalf("error = %v, want ConsentRequiredError", err)
		}
		if consent.Provider != "github" || consent.Ticket != "tckt" || consent.Path != "/dev/mcp" {
			t.Fatalf("consent = %+v", consent)
		}
	})

	t.Run("vaulted credential is injected", func(t *testing.T) {
		t.Parallel()
		vault := &memVault{}
		cred, _ := vaultdomain.NewCredential(gw, "alice", "github", "", "gh-token", "", nil, time.Now().Add(time.Hour))
		_ = vault.Upsert(context.Background(), cred)
		r := NewCredentialResolver(nil, vault, &stubConnect{}, infraoauth.NewProviderClient(nil))
		ctx := principalCtx(&identity.Principal{Subject: "alice"})
		target := Target{}
		if err := r.Apply(ctx, mcpConsumer(gw), reg, &target); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if target.Headers["Authorization"] != "Bearer gh-token" {
			t.Fatalf("Authorization = %q", target.Headers["Authorization"])
		}
	})

	t.Run("credentials never cross principals", func(t *testing.T) {
		t.Parallel()
		vault := &memVault{}
		cred, _ := vaultdomain.NewCredential(gw, "alice", "github", "", "alice-token", "", nil, time.Now().Add(time.Hour))
		_ = vault.Upsert(context.Background(), cred)
		r := NewCredentialResolver(nil, vault, &stubConnect{ticket: "t2"}, infraoauth.NewProviderClient(nil))
		ctx := principalCtx(&identity.Principal{Subject: "bob"})
		target := Target{}
		err := r.Apply(ctx, mcpConsumer(gw), reg, &target)
		var consent *ConsentRequiredError
		if !errors.As(err, &consent) {
			t.Fatalf("bob got %v, want consent (must not reuse alice's token)", err)
		}
		if target.Headers["Authorization"] != "" {
			t.Fatal("bob received alice's credential")
		}
	})

	t.Run("expired with refresh token refreshes via RefreshAuth config", func(t *testing.T) {
		t.Parallel()
		var gotForm url.Values
		idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			gotForm = r.Form
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fresh", "expires_in": 3600})
		}))
		defer idp.Close()
		vault := &memVault{}
		cred, _ := vaultdomain.NewCredential(gw, "alice", "github", "", "old", "refresh-me", nil, time.Now().Add(-time.Hour))
		_ = vault.Upsert(context.Background(), cred)
		connect := &stubConnect{refreshCfg: &registrydomain.MCPAuth{
			Provider: "github", ClientID: "dcr-id", TokenURL: idp.URL,
		}}
		r := NewCredentialResolver(nil, vault, connect, infraoauth.NewProviderClient(nil))
		ctx := principalCtx(&identity.Principal{Subject: "alice"})
		target := Target{}
		if err := r.Apply(ctx, mcpConsumer(gw), reg, &target); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if target.Headers["Authorization"] != "Bearer fresh" {
			t.Fatalf("Authorization = %q, want refreshed token", target.Headers["Authorization"])
		}
		if gotForm.Get("client_id") != "dcr-id" || gotForm.Get("refresh_token") != "refresh-me" {
			t.Fatalf("refresh form = %v", gotForm)
		}
	})

	t.Run("transient RefreshAuth failure propagates without consent", func(t *testing.T) {
		t.Parallel()
		vault := &memVault{}
		cred, _ := vaultdomain.NewCredential(gw, "alice", "github", "", "old", "refresh-me", nil, time.Now().Add(-time.Hour))
		_ = vault.Upsert(context.Background(), cred)
		transient := errors.New("client registration store unavailable")
		connect := &stubConnect{ticket: "t4", refreshErr: transient}
		r := NewCredentialResolver(nil, vault, connect, infraoauth.NewProviderClient(nil))
		ctx := principalCtx(&identity.Principal{Subject: "alice"})
		target := Target{}
		err := r.Apply(ctx, mcpConsumer(gw), reg, &target)
		if !errors.Is(err, transient) {
			t.Fatalf("error = %v, want transient error propagated", err)
		}
		var consent *ConsentRequiredError
		if errors.As(err, &consent) {
			t.Fatal("transient failures must not force the user back through consent")
		}
	})

	t.Run("invalid_grant on refresh falls back to consent", func(t *testing.T) {
		t.Parallel()
		idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant", "error_description": "revoked"})
		}))
		defer idp.Close()
		vault := &memVault{}
		cred, _ := vaultdomain.NewCredential(gw, "alice", "github", "", "old", "refresh-me", nil, time.Now().Add(-time.Hour))
		_ = vault.Upsert(context.Background(), cred)
		connect := &stubConnect{ticket: "t5", refreshCfg: &registrydomain.MCPAuth{
			Provider: "github", ClientID: "dcr-id", TokenURL: idp.URL,
		}}
		r := NewCredentialResolver(nil, vault, connect, infraoauth.NewProviderClient(nil))
		ctx := principalCtx(&identity.Principal{Subject: "alice"})
		target := Target{}
		err := r.Apply(ctx, mcpConsumer(gw), reg, &target)
		var consent *ConsentRequiredError
		if !errors.As(err, &consent) || consent.Ticket != "t5" {
			t.Fatalf("error = %v, want consent fallback on invalid_grant", err)
		}
	})

	t.Run("expired without refresh token returns consent", func(t *testing.T) {
		t.Parallel()
		vault := &memVault{}
		cred, _ := vaultdomain.NewCredential(gw, "alice", "github", "", "old", "", nil, time.Now().Add(-time.Hour))
		_ = vault.Upsert(context.Background(), cred)
		r := NewCredentialResolver(nil, vault, &stubConnect{ticket: "t3"}, infraoauth.NewProviderClient(nil))
		ctx := principalCtx(&identity.Principal{Subject: "alice"})
		target := Target{}
		err := r.Apply(ctx, mcpConsumer(gw), reg, &target)
		var consent *ConsentRequiredError
		if !errors.As(err, &consent) {
			t.Fatalf("error = %v, want consent for expired credential", err)
		}
	})
}

func TestCredentialResolver_NoneAndStaticAreNoops(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	r := NewCredentialResolver(nil, nil, nil, nil)
	for _, auth := range []*registrydomain.MCPAuth{
		{Mode: registrydomain.MCPAuthModeNone},
		{Mode: registrydomain.MCPAuthModeStatic, Header: "Authorization", Value: "Bearer static"},
	} {
		reg := regWithAuth(gw, auth)
		target := Target{}
		if err := r.Apply(context.Background(), mcpConsumer(gw), reg, &target); err != nil {
			t.Fatalf("Apply(%s): %v", auth.Mode, err)
		}
	}
}

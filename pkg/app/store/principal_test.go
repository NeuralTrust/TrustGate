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

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
)

// fakeVault answers Find per provider: a credential, ErrUndecryptable, or
// ErrNotFound when the provider is absent from both maps.
type fakeVault struct {
	creds         map[string]*vaultdomain.Credential
	undecryptable map[string]bool
}

func (f *fakeVault) Upsert(context.Context, *vaultdomain.Credential) error { return nil }
func (f *fakeVault) Find(_ context.Context, _ ids.GatewayID, _, provider string) (*vaultdomain.Credential, error) {
	if f.undecryptable[provider] {
		return nil, vaultdomain.ErrUndecryptable
	}
	if c, ok := f.creds[provider]; ok {
		return c, nil
	}
	return nil, vaultdomain.ErrNotFound
}
func (f *fakeVault) ListByPrincipal(context.Context, ids.GatewayID, string) ([]*vaultdomain.Credential, error) {
	return nil, nil
}
func (f *fakeVault) Delete(context.Context, ids.GatewayID, string, string) error { return nil }

// forwardedRegistry is a shelved MCP registry whose upstream wants the caller's
// own OAuth credential under the given provider key.
func forwardedRegistry(code, name, provider string) *registrydomain.Registry {
	reg := namedRegistry(code, name)
	reg.Type = registrydomain.TypeMCP
	reg.MCPTarget.Auth = &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeForwarded, Provider: provider}
	return reg
}

func newPreviewT(t *testing.T, installs *fakeInstalls, regs *fakeRegistries, vault vaultdomain.Repository) PrincipalPreview {
	t.Helper()
	cat := fakeCatalog{entries: map[string]catalogdomain.MCPServer{
		"github": {Code: "github", DisplayName: "GitHub"},
		"notion": {Code: "notion", DisplayName: "Notion"},
	}}
	p, err := NewPrincipalPreview(installs, regs, cat, vault)
	if err != nil {
		t.Fatalf("NewPrincipalPreview: %v", err)
	}
	return p
}

func TestNewPrincipalPreview_RequiresStores(t *testing.T) {
	if _, err := NewPrincipalPreview(nil, &fakeRegistries{}, fakeCatalog{}, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable without installs, got %v", err)
	}
	if _, err := NewPrincipalPreview(&fakeInstalls{}, &fakeRegistries{}, fakeCatalog{}, nil); err != nil {
		t.Fatalf("vault is optional, got %v", err)
	}
}

func TestPrincipalPreview_ValidatesInput(t *testing.T) {
	p := newPreviewT(t, &fakeInstalls{}, &fakeRegistries{}, nil)
	if _, err := p.Preview(context.Background(), ids.New[ids.GatewayKind](), "  "); !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("want validation error for blank sub, got %v", err)
	}
	if _, err := p.Preview(context.Background(), ids.GatewayID{}, "ana"); !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("want validation error for nil gateway, got %v", err)
	}
}

func TestPrincipalPreview_InstallsNamedFromCatalogAndBoundInstance(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	finance := namedRegistry("snowflake", "Snowflake (finance)")
	installed := mustInstall(t, gw, "ana", "github")
	pending := pendingInstall(t, gw, "ana", "snowflake")
	pending.RegistryID = finance.ID
	revoked := mustInstall(t, gw, "ana", "unknown-code")
	revoked.Status = installationdomain.StatusRevoked

	p := newPreviewT(t,
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{installed, pending, revoked}},
		&fakeRegistries{items: []*registrydomain.Registry{shelfRegistry("github"), finance}},
		nil,
	)
	state, err := p.Preview(context.Background(), gw, "ana")
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if state.PrincipalSub != "ana" || len(state.Installs) != 3 {
		t.Fatalf("unexpected state: %+v", state)
	}
	if got := state.Installs[0]; got.Name != "GitHub" || got.Status != installationdomain.StatusInstalled || got.InstanceID != installed.ID {
		t.Fatalf("installed row: %+v", got)
	}
	if got := state.Installs[1]; got.Registry != "Snowflake (finance)" || got.RegistryID != finance.ID || got.Status != installationdomain.StatusPendingApproval {
		t.Fatalf("pending row should carry its bound instance: %+v", got)
	}
	if got := state.Installs[2]; got.Name != "unknown-code" || got.Status != installationdomain.StatusRevoked {
		t.Fatalf("revoked row falls back to the code as its name: %+v", got)
	}
	if len(state.Connections) != 0 {
		t.Fatalf("no forwarded-auth registries → no connections, got %+v", state.Connections)
	}
}

func TestPrincipalPreview_ConnectionsPerForwardedSource(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	github := forwardedRegistry("github", "GitHub", "github")
	notion := forwardedRegistry("notion", "Notion", "notion")
	jira := forwardedRegistry("jira", "Jira", "jira")
	stale := forwardedRegistry("slack", "Slack", "slack")
	static := shelfRegistry("linear") // admin credential: not a connection
	vault := &fakeVault{
		creds: map[string]*vaultdomain.Credential{
			"github": {Provider: "github", AccountRef: "ana@corp", RefreshToken: "r", ExpiresAt: time.Now().Add(-time.Hour)},
			"slack":  {Provider: "slack", AccountRef: "ana", ExpiresAt: time.Now().Add(-time.Hour)},
		},
		undecryptable: map[string]bool{"jira": true},
	}
	p := newPreviewT(t, &fakeInstalls{}, &fakeRegistries{items: []*registrydomain.Registry{github, notion, jira, stale, static}}, vault)
	state, err := p.Preview(context.Background(), gw, "ana")
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if len(state.Connections) != 4 {
		t.Fatalf("want one connection per forwarded registry, got %+v", state.Connections)
	}
	byProvider := map[string]PrincipalConnection{}
	for _, c := range state.Connections {
		byProvider[c.Provider] = c
	}
	if c := byProvider["github"]; !c.Linked || c.AccountRef != "ana@corp" || c.NeedsReconnect || c.Code != "github" || c.RegistryID != github.ID {
		t.Fatalf("refreshable expired token is still linked: %+v", c)
	}
	if c := byProvider["notion"]; c.Linked || c.NeedsReconnect || c.Registry != "Notion" {
		t.Fatalf("no credential → not linked: %+v", c)
	}
	if c := byProvider["jira"]; !c.Linked || !c.NeedsReconnect || c.AccountRef != "" {
		t.Fatalf("undecryptable credential → linked but needs reconnect: %+v", c)
	}
	if c := byProvider["slack"]; !c.Linked || !c.NeedsReconnect {
		t.Fatalf("expired token without refresh → needs reconnect: %+v", c)
	}
}

func TestPrincipalPreview_NoVaultReportsUnlinked(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	p := newPreviewT(t, &fakeInstalls{}, &fakeRegistries{items: []*registrydomain.Registry{forwardedRegistry("github", "GitHub", "github")}}, nil)
	state, err := p.Preview(context.Background(), gw, "ana")
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if len(state.Connections) != 1 || state.Connections[0].Linked {
		t.Fatalf("want one unlinked connection, got %+v", state.Connections)
	}
}

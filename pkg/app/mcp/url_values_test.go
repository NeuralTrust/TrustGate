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
	"log/slog"
	"strings"
	"testing"

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
)

// fakeVault returns a secret keyed by (provider) for any principal.
type fakeVault struct {
	byProvider map[string]string
}

func (f fakeVault) Find(
	_ context.Context, gw ids.GatewayID, sub, provider string,
) (*vaultdomain.Credential, error) {
	v, ok := f.byProvider[provider]
	if !ok {
		return nil, vaultdomain.ErrNotFound
	}
	return &vaultdomain.Credential{GatewayID: gw, PrincipalSub: sub, Provider: provider, AccessToken: v}, nil
}

// fakeInstallFinder returns a per-(gateway,subject,code) installation config.
type fakeInstallFinder struct {
	byCode map[string]map[string]string
}

func (f fakeInstallFinder) Find(
	_ context.Context, gw ids.GatewayID, sub, code string,
) (*installationdomain.Installation, error) {
	cfg, ok := f.byCode[code]
	if !ok {
		return nil, installationdomain.ErrNotFound
	}
	return &installationdomain.Installation{
		GatewayID: gw, PrincipalSub: sub, CatalogCode: code,
		Status: installationdomain.StatusInstalled, Config: cfg,
	}, nil
}

func urlVarRegistry(t *testing.T) *registrydomain.Registry {
	t.Helper()
	reg, err := registrydomain.NewMCPRegistry(ids.New[ids.GatewayKind](), "Snowflake", "",
		&registrydomain.MCPTarget{
			Code: "snowflake",
			URL:  "https://{account_url}/api/v2/databases/{database}/mcp",
			URLVariables: []registrydomain.MCPURLVariable{
				{Name: "account_url", Required: true},
				{Name: "database", Required: true},
			},
		})
	if err != nil {
		t.Fatalf("build registry: %v", err)
	}
	return reg
}

func subCtx(sub string) context.Context {
	return identity.WithPrincipal(context.Background(), &identity.Principal{Subject: sub, Issuer: "idp"})
}

func TestComposerTarget_ResolvesURLVariablesPerUser(t *testing.T) {
	reg := urlVarRegistry(t)
	finder := fakeInstallFinder{byCode: map[string]map[string]string{
		"snowflake": {"account_url": "acme.snowflakecomputing.com", "database": "ANALYTICS"},
	}}
	c := &composer{logger: slog.New(slog.DiscardHandler), urlvars: NewURLValueResolver(finder, nil)}
	rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP})

	tgt, err := c.target(subCtx("ana"), rc, reg)
	if err != nil {
		t.Fatalf("target: %v", err)
	}
	want := "https://acme.snowflakecomputing.com/api/v2/databases/ANALYTICS/mcp"
	if tgt.URL != want {
		t.Fatalf("URL not resolved from install config: got %q want %q", tgt.URL, want)
	}
	if !strings.Contains(tgt.PinKey, ":u:") {
		t.Fatalf("resolved URL must be folded into the pin key for per-user isolation: %q", tgt.PinKey)
	}
}

func TestComposerTarget_DifferentUsersDifferentPinKeys(t *testing.T) {
	reg := urlVarRegistry(t)
	finder := fakeInstallFinder{byCode: map[string]map[string]string{}}
	// Two users, two accounts.
	finderA := fakeInstallFinder{byCode: map[string]map[string]string{"snowflake": {"account_url": "a.snowflakecomputing.com", "database": "D"}}}
	finderB := fakeInstallFinder{byCode: map[string]map[string]string{"snowflake": {"account_url": "b.snowflakecomputing.com", "database": "D"}}}
	_ = finder
	rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP})

	ca := &composer{logger: slog.New(slog.DiscardHandler), urlvars: NewURLValueResolver(finderA, nil)}
	cb := &composer{logger: slog.New(slog.DiscardHandler), urlvars: NewURLValueResolver(finderB, nil)}
	ta, err := ca.target(subCtx("ana"), rc, reg)
	if err != nil {
		t.Fatalf("target a: %v", err)
	}
	tb, err := cb.target(subCtx("ben"), rc, reg)
	if err != nil {
		t.Fatalf("target b: %v", err)
	}
	if ta.URL == tb.URL {
		t.Fatal("two users' accounts must resolve to different URLs")
	}
	if ta.PinKey == tb.PinKey {
		t.Fatalf("two users must not share a session pin key: %q", ta.PinKey)
	}
}

func TestComposerTarget_MissingConfigFailsClosed(t *testing.T) {
	reg := urlVarRegistry(t)
	// No install config for this principal → required placeholders unfilled.
	c := &composer{logger: slog.New(slog.DiscardHandler), urlvars: NewURLValueResolver(fakeInstallFinder{byCode: map[string]map[string]string{}}, nil)}
	rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP})
	if _, err := c.target(subCtx("ana"), rc, reg); err == nil {
		t.Fatal("an unconfigured URL-variable server must not dial")
	}
}

func TestComposerTarget_NoVariablesUnchanged(t *testing.T) {
	reg := mcpRegistry(t, "Linear", "https://mcp.linear.app/mcp")
	c := &composer{logger: slog.New(slog.DiscardHandler)}
	rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP})
	tgt, err := c.target(context.Background(), rc, reg)
	if err != nil {
		t.Fatalf("target: %v", err)
	}
	if tgt.URL != "https://mcp.linear.app/mcp" || strings.Contains(tgt.PinKey, ":u:") {
		t.Fatalf("a fully-determined URL must pass through untouched: %q pin %q", tgt.URL, tgt.PinKey)
	}
}

func TestComposerTarget_SecretVariableFromVault(t *testing.T) {
	reg, err := registrydomain.NewMCPRegistry(ids.New[ids.GatewayKind](), "Bright Data", "",
		&registrydomain.MCPTarget{
			Code: "com.brightdata/mcp",
			URL:  "https://mcp.brightdata.com/mcp?token={token}",
			URLVariables: []registrydomain.MCPURLVariable{
				{Name: "token", Required: true, Secret: true, In: registrydomain.URLVariableInQuery},
			},
		})
	if err != nil {
		t.Fatalf("build registry: %v", err)
	}
	vault := fakeVault{byProvider: map[string]string{
		registrydomain.URLVariableVaultProvider("com.brightdata/mcp", "token"): "s3cr3t/xyz",
	}}
	// No install config needed — the only variable is a secret from the vault.
	c := &composer{logger: slog.New(slog.DiscardHandler), urlvars: NewURLValueResolver(fakeInstallFinder{}, vault)}
	rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP})

	tgt, err := c.target(subCtx("ana"), rc, reg)
	if err != nil {
		t.Fatalf("target: %v", err)
	}
	if tgt.URL != "https://mcp.brightdata.com/mcp?token=s3cr3t%2Fxyz" {
		t.Fatalf("secret from vault not substituted/escaped into query: %q", tgt.URL)
	}
}

func TestComposerTarget_SecretMissingFromVaultFailsClosed(t *testing.T) {
	reg, err := registrydomain.NewMCPRegistry(ids.New[ids.GatewayKind](), "Bright Data", "",
		&registrydomain.MCPTarget{
			Code:         "com.brightdata/mcp",
			URL:          "https://mcp.brightdata.com/mcp?token={token}",
			URLVariables: []registrydomain.MCPURLVariable{{Name: "token", Required: true, Secret: true, In: registrydomain.URLVariableInQuery}},
		})
	if err != nil {
		t.Fatalf("build registry: %v", err)
	}
	c := &composer{logger: slog.New(slog.DiscardHandler), urlvars: NewURLValueResolver(fakeInstallFinder{}, fakeVault{})}
	rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP})
	if _, err := c.target(subCtx("ana"), rc, reg); err == nil {
		t.Fatal("a server whose required secret is not yet connected must not dial")
	}
}

func TestDiscoveryKey_PerUserForURLVariables(t *testing.T) {
	reg := urlVarRegistry(t) // URL variables, non-per-principal auth (none)
	ana, okA := discoveryKey(subCtx("ana"), reg, "tools")
	ben, okB := discoveryKey(subCtx("ben"), reg, "tools")
	if !okA || !okB {
		t.Fatal("discovery must be cacheable for URL-variable servers with a principal")
	}
	if ana == ben {
		t.Fatal("URL-variable servers must have per-principal discovery keys")
	}
	if _, ok := discoveryKey(context.Background(), reg, "tools"); ok {
		t.Fatal("without a principal a URL-variable server must not be cacheable")
	}
}

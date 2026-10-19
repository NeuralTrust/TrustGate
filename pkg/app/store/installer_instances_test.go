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
	"fmt"
	"strings"
	"testing"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func liveRows(code string, n int, status installationdomain.Status) []*installationdomain.Installation {
	out := make([]*installationdomain.Installation, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, &installationdomain.Installation{
			ID:          ids.New[ids.InstallationKind](),
			CatalogCode: code,
			Status:      status,
			Config:      map[string]string{"account_url": "acme", "database": fmt.Sprintf("db%d", i)},
		})
	}
	return out
}

func TestInstallResultCarriesInstanceID(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{
		shelfRegistry("github"),
	}}
	installs := &fakeInstalls{}
	res, err := newInstaller(t, regs, installs).Install(context.Background(), openReq(gw, "github"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.InstanceID == "" || res.InstanceID != installs.upserts[0].ID.String() {
		t.Fatalf("result must carry the recorded instance id, got %q (row %s)", res.InstanceID, installs.upserts[0].ID)
	}
}

// TestInstallSameConfigRefreshesTheInstance: re-installing an existing instance
// (same config) is idempotent — it refreshes that row instead of adding one.
func TestInstallSameConfigRefreshesTheInstance(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{
		shelfRegistry("snowflake"),
	}}
	rows := liveRows("snowflake", 10, installationdomain.StatusInstalled)
	installs := &fakeInstalls{byCode: rows}
	in := openReq(gw, "snowflake")
	in.Config = map[string]string{"account_url": "acme", "database": "db3"}
	_, err := newInstaller(t, regs, installs).Install(context.Background(), in)
	if err == nil || !errors.Is(err, ErrConfigInvalid) || !strings.Contains(err.Error(), "is set by an admin") {
		t.Fatalf("employee config must not select an instance, got %v", err)
	}
}

func apiKeyOnlyCatalog() fakeCatalog {
	return fakeCatalog{entries: map[string]catalogdomain.MCPServer{
		"com.semrush/mcp": {
			Code: "com.semrush/mcp", DisplayName: "Semrush", URL: "https://mcp.semrush.com/mcp",
			AuthHint: "static", RequiresAuth: true, AuthMethods: []string{"static"},
			AuthHeaders: []catalogdomain.MCPAuthHeader{{Name: "Authorization", Required: true, Secret: true, Scheme: "Bearer"}},
			SelfService: false,
		},
		"com.dual/mcp": {
			Code: "com.dual/mcp", DisplayName: "Dual", URL: "https://mcp.dual.example/mcp",
			AuthHint: "static", RequiresAuth: true, AuthMethods: []string{"static", "oauth"},
			AuthHeaders: []catalogdomain.MCPAuthHeader{{Name: "Authorization", Required: true, Secret: true}},
			SelfService: true,
			OAuth:       &catalogdomain.MCPOAuth{Registration: "auto"},
		},
	}}
}

// TestInstallOpenModeStaticOnlyRequiresAdminSetup guards fix 6: in open mode a
// catalog server whose only auth is a shared API key cannot be self-served — the
// registry it would materialise has no credential and fails validation. Instead
// of an error the install reports RequiresAdminSetup cleanly, materialises
// nothing and records nothing.
func TestInstallOpenModeStaticOnlyRequiresAdminSetup(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{}
	ensurer := &fakeEnsurer{addTo: regs}
	installs := &fakeInstalls{}
	inst, err := NewInstaller(apiKeyOnlyCatalog(), regs, installs, nil, ensurer)
	if err != nil {
		t.Fatalf("NewInstaller: %v", err)
	}
	res, err := inst.Install(context.Background(), openReq(gw, "com.semrush/mcp"))
	if err != nil {
		t.Fatalf("Install must not error, got %v", err)
	}
	if !res.RequiresAdminSetup || res.Status != "" || res.Pending || res.InstanceID != "" {
		t.Fatalf("expected a clean requires-admin-setup result, got %+v", res)
	}
	if len(ensurer.ensured) != 0 {
		t.Fatalf("must not attempt to materialise an API-key-only server, got %+v", ensurer.ensured)
	}
	if len(installs.upserts) != 0 {
		t.Fatalf("must not record an install, got %+v", installs.upserts)
	}
}

// TestInstallOpenModeDualAuthMaterialises: a server offering OAuth alongside an
// API key is self-serviceable — it materialises with forwarded auth.
func TestInstallOpenModeDualAuthMaterialises(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{}
	ensurer := &fakeEnsurer{addTo: regs}
	installs := &fakeInstalls{}
	inst, err := NewInstaller(apiKeyOnlyCatalog(), regs, installs, nil, ensurer)
	if err != nil {
		t.Fatalf("NewInstaller: %v", err)
	}
	res, err := inst.Install(context.Background(), openReq(gw, "com.dual/mcp"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.RequiresAdminSetup || res.Status != installationdomain.StatusInstalled {
		t.Fatalf("dual-auth server must self-serve, got %+v", res)
	}
	if len(ensurer.ensured) != 1 {
		t.Fatalf("expected one materialisation, got %+v", ensurer.ensured)
	}
}

// TestInstallStaticOnlyOnShelfInstallsNormally: once an admin has connected the
// API-key server (it is on the shelf), it installs like any other.
func TestInstallStaticOnlyOnShelfInstallsNormally(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{
		shelfRegistry("com.semrush/mcp"),
	}}
	installs := &fakeInstalls{}
	inst, err := NewInstaller(apiKeyOnlyCatalog(), regs, installs, nil, &fakeEnsurer{})
	if err != nil {
		t.Fatalf("NewInstaller: %v", err)
	}
	res, err := inst.Install(context.Background(), openReq(gw, "com.semrush/mcp"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.RequiresAdminSetup || res.Status != installationdomain.StatusInstalled {
		t.Fatalf("shelved API-key server must install, got %+v", res)
	}
}

// TestInstallCuratedStaticOnlyStaysPendingRequest: in curated mode the same
// server is a request for the admin, exactly as before.
func TestInstallCuratedStaticOnlyStaysPendingRequest(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	installs := &fakeInstalls{}
	inst, err := NewInstaller(apiKeyOnlyCatalog(), &fakeRegistries{}, installs, nil, &fakeEnsurer{})
	if err != nil {
		t.Fatalf("NewInstaller: %v", err)
	}
	res, err := inst.Install(context.Background(), req(gw, "com.semrush/mcp"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.RequiresAdminSetup || !res.Pending {
		t.Fatalf("curated mode must file a pending request, got %+v", res)
	}
}

// TestInstallSelectedCodeGrantStaticOnlyRequiresAdminSetup: the lazy path under
// Selected obeys the same rule as self-service — a code-granted API-key-only
// server with no registry cannot be materialised; an admin connects it first.
func TestInstallSelectedCodeGrantStaticOnlyRequiresAdminSetup(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{}
	ensurer := &fakeEnsurer{addTo: regs}
	installs := &fakeInstalls{}
	grants := grantsOf(codeGrant(gw, "com.semrush/mcp", nil, []string{"ana"}))
	inst, err := NewInstaller(apiKeyOnlyCatalog(), regs, installs, grants, ensurer)
	if err != nil {
		t.Fatalf("NewInstaller: %v", err)
	}
	res, err := inst.Install(context.Background(), req(gw, "com.semrush/mcp"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.RequiresAdminSetup || len(ensurer.ensured) != 0 || len(installs.upserts) != 0 {
		t.Fatalf("expected requires-admin-setup with no side effects, got %+v ensured=%v upserts=%d", res, ensurer.ensured, len(installs.upserts))
	}
}

// These six catalog entries carry a non-secret URL variable. An employee
// install with no admin row asks for that setup instead of failing as bad
// config. Sending the variable is still refused: the admin writes it.
func TestInstall_AdminOnlyURLVariableEntriesRequireAdminSetup(t *testing.T) {
	cat, err := appcatalog.NewMCPServerCatalog(nil)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	codes := []string{
		"io.aha/mcp",
		"com.algolia/mcp",
		"com.gorgias/mcp",
		"io.n8n/mcp",
		"com.shopify/storefront",
		"com.vanta/mcp",
	}
	for _, code := range codes {
		t.Run(code, func(t *testing.T) {
			gw := ids.New[ids.GatewayKind]()
			regs := &fakeRegistries{}
			ensurer := &fakeEnsurer{addTo: regs}
			installs := &fakeInstalls{}
			inst, err := NewInstaller(cat, regs, installs, nil, ensurer)
			if err != nil {
				t.Fatalf("NewInstaller: %v", err)
			}
			res, err := inst.Install(context.Background(), openReq(gw, code))
			if err != nil {
				t.Fatalf("Install: %v", err)
			}
			if !res.RequiresAdminSetup || res.Status != "" || len(ensurer.ensured) != 0 || len(installs.upserts) != 0 {
				t.Fatalf("want requires-admin-setup with no side effects, got %+v ensured=%v upserts=%d", res, ensurer.ensured, len(installs.upserts))
			}
		})
	}

	gw := ids.New[ids.GatewayKind]()
	inst, err := NewInstaller(cat, &fakeRegistries{}, &fakeInstalls{}, nil, &fakeEnsurer{})
	if err != nil {
		t.Fatalf("NewInstaller: %v", err)
	}
	in := openReq(gw, "com.shopify/storefront")
	in.Config = map[string]string{"shop": "allbirds"}
	_, err = inst.Install(context.Background(), in)
	if err == nil || !errors.Is(err, ErrConfigInvalid) || !strings.Contains(err.Error(), "is set by an admin") {
		t.Fatalf("employee shop must be rejected, got %v", err)
	}
}

// A principal may hold as many instances of a server as their work needs — a
// schema per team, an account per region. There is no ceiling: the grants say
// what they may install, and that is the whole governance.
func TestInstallDoesNotCapTheNumberOfInstances(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{shelfRegistry("snowflake")}}
	installs := &fakeInstalls{byCode: liveRows("snowflake", 50, installationdomain.StatusInstalled)}
	in := openReq(gw, "snowflake")
	in.Config = map[string]string{"account_url": "acme", "database": "one-more"}
	_, err := newInstaller(t, regs, installs).Install(context.Background(), in)
	if err == nil || !errors.Is(err, ErrConfigInvalid) || !strings.Contains(err.Error(), "is set by an admin") {
		t.Fatalf("another database is another registry row, got %v", err)
	}
}

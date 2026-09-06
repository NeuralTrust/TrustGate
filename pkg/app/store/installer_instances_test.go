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
	"testing"

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

// TestInstallCapsInstancesPerCode: the 11th distinct instance of one code is
// refused with the typed error and nothing is recorded or materialised.
func TestInstallCapsInstancesPerCode(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{
		shelfRegistry("snowflake"),
	}}
	installs := &fakeInstalls{byCode: liveRows("snowflake", MaxInstancesPerCode, installationdomain.StatusInstalled)}
	in := openReq(gw, "snowflake")
	in.Config = map[string]string{"account_url": "acme", "database": "one-more"}
	_, err := newInstaller(t, regs, installs).Install(context.Background(), in)
	if !errors.Is(err, ErrTooManyInstances) {
		t.Fatalf("expected ErrTooManyInstances, got %v", err)
	}
	if len(installs.upserts) != 0 {
		t.Fatalf("a refused install must record nothing, got %+v", installs.upserts)
	}
}

// TestInstallCapCountsPendingButNotRevoked: pending requests occupy a slot
// (request spam is the abuse); revoked rows do not.
func TestInstallCapCountsPendingButNotRevoked(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{shelfRegistry("snowflake")}}
	grants := grantsOf(codeGrant(gw, "snowflake", nil, []string{"ana"}))
	in := req(gw, "snowflake")
	in.Config = map[string]string{"account_url": "acme", "database": "one-more"}

	pending := &fakeInstalls{byCode: liveRows("snowflake", MaxInstancesPerCode, installationdomain.StatusPendingApproval)}
	if _, err := newInstallerWithGrants(t, regs, pending, grants).Install(context.Background(), in); !errors.Is(err, ErrTooManyInstances) {
		t.Fatalf("pending rows must count toward the cap, got %v", err)
	}

	revoked := &fakeInstalls{byCode: liveRows("snowflake", MaxInstancesPerCode, installationdomain.StatusRevoked)}
	res, err := newInstallerWithGrants(t, regs, revoked, grants).Install(context.Background(), in)
	if err != nil {
		t.Fatalf("revoked rows must not count toward the cap: %v", err)
	}
	if res.Status != installationdomain.StatusInstalled {
		t.Fatalf("expected an install, got %+v", res)
	}
}

// TestInstallSameConfigNotCapped: re-installing an existing instance (same
// config) is idempotent and never hits the cap.
func TestInstallSameConfigNotCapped(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{
		shelfRegistry("snowflake"),
	}}
	rows := liveRows("snowflake", MaxInstancesPerCode, installationdomain.StatusInstalled)
	installs := &fakeInstalls{byCode: rows}
	in := openReq(gw, "snowflake")
	in.Config = map[string]string{"account_url": "acme", "database": "db3"}
	res, err := newInstaller(t, regs, installs).Install(context.Background(), in)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.AlreadyInstalled || res.InstanceID != rows[3].ID.String() {
		t.Fatalf("same-config install must refresh the existing instance, got %+v", res)
	}
}

// TestInstallCapsInstancesPerPrincipal: the gateway-wide cap across codes.
func TestInstallCapsInstancesPerPrincipal(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{
		shelfRegistry("github"),
	}}
	all := make([]*installationdomain.Installation, 0, MaxInstancesPerPrincipal)
	for i := 0; i < MaxInstancesPerPrincipal; i++ {
		all = append(all, &installationdomain.Installation{
			ID: ids.New[ids.InstallationKind](), CatalogCode: fmt.Sprintf("server-%d", i), Status: installationdomain.StatusInstalled,
		})
	}
	installs := &fakeInstalls{byPrincipal: all}
	_, err := newInstaller(t, regs, installs).Install(context.Background(), openReq(gw, "github"))
	if !errors.Is(err, ErrTooManyInstances) {
		t.Fatalf("expected ErrTooManyInstances across codes, got %v", err)
	}
}

// TestInstallCapCheckedBeforeMaterialisation: a capped install in open mode must
// not materialise a registry as a side effect.
func TestInstallCapCheckedBeforeMaterialisation(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{}
	ensurer := &fakeEnsurer{addTo: regs}
	installs := &fakeInstalls{byCode: liveRows("snowflake", MaxInstancesPerCode, installationdomain.StatusInstalled)}
	in := openReq(gw, "snowflake")
	in.Config = map[string]string{"account_url": "acme", "database": "one-more"}
	_, err := newInstallerWithEnsurer(t, regs, installs, ensurer).Install(context.Background(), in)
	if !errors.Is(err, ErrTooManyInstances) {
		t.Fatalf("expected ErrTooManyInstances, got %v", err)
	}
	if len(ensurer.ensured) != 0 {
		t.Fatalf("a capped install must not materialise, got %+v", ensurer.ensured)
	}
}

func apiKeyOnlyCatalog() fakeCatalog {
	return fakeCatalog{entries: map[string]catalogdomain.MCPServer{
		"com.semrush/mcp": {
			Code: "com.semrush/mcp", DisplayName: "Semrush", URL: "https://mcp.semrush.com/mcp",
			AuthHint: "static", RequiresAuth: true, AuthMethods: []string{"static"},
			AuthHeaders: []catalogdomain.MCPAuthHeader{{Name: "Authorization", Required: true, Secret: true, Scheme: "Bearer"}},
		},
		"com.dual/mcp": {
			Code: "com.dual/mcp", DisplayName: "Dual", URL: "https://mcp.dual.example/mcp",
			AuthHint: "static", RequiresAuth: true, AuthMethods: []string{"static", "oauth"},
			AuthHeaders: []catalogdomain.MCPAuthHeader{{Name: "Authorization", Required: true, Secret: true}},
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

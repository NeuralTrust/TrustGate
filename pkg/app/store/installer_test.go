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

	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type fakeCatalog struct {
	entries map[string]catalogdomain.MCPServer
}

func (f fakeCatalog) GetByCode(code string) (catalogdomain.MCPServer, bool) {
	e, ok := f.entries[code]
	return e, ok
}

type fakeRegistries struct {
	items   []*registrydomain.Registry
	updated []*registrydomain.Registry
}

func (f *fakeRegistries) List(context.Context, registrydomain.ListFilter) ([]*registrydomain.Registry, int, error) {
	return f.items, len(f.items), nil
}

func (f *fakeRegistries) Update(_ context.Context, b *registrydomain.Registry) error {
	f.updated = append(f.updated, b)
	return nil
}

type fakeInstalls struct {
	upserts     []*installationdomain.Installation
	deletes     int
	findValue   *installationdomain.Installation
	byPrincipal []*installationdomain.Installation
	pending     []*installationdomain.Installation
}

func (f *fakeInstalls) Upsert(_ context.Context, in *installationdomain.Installation) error {
	f.upserts = append(f.upserts, in)
	return nil
}

func (f *fakeInstalls) Find(_ context.Context, _ ids.GatewayID, _, _ string) (*installationdomain.Installation, error) {
	if f.findValue != nil {
		return f.findValue, nil
	}
	return nil, installationdomain.ErrNotFound
}

func (f *fakeInstalls) ListByPrincipal(context.Context, ids.GatewayID, string) ([]*installationdomain.Installation, error) {
	return f.byPrincipal, nil
}

func (f *fakeInstalls) ListByCatalogCode(context.Context, ids.GatewayID, string) ([]*installationdomain.Installation, error) {
	return nil, nil
}

func (f *fakeInstalls) ListPendingByGateway(context.Context, ids.GatewayID) ([]*installationdomain.Installation, error) {
	return f.pending, nil
}

func (f *fakeInstalls) Delete(context.Context, ids.GatewayID, string, string) error {
	f.deletes++
	return nil
}

// shelfRegistry builds a gateway registry for a catalog code with the given
// Store governance.
func shelfRegistry(code string, store *registrydomain.MCPStoreConfig) *registrydomain.Registry {
	return &registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		MCPTarget: &registrydomain.MCPTarget{Code: code, Store: store},
	}
}

// fakeEnsurer records the codes it was asked to materialise and, when addTo is
// set, appends a freshly-shelved registry to it so a follow-up install sees an
// available registry.
type fakeEnsurer struct {
	ensured []string
	addTo   *fakeRegistries
	err     error
}

func (f *fakeEnsurer) Ensure(_ context.Context, _ ids.GatewayID, code string) error {
	if f.err != nil {
		return f.err
	}
	f.ensured = append(f.ensured, code)
	if f.addTo != nil {
		f.addTo.items = append(f.addTo.items, shelfRegistry(code, &registrydomain.MCPStoreConfig{Available: true}))
	}
	return nil
}

func newInstaller(t *testing.T, regs *fakeRegistries, installs *fakeInstalls) Installer {
	t.Helper()
	return newInstallerWithEnsurer(t, regs, installs, nil)
}

func newInstallerWithEnsurer(t *testing.T, regs *fakeRegistries, installs *fakeInstalls, ensurer RegistryEnsurer) Installer {
	t.Helper()
	catalog := fakeCatalog{entries: map[string]catalogdomain.MCPServer{
		"github": {Code: "github", DisplayName: "GitHub", URL: "https://mcp.github.com", RequiresAuth: true},
		"snowflake": {
			Code:        "snowflake",
			DisplayName: "Snowflake",
			URL:         "https://{account_url}/api/v2/databases/{database}/mcp",
			URLVariables: []catalogdomain.MCPURLVariable{
				{Name: "account_url", Required: true},
				{Name: "database", Required: true},
			},
		},
		"brightdata": {
			Code:        "brightdata",
			DisplayName: "Bright Data",
			URL:         "https://mcp.brightdata.com/mcp?token={token}",
			URLVariables: []catalogdomain.MCPURLVariable{
				{Name: "token", Required: true, Secret: true, In: "query"},
			},
		},
	}}
	inst, err := NewInstaller(catalog, regs, installs, ensurer)
	if err != nil {
		t.Fatalf("NewInstaller: %v", err)
	}
	return inst
}

func req(gw ids.GatewayID, code string, groups ...string) InstallRequest {
	return InstallRequest{GatewayID: gw, PrincipalSub: "ana", Code: code, InstalledBy: "ana", Groups: groups}
}

// openReq is a self-service (open Store) install request.
func openReq(gw ids.GatewayID, code string, groups ...string) InstallRequest {
	r := req(gw, code, groups...)
	r.OpenMode = true
	return r
}

func TestNewInstallerRejectsNilDeps(t *testing.T) {
	if _, err := NewInstaller(nil, &fakeRegistries{}, &fakeInstalls{}, nil); err == nil {
		t.Fatal("nil catalog must error")
	}
}

func TestInstallAvailableServerInstallsImmediately(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{
		shelfRegistry("github", &registrydomain.MCPStoreConfig{Available: true}),
	}}
	installs := &fakeInstalls{}
	res, err := newInstaller(t, regs, installs).Install(context.Background(), req(gw, "github"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.Status != installationdomain.StatusInstalled || res.Pending {
		t.Fatalf("available server must install immediately, got %+v", res)
	}
	if len(installs.upserts) != 1 || installs.upserts[0].Status != installationdomain.StatusInstalled {
		t.Fatalf("must record an installed row, got %+v", installs.upserts)
	}
}

func TestInstallNotOnShelfBecomesPendingRequest(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	// Curated mode (OpenMode false), no registry for the code — a request the
	// admin must shelve+approve.
	res, err := newInstaller(t, &fakeRegistries{}, &fakeInstalls{}).Install(context.Background(), req(gw, "github"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.Pending || res.Status != installationdomain.StatusPendingApproval {
		t.Fatalf("a server not on the shelf must become a pending request, got %+v", res)
	}
}

// TestInstallSelfServiceMaterialisesAndInstalls guards the B2 self-service path:
// in open mode a catalog server that is not yet on the shelf is materialised
// through the ensurer and installed immediately, not queued.
func TestInstallSelfServiceMaterialisesAndInstalls(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{}
	ensurer := &fakeEnsurer{addTo: regs}
	installs := &fakeInstalls{}
	res, err := newInstallerWithEnsurer(t, regs, installs, ensurer).
		Install(context.Background(), openReq(gw, "github"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.Pending || res.Status != installationdomain.StatusInstalled {
		t.Fatalf("open-mode install of a catalog server must materialise and install, got %+v", res)
	}
	if len(ensurer.ensured) != 1 || ensurer.ensured[0] != "github" {
		t.Fatalf("expected the registry to be materialised once for github, got %+v", ensurer.ensured)
	}
	if len(installs.upserts) != 1 || installs.upserts[0].Status != installationdomain.StatusInstalled {
		t.Fatalf("must record an installed row, got %+v", installs.upserts)
	}
}

// TestInstallSelfServiceWithoutEnsurerStaysPending confirms open mode alone does
// not grant an install: without a materialiser wired, a not-yet-shelved server
// still becomes a pending request rather than being silently installed.
func TestInstallSelfServiceWithoutEnsurerStaysPending(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	res, err := newInstaller(t, &fakeRegistries{}, &fakeInstalls{}).
		Install(context.Background(), openReq(gw, "github"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.Pending || res.Status != installationdomain.StatusPendingApproval {
		t.Fatalf("open mode without an ensurer must fall back to a pending request, got %+v", res)
	}
}

// TestInstallSelfServiceEnsurerErrorFailsInstall confirms a materialisation
// failure surfaces as an error and records no installation row.
func TestInstallSelfServiceEnsurerErrorFailsInstall(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	installs := &fakeInstalls{}
	ensurer := &fakeEnsurer{err: errors.New("boom")}
	_, err := newInstallerWithEnsurer(t, &fakeRegistries{}, installs, ensurer).
		Install(context.Background(), openReq(gw, "github"))
	if err == nil {
		t.Fatal("a materialisation failure must fail the install")
	}
	if len(installs.upserts) != 0 {
		t.Fatalf("a failed materialisation must not record an install, got %+v", installs.upserts)
	}
}

// TestInstallSelfServiceRespectsExistingGovernance confirms open mode does not
// bypass governance on a registry an admin already curated: an existing
// requires-approval registry is still pending even in open mode, and the ensurer
// is never called (the registry already exists).
func TestInstallSelfServiceRespectsExistingGovernance(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{
		shelfRegistry("github", &registrydomain.MCPStoreConfig{Available: true, RequiresApproval: true}),
	}}
	ensurer := &fakeEnsurer{addTo: regs}
	res, err := newInstallerWithEnsurer(t, regs, &fakeInstalls{}, ensurer).
		Install(context.Background(), openReq(gw, "github"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.Pending {
		t.Fatal("an admin-curated requires-approval registry stays pending even in open mode")
	}
	if len(ensurer.ensured) != 0 {
		t.Fatalf("the ensurer must not run when a registry already exists, got %+v", ensurer.ensured)
	}
}

func TestInstallAvailableButRequiresApprovalIsPending(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{
		shelfRegistry("github", &registrydomain.MCPStoreConfig{Available: true, RequiresApproval: true}),
	}}
	res, err := newInstaller(t, regs, &fakeInstalls{}).Install(context.Background(), req(gw, "github"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.Pending {
		t.Fatal("a requires-approval server must be pending")
	}
}

func TestInstallRoleGating(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{
		shelfRegistry("github", &registrydomain.MCPStoreConfig{Available: true, Roles: []string{"sre"}}),
	}}
	inst := newInstaller(t, regs, &fakeInstalls{})

	if _, err := inst.Install(context.Background(), req(gw, "github", "eng")); !errors.Is(err, ErrRoleNotAllowed) {
		t.Fatalf("a principal without the allowed role must be denied, got %v", err)
	}
	res, err := inst.Install(context.Background(), req(gw, "github", "sre"))
	if err != nil {
		t.Fatalf("allowed role Install: %v", err)
	}
	if res.Status != installationdomain.StatusInstalled {
		t.Fatalf("allowed role must install, got %+v", res)
	}
}

// TestInstallRoleGatedNotYetShelvedDeniesExcludedPrincipal guards the M1 fix:
// the role gate must be enforced as soon as a shelf registry exists, even before
// it is marked available. Otherwise a role-excluded principal could file a
// pending request that the (role-blind) approve path would later grant.
func TestInstallRoleGatedNotYetShelvedDeniesExcludedPrincipal(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	// Registry exists with a role list but is NOT available (not shelved yet).
	regs := &fakeRegistries{items: []*registrydomain.Registry{
		shelfRegistry("github", &registrydomain.MCPStoreConfig{Available: false, Roles: []string{"sre"}}),
	}}
	installs := &fakeInstalls{}
	inst := newInstaller(t, regs, installs)

	if _, err := inst.Install(context.Background(), req(gw, "github", "eng")); !errors.Is(err, ErrRoleNotAllowed) {
		t.Fatalf("role-excluded principal must be denied before queueing, got %v", err)
	}
	if len(installs.upserts) != 0 {
		t.Fatalf("a denied install must not record a pending request, got %+v", installs.upserts)
	}

	// A principal in the role list still queues for approval (not available yet).
	res, err := inst.Install(context.Background(), req(gw, "github", "sre"))
	if err != nil {
		t.Fatalf("allowed role Install: %v", err)
	}
	if !res.Pending || res.Status != installationdomain.StatusPendingApproval {
		t.Fatalf("allowed role on a not-yet-shelved server must be pending, got %+v", res)
	}
}

func TestInstallReportsAlreadyInstalled(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{
		shelfRegistry("github", &registrydomain.MCPStoreConfig{Available: true}),
	}}
	installs := &fakeInstalls{findValue: &installationdomain.Installation{Status: installationdomain.StatusInstalled}}
	res, err := newInstaller(t, regs, installs).Install(context.Background(), req(gw, "github"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.AlreadyInstalled {
		t.Fatal("must report already installed when an active install exists")
	}
}

func TestInstallUnknownCatalogCode(t *testing.T) {
	inst := newInstaller(t, &fakeRegistries{}, &fakeInstalls{})
	_, err := inst.Install(context.Background(), req(ids.New[ids.GatewayKind](), "does-not-exist"))
	if !errors.Is(err, ErrCatalogEntryNotFound) {
		t.Fatalf("expected ErrCatalogEntryNotFound, got %v", err)
	}
}

func TestInstallRequiresConfigWhenVariablesMissing(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{}
	installs := &fakeInstalls{}
	res, err := newInstallerWithEnsurer(t, regs, installs, &fakeEnsurer{addTo: regs}).
		Install(context.Background(), openReq(gw, "snowflake"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.RequiresConfig || len(res.ConfigVariables) != 2 {
		t.Fatalf("must ask for the two required variables, got %+v", res)
	}
	if len(installs.upserts) != 0 {
		t.Fatalf("a requires-config result must not record an install, got %+v", installs.upserts)
	}
}

func TestInstallWithConfigStoresAndInstalls(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{}
	installs := &fakeInstalls{}
	in := openReq(gw, "snowflake")
	in.Config = map[string]string{"account_url": "acme.snowflakecomputing.com", "database": "ANALYTICS"}
	res, err := newInstallerWithEnsurer(t, regs, installs, &fakeEnsurer{addTo: regs}).
		Install(context.Background(), in)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.RequiresConfig || res.Status != installationdomain.StatusInstalled {
		t.Fatalf("a fully-configured install must proceed, got %+v", res)
	}
	if len(installs.upserts) != 1 {
		t.Fatalf("expected one install row, got %+v", installs.upserts)
	}
	cfg := installs.upserts[0].Config
	if cfg["account_url"] != "acme.snowflakecomputing.com" || cfg["database"] != "ANALYTICS" {
		t.Fatalf("config not persisted on the installation: %+v", cfg)
	}
}

func TestInstallRejectsUnsafeConfigValue(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	in := openReq(gw, "snowflake")
	in.Config = map[string]string{"account_url": "evil.com/../x", "database": "ANALYTICS"}
	_, err := newInstallerWithEnsurer(t, &fakeRegistries{}, &fakeInstalls{}, &fakeEnsurer{}).
		Install(context.Background(), in)
	if !errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("an unsafe host value must be rejected, got %v", err)
	}
}

func TestInstallRejectsSecretSuppliedInline(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	in := openReq(gw, "brightdata")
	in.Config = map[string]string{"token": "sk-secret"}
	_, err := newInstallerWithEnsurer(t, &fakeRegistries{}, &fakeInstalls{}, &fakeEnsurer{}).
		Install(context.Background(), in)
	if !errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("a secret supplied inline must be rejected, got %v", err)
	}
}

func TestInstallSecretVariableRequiresConnect(t *testing.T) {
	// A server whose only required variable is a secret cannot be completed via
	// inline config: it is reported as requires-config (to be set via the connect
	// link), never installed half-configured.
	gw := ids.New[ids.GatewayKind]()
	installs := &fakeInstalls{}
	res, err := newInstallerWithEnsurer(t, &fakeRegistries{}, installs, &fakeEnsurer{}).
		Install(context.Background(), openReq(gw, "brightdata"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.RequiresConfig || len(res.ConfigVariables) != 1 || !res.ConfigVariables[0].Secret {
		t.Fatalf("a required secret variable must be reported for connect-link setup, got %+v", res)
	}
	if len(installs.upserts) != 0 {
		t.Fatalf("must not install before the secret is provided, got %+v", installs.upserts)
	}
}

func TestUninstallDeletesInstallationOnly(t *testing.T) {
	installs := &fakeInstalls{}
	inst := newInstaller(t, &fakeRegistries{}, installs)
	if err := inst.Uninstall(context.Background(), ids.New[ids.GatewayKind](), "ana", "github"); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if installs.deletes != 1 {
		t.Fatalf("expected one delete, got %d", installs.deletes)
	}
}

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

func newInstaller(t *testing.T, regs *fakeRegistries, installs *fakeInstalls) Installer {
	t.Helper()
	catalog := fakeCatalog{entries: map[string]catalogdomain.MCPServer{
		"github": {Code: "github", DisplayName: "GitHub", URL: "https://mcp.github.com", RequiresAuth: true},
	}}
	inst, err := NewInstaller(catalog, regs, installs)
	if err != nil {
		t.Fatalf("NewInstaller: %v", err)
	}
	return inst
}

func req(gw ids.GatewayID, code string, groups ...string) InstallRequest {
	return InstallRequest{GatewayID: gw, PrincipalSub: "ana", Code: code, InstalledBy: "ana", Groups: groups}
}

func TestNewInstallerRejectsNilDeps(t *testing.T) {
	if _, err := NewInstaller(nil, &fakeRegistries{}, &fakeInstalls{}); err == nil {
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
	// No registry for the code — a request the admin must shelve+approve.
	res, err := newInstaller(t, &fakeRegistries{}, &fakeInstalls{}).Install(context.Background(), req(gw, "github"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.Pending || res.Status != installationdomain.StatusPendingApproval {
		t.Fatalf("a server not on the shelf must become a pending request, got %+v", res)
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

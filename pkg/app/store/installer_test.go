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

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
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

type fakeRegistries struct{ items []*registrydomain.Registry }

func (f *fakeRegistries) List(context.Context, registrydomain.ListFilter) ([]*registrydomain.Registry, int, error) {
	return f.items, len(f.items), nil
}

type fakeCreator struct {
	created []appregistry.CreateInput
	ret     *registrydomain.Registry
}

func (f *fakeCreator) Create(_ context.Context, in appregistry.CreateInput) (*registrydomain.Registry, error) {
	f.created = append(f.created, in)
	if f.ret != nil {
		return f.ret, nil
	}
	return &registrydomain.Registry{ID: ids.New[ids.RegistryKind]()}, nil
}

type fakeInstalls struct {
	upserts     []*installationdomain.Installation
	deletes     int
	findErr     error
	findValue   *installationdomain.Installation
	byPrincipal []*installationdomain.Installation
}

func (f *fakeInstalls) Upsert(_ context.Context, in *installationdomain.Installation) error {
	f.upserts = append(f.upserts, in)
	return nil
}

func (f *fakeInstalls) Find(_ context.Context, _ ids.GatewayID, _, _ string) (*installationdomain.Installation, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
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

func (f *fakeInstalls) Delete(context.Context, ids.GatewayID, string, string) error {
	f.deletes++
	return nil
}

func newInstaller(t *testing.T, regs *fakeRegistries, creator *fakeCreator, installs *fakeInstalls) Installer {
	t.Helper()
	catalog := fakeCatalog{entries: map[string]catalogdomain.MCPServer{
		"github": {Code: "github", DisplayName: "GitHub", URL: "https://mcp.github.com", Transport: "streamable-http", RequiresAuth: true},
	}}
	inst, err := NewInstaller(catalog, regs, creator, installs)
	if err != nil {
		t.Fatalf("NewInstaller: %v", err)
	}
	return inst
}

func TestNewInstallerRejectsNilDeps(t *testing.T) {
	if _, err := NewInstaller(nil, &fakeRegistries{}, &fakeCreator{}, &fakeInstalls{}); err == nil {
		t.Fatal("nil catalog must error")
	}
}

func TestInstallProvisionsSharedRegistryWhenAbsent(t *testing.T) {
	regs := &fakeRegistries{}
	creator := &fakeCreator{}
	installs := &fakeInstalls{}
	inst := newInstaller(t, regs, creator, installs)

	gw := ids.New[ids.GatewayKind]()
	res, err := inst.Install(context.Background(), gw, "ana", "github", "ana")
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if len(creator.created) != 1 {
		t.Fatalf("expected one registry created, got %d", len(creator.created))
	}
	if creator.created[0].MCPTarget == nil || creator.created[0].MCPTarget.Code != "github" {
		t.Fatalf("created registry must carry the catalog code, got %+v", creator.created[0].MCPTarget)
	}
	if len(installs.upserts) != 1 || installs.upserts[0].CatalogCode != "github" {
		t.Fatalf("install must be recorded, got %+v", installs.upserts)
	}
	if !res.RequiresAuth || res.AlreadyInstalled {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestInstallReusesExistingSharedRegistry(t *testing.T) {
	existing := &registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		MCPTarget: &registrydomain.MCPTarget{Code: "github"},
	}
	regs := &fakeRegistries{items: []*registrydomain.Registry{existing}}
	creator := &fakeCreator{}
	installs := &fakeInstalls{}
	inst := newInstaller(t, regs, creator, installs)

	res, err := inst.Install(context.Background(), ids.New[ids.GatewayKind](), "bob", "github", "bob")
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if len(creator.created) != 0 {
		t.Fatal("must not create a second registry when one already exists for the code")
	}
	if res.RegistryID != existing.ID.String() {
		t.Fatalf("must reuse the existing registry id, got %s", res.RegistryID)
	}
}

func TestInstallReportsAlreadyInstalled(t *testing.T) {
	regs := &fakeRegistries{items: []*registrydomain.Registry{{
		ID: ids.New[ids.RegistryKind](), MCPTarget: &registrydomain.MCPTarget{Code: "github"},
	}}}
	installs := &fakeInstalls{findValue: &installationdomain.Installation{Status: installationdomain.StatusInstalled}}
	inst := newInstaller(t, regs, &fakeCreator{}, installs)

	res, err := inst.Install(context.Background(), ids.New[ids.GatewayKind](), "ana", "github", "ana")
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.AlreadyInstalled {
		t.Fatal("must report already installed when an active install exists")
	}
}

func TestInstallUnknownCatalogCode(t *testing.T) {
	inst := newInstaller(t, &fakeRegistries{}, &fakeCreator{}, &fakeInstalls{})
	_, err := inst.Install(context.Background(), ids.New[ids.GatewayKind](), "ana", "does-not-exist", "ana")
	if !errors.Is(err, ErrCatalogEntryNotFound) {
		t.Fatalf("expected ErrCatalogEntryNotFound, got %v", err)
	}
}

func TestUninstallDeletesInstallationOnly(t *testing.T) {
	installs := &fakeInstalls{}
	inst := newInstaller(t, &fakeRegistries{}, &fakeCreator{}, installs)
	if err := inst.Uninstall(context.Background(), ids.New[ids.GatewayKind](), "ana", "github"); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if installs.deletes != 1 {
		t.Fatalf("expected one delete, got %d", installs.deletes)
	}
}

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

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func TestInstall_SSETransportIsRefusedBeforeMaterialise(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	ensurer := &fakeEnsurer{}
	_, err := newInstallerWithEnsurer(t, &fakeRegistries{}, &fakeInstalls{}, ensurer).
		Install(context.Background(), openReq(gw, "com.replicate/mcp"))
	if !errors.Is(err, ErrSSEUnsupported) {
		t.Fatalf("Install = %v, want ErrSSEUnsupported", err)
	}
	if err.Error() != "SSE transport is not supported by the gateway yet" {
		t.Fatalf("error = %q", err.Error())
	}
	if len(ensurer.ensured) != 0 {
		t.Fatalf("SSE install must not materialise a registry, got %v", ensurer.ensured)
	}
}

func TestUninstall_NeverInstalledIsNothingInstalled(t *testing.T) {
	installs := &fakeInstalls{deleteErr: installationdomain.ErrNotFound}
	inst := newInstaller(t, &fakeRegistries{}, installs)
	err := inst.Uninstall(context.Background(), ids.New[ids.GatewayKind](), "ana", "com.replicate/mcp", "")
	if !errors.Is(err, ErrNothingInstalled) {
		t.Fatalf("Uninstall = %v, want ErrNothingInstalled", err)
	}
	if installs.deletes != 1 {
		t.Fatalf("deletes = %d, want the missing-row delete to be attempted", installs.deletes)
	}
}

func TestUninstall_UnknownInstanceStaysNotFound(t *testing.T) {
	inst := newInstaller(t, &fakeRegistries{}, &fakeInstalls{})
	missing := ids.New[ids.InstallationKind]()
	err := inst.Uninstall(context.Background(), ids.New[ids.GatewayKind](), "ana", "github", missing.String())
	if errors.Is(err, ErrNothingInstalled) {
		t.Fatal("a named instance that does not exist is not the never-installed answer")
	}
	if !errors.Is(err, installationdomain.ErrNotFound) {
		t.Fatalf("Uninstall = %v, want ErrNotFound", err)
	}
}

func TestInstalledCodes_ActiveInstallsOnly(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	installs := &fakeInstalls{byPrincipal: []*installationdomain.Installation{
		{CatalogCode: "gitlab", Status: installationdomain.StatusInstalled},
		{CatalogCode: "gitlab", Status: installationdomain.StatusInstalled},
		{CatalogCode: "salesforce", Status: installationdomain.StatusPendingApproval},
		{CatalogCode: "github", Status: installationdomain.StatusRevoked},
		{CatalogCode: "  ", Status: installationdomain.StatusInstalled},
	}}
	codes, err := newInstaller(t, &fakeRegistries{}, installs).InstalledCodes(context.Background(), gw, "ana")
	if err != nil {
		t.Fatalf("InstalledCodes: %v", err)
	}
	if _, ok := codes["gitlab"]; !ok || len(codes) != 1 {
		t.Fatalf("codes = %v, want only gitlab", codes)
	}
}

func TestInstalledShelves_ResolvesTheInstanceTheScoperExposes(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	canonical := shelfRegistry("github")
	sandbox := shelfRegistry("github")
	gitlab := shelfRegistry("gitlab")
	installs := &fakeInstalls{byPrincipal: []*installationdomain.Installation{
		// Unbound: the scoper serves this from the code's oldest instance.
		{CatalogCode: "gitlab", Status: installationdomain.StatusInstalled},
		// Bound to the newer instance, not the canonical one.
		{CatalogCode: "github", Status: installationdomain.StatusInstalled, RegistryID: sandbox.ID},
		{CatalogCode: "salesforce", Status: installationdomain.StatusPendingApproval},
		{CatalogCode: "github", Status: installationdomain.StatusRevoked, RegistryID: canonical.ID},
	}}
	shelves, err := newInstaller(t, &fakeRegistries{items: []*registrydomain.Registry{canonical, sandbox, gitlab}}, installs).
		InstalledShelves(context.Background(), gw, "ana")
	if err != nil {
		t.Fatalf("InstalledShelves: %v", err)
	}
	if got := shelves["gitlab"]; len(got) != 1 || got[0] != gitlab.ID {
		t.Fatalf("gitlab shelves = %v, want the canonical instance %s", got, gitlab.ID)
	}
	if got := shelves["github"]; len(got) != 1 || got[0] != sandbox.ID {
		t.Fatalf("github shelves = %v, want the bound instance %s", got, sandbox.ID)
	}
	if _, ok := shelves["salesforce"]; ok || len(shelves) != 2 {
		t.Fatalf("shelves = %v, want only the active installs", shelves)
	}
}

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

func pendingInstall(t *testing.T, gw ids.GatewayID, sub, code string) *installationdomain.Installation {
	t.Helper()
	in := mustInstall(t, gw, sub, code)
	in.Status = installationdomain.StatusPendingApproval
	return in
}

func shelvedRegistry(code string, available bool) *registrydomain.Registry {
	return &registrydomain.Registry{
		ID: ids.New[ids.RegistryKind](),
		MCPTarget: &registrydomain.MCPTarget{
			Code:  code,
			Store: &registrydomain.MCPStoreConfig{Available: available, RequiresApproval: true},
		},
	}
}

func newApproverT(t *testing.T, installs *fakeInstalls, regs *fakeRegistries) Approver {
	t.Helper()
	cat := fakeCatalog{entries: map[string]catalogdomain.MCPServer{
		"github": {Code: "github", DisplayName: "GitHub"},
	}}
	a, err := NewApprover(cat, regs, installs)
	if err != nil {
		t.Fatalf("NewApprover: %v", err)
	}
	return a
}

func TestApprover_ListPending_NamesFromCatalog(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	installs := &fakeInstalls{pending: []*installationdomain.Installation{pendingInstall(t, gw, "ana", "github")}}
	a := newApproverT(t, installs, &fakeRegistries{})

	got, err := a.ListPending(context.Background(), gw)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 pending, got %d", len(got))
	}
	if got[0].Name != "GitHub" || got[0].Code != "github" || got[0].PrincipalSub != "ana" {
		t.Fatalf("unexpected request: %+v", got[0])
	}
}

func TestApprover_Approve_ShelvedAvailable_FlipsInstalledWithoutRegistryUpdate(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	installs := &fakeInstalls{findValue: pendingInstall(t, gw, "ana", "github")}
	regs := &fakeRegistries{items: []*registrydomain.Registry{shelvedRegistry("github", true)}}
	a := newApproverT(t, installs, regs)

	if err := a.Approve(context.Background(), ApproveRequest{GatewayID: gw, PrincipalSub: "ana", Code: "github", ApprovedBy: "admin@acme"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if len(installs.upserts) != 1 || installs.upserts[0].Status != installationdomain.StatusInstalled {
		t.Fatalf("want one installed upsert, got %+v", installs.upserts)
	}
	if len(regs.updated) != 0 {
		t.Fatalf("registry should not be updated when already available, got %d", len(regs.updated))
	}
}

func TestApprover_Approve_ShelvedNotAvailable_ShelvesAndInstalls(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	installs := &fakeInstalls{findValue: pendingInstall(t, gw, "ana", "github")}
	regs := &fakeRegistries{items: []*registrydomain.Registry{shelvedRegistry("github", false)}}
	a := newApproverT(t, installs, regs)

	if err := a.Approve(context.Background(), ApproveRequest{GatewayID: gw, PrincipalSub: "ana", Code: "github"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if len(regs.updated) != 1 || !regs.updated[0].MCPTarget.StoreAvailable() {
		t.Fatalf("registry should be shelved available, got %+v", regs.updated)
	}
	// RequiresApproval must be preserved so future installs still queue.
	if !regs.updated[0].MCPTarget.StoreRequiresApproval() {
		t.Fatalf("requires_approval should be preserved on shelve")
	}
	if len(installs.upserts) != 1 || installs.upserts[0].Status != installationdomain.StatusInstalled {
		t.Fatalf("want one installed upsert, got %+v", installs.upserts)
	}
}

func TestApprover_Approve_NotShelved_ReturnsErrNotShelved(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	installs := &fakeInstalls{findValue: pendingInstall(t, gw, "ana", "github")}
	a := newApproverT(t, installs, &fakeRegistries{})

	err := a.Approve(context.Background(), ApproveRequest{GatewayID: gw, PrincipalSub: "ana", Code: "github"})
	if !errors.Is(err, ErrNotShelved) {
		t.Fatalf("want ErrNotShelved, got %v", err)
	}
	if len(installs.upserts) != 0 {
		t.Fatalf("no upsert expected when not shelved, got %d", len(installs.upserts))
	}
}

func TestApprover_Approve_AlreadyInstalled_NoOp(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	installed := mustInstall(t, gw, "ana", "github") // starts installed
	installs := &fakeInstalls{findValue: installed}
	a := newApproverT(t, installs, &fakeRegistries{})

	if err := a.Approve(context.Background(), ApproveRequest{GatewayID: gw, PrincipalSub: "ana", Code: "github"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if len(installs.upserts) != 0 {
		t.Fatalf("already-installed approve should be a no-op, got %d upserts", len(installs.upserts))
	}
}

func TestApprover_Approve_NotFound_ReturnsErr(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	installs := &fakeInstalls{} // Find returns ErrNotFound
	a := newApproverT(t, installs, &fakeRegistries{})

	err := a.Approve(context.Background(), ApproveRequest{GatewayID: gw, PrincipalSub: "ana", Code: "github"})
	if !errors.Is(err, installationdomain.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestApprover_Deny_FlipsRevoked(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	installs := &fakeInstalls{findValue: pendingInstall(t, gw, "ana", "github")}
	a := newApproverT(t, installs, &fakeRegistries{})

	if err := a.Deny(context.Background(), DenyRequest{GatewayID: gw, PrincipalSub: "ana", Code: "github", DeniedBy: "admin@acme"}); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if len(installs.upserts) != 1 || installs.upserts[0].Status != installationdomain.StatusRevoked {
		t.Fatalf("want one revoked upsert, got %+v", installs.upserts)
	}
}

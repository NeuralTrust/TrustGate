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

// newApproverT wires an approver over empty grants.
func newApproverT(t *testing.T, installs *fakeInstalls, regs *fakeRegistries) Approver {
	t.Helper()
	return newApproverWith(t, installs, regs, &fakeGrants{}, nil)
}

func newApproverWith(t *testing.T, installs *fakeInstalls, regs *fakeRegistries, grants *fakeGrants, ensurer RegistryEnsurer) Approver {
	t.Helper()
	cat := fakeCatalog{entries: map[string]catalogdomain.MCPServer{
		"github": {Code: "github", DisplayName: "GitHub"},
	}}
	var opts []ApproverOption
	if ensurer != nil {
		opts = append(opts, WithApproverEnsurer(ensurer))
	}
	a, err := NewApprover(cat, regs, installs, grants, opts...)
	if err != nil {
		t.Fatalf("NewApprover: %v", err)
	}
	return a
}

func TestNewApproverRejectsNilGrants(t *testing.T) {
	if _, err := NewApprover(fakeCatalog{}, &fakeRegistries{}, &fakeInstalls{}, nil); err == nil {
		t.Fatal("nil grants must error")
	}
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

// TestApprover_Approve_AlreadyGranted_NoGrantWrite: approving a request from a
// principal a grant already covers just installs — no grant write.
func TestApprover_Approve_AlreadyGranted_NoGrantWrite(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	installs := &fakeInstalls{findValue: pendingInstall(t, gw, "ana", "github")}
	regs := &fakeRegistries{items: []*registrydomain.Registry{shelfRegistry("github")}}
	grants := grantsOf(codeGrant(gw, "github", nil, []string{"ana"}))
	a := newApproverWith(t, installs, regs, grants, nil)

	if err := a.Approve(context.Background(), ApproveRequest{GatewayID: gw, PrincipalSub: "ana", Code: "github", ApprovedBy: "admin@acme"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if len(installs.upserts) != 1 || installs.upserts[0].Status != installationdomain.StatusInstalled {
		t.Fatalf("want one installed upsert, got %+v", installs.upserts)
	}
	if len(grants.upserts) != 0 {
		t.Fatalf("no grant write when the requester is already granted, got %d", len(grants.upserts))
	}
}

// TestApprover_Approve_Ungranted_GrantsCodeAndInstalls: approving is granting.
// An unbound request adds the requester to the code-level grant (creating it
// when absent) and installs.
func TestApprover_Approve_Ungranted_GrantsCodeAndInstalls(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	installs := &fakeInstalls{findValue: pendingInstall(t, gw, "ana", "github")}
	regs := &fakeRegistries{items: []*registrydomain.Registry{shelfRegistry("github")}}
	grants := &fakeGrants{}
	a := newApproverWith(t, installs, regs, grants, nil)

	if err := a.Approve(context.Background(), ApproveRequest{GatewayID: gw, PrincipalSub: "ana", Code: "github"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if len(grants.upserts) != 1 {
		t.Fatalf("exactly one grant write expected, got %d", len(grants.upserts))
	}
	g := grants.upserts[0]
	if g.CatalogCode != "github" || g.IsInstance() || len(g.Users) != 1 || g.Users[0] != "ana" {
		t.Fatalf("approve must grant the requester on the code, got %+v", g)
	}
	if len(installs.upserts) != 1 || installs.upserts[0].Status != installationdomain.StatusInstalled {
		t.Fatalf("want one installed upsert, got %+v", installs.upserts)
	}
}

// TestApprover_Approve_NotShelved_ReturnsErrNotShelved: without a materialiser
// a request for a never-connected server cannot be approved.
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

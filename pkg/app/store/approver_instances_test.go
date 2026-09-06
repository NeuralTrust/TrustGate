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

// twoInstances is the bug scenario: instance A installed, instance B pending,
// both of the same code for the same principal.
func twoInstances(t *testing.T, gw ids.GatewayID) (a, b *installationdomain.Installation, installs *fakeInstalls) {
	t.Helper()
	a = mustInstall(t, gw, "ana", "github")
	a.Config = map[string]string{"org": "a"}
	b = pendingInstall(t, gw, "ana", "github")
	b.Config = map[string]string{"org": "b"}
	installs = &fakeInstalls{byCode: []*installationdomain.Installation{a, b}}
	return a, b, installs
}

func TestApprover_ListPending_CarriesInstanceID(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	p := pendingInstall(t, gw, "ana", "github")
	a := newApproverT(t, &fakeInstalls{pending: []*installationdomain.Installation{p}}, &fakeRegistries{})
	got, err := a.ListPending(context.Background(), gw)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(got) != 1 || got[0].InstanceID != p.ID.String() {
		t.Fatalf("pending row must carry its instance id, got %+v", got)
	}
}

// TestApprover_Deny_ByCodeWithSeveralInstancesIsAmbiguous guards fix 3: a deny
// naming only the code, when A is installed and B is pending, must not revoke A
// (the by-code Find picked the earliest row before). It is refused instead.
func TestApprover_Deny_ByCodeWithSeveralInstancesIsAmbiguous(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	a, _, installs := twoInstances(t, gw)
	ap := newApproverT(t, installs, &fakeRegistries{})

	err := ap.Deny(context.Background(), DenyRequest{GatewayID: gw, PrincipalSub: "ana", Code: "github"})
	if !errors.Is(err, ErrAmbiguousRequest) {
		t.Fatalf("expected ErrAmbiguousRequest, got %v", err)
	}
	if len(installs.upserts) != 0 || a.Status != installationdomain.StatusInstalled {
		t.Fatalf("nothing may change on an ambiguous deny; upserts=%d a=%q", len(installs.upserts), a.Status)
	}
}

func TestApprover_Deny_ByInstanceIDTargetsThatInstanceOnly(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	a, b, installs := twoInstances(t, gw)
	ap := newApproverT(t, installs, &fakeRegistries{})

	if err := ap.Deny(context.Background(), DenyRequest{GatewayID: gw, PrincipalSub: "ana", Code: "github", InstanceID: b.ID.String()}); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if b.Status != installationdomain.StatusRevoked {
		t.Fatalf("instance B must be revoked, got %q", b.Status)
	}
	if a.Status != installationdomain.StatusInstalled {
		t.Fatalf("instance A must be untouched, got %q", a.Status)
	}
	if len(installs.upserts) != 1 || installs.upserts[0].ID != b.ID {
		t.Fatalf("exactly one upsert of B expected, got %+v", installs.upserts)
	}
}

func TestApprover_Approve_ByInstanceIDTargetsThatInstanceOnly(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	_, b, installs := twoInstances(t, gw)
	regs := &fakeRegistries{items: []*registrydomain.Registry{shelvedRegistry("github", true)}}
	ap := newApproverT(t, installs, regs)

	if err := ap.Approve(context.Background(), ApproveRequest{GatewayID: gw, PrincipalSub: "ana", InstanceID: b.ID.String()}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if b.Status != installationdomain.StatusInstalled {
		t.Fatalf("instance B must be installed, got %q", b.Status)
	}
	if len(installs.upserts) != 1 || installs.upserts[0].ID != b.ID {
		t.Fatalf("exactly one upsert of B expected, got %+v", installs.upserts)
	}
}

func TestApprover_Approve_ByCodeWithSeveralInstancesIsAmbiguous(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	_, _, installs := twoInstances(t, gw)
	regs := &fakeRegistries{items: []*registrydomain.Registry{shelvedRegistry("github", true)}}
	ap := newApproverT(t, installs, regs)
	err := ap.Approve(context.Background(), ApproveRequest{GatewayID: gw, PrincipalSub: "ana", Code: "github"})
	if !errors.Is(err, ErrAmbiguousRequest) {
		t.Fatalf("expected ErrAmbiguousRequest, got %v", err)
	}
}

// TestApprover_InstanceIDMustMatchCode: an instance id of another code (or an
// unknown id) is not found — a stray id cannot decide an unrelated request.
func TestApprover_InstanceIDMustMatchCode(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	p := pendingInstall(t, gw, "ana", "snowflake")
	installs := &fakeInstalls{byCode: []*installationdomain.Installation{p}}
	ap := newApproverT(t, installs, &fakeRegistries{})

	err := ap.Deny(context.Background(), DenyRequest{GatewayID: gw, PrincipalSub: "ana", Code: "github", InstanceID: p.ID.String()})
	if !errors.Is(err, installationdomain.ErrNotFound) {
		t.Fatalf("instance of another code must be ErrNotFound, got %v", err)
	}
	err = ap.Deny(context.Background(), DenyRequest{GatewayID: gw, PrincipalSub: "ana", InstanceID: ids.New[ids.InstallationKind]().String()})
	if !errors.Is(err, installationdomain.ErrNotFound) {
		t.Fatalf("unknown instance must be ErrNotFound, got %v", err)
	}
	if len(installs.upserts) != 0 {
		t.Fatal("nothing may change")
	}
}

// TestApprover_ByCodeIgnoresRevokedWhenOneLive: revoked leftovers do not make a
// by-code decision ambiguous when exactly one live instance remains.
func TestApprover_ByCodeIgnoresRevokedWhenOneLive(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	old := mustInstall(t, gw, "ana", "github")
	old.Status = installationdomain.StatusRevoked
	p := pendingInstall(t, gw, "ana", "github")
	installs := &fakeInstalls{byCode: []*installationdomain.Installation{old, p}}
	ap := newApproverT(t, installs, &fakeRegistries{})

	if err := ap.Deny(context.Background(), DenyRequest{GatewayID: gw, PrincipalSub: "ana", Code: "github"}); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if p.Status != installationdomain.StatusRevoked {
		t.Fatalf("the live pending instance must be denied, got %q", p.Status)
	}
}

// TestApprover_Approve_ByCodeDoesNotResurrectRevoked: with only revoked rows, a
// by-code approve finds no pending request (deny stays idempotent).
func TestApprover_Approve_ByCodeDoesNotResurrectRevoked(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	old := mustInstall(t, gw, "ana", "github")
	old.Status = installationdomain.StatusRevoked
	installs := &fakeInstalls{byCode: []*installationdomain.Installation{old}}
	regs := &fakeRegistries{items: []*registrydomain.Registry{shelvedRegistry("github", true)}}
	ap := newApproverT(t, installs, regs)

	err := ap.Approve(context.Background(), ApproveRequest{GatewayID: gw, PrincipalSub: "ana", Code: "github"})
	if !errors.Is(err, installationdomain.ErrNotFound) {
		t.Fatalf("by-code approve over revoked rows must be ErrNotFound, got %v", err)
	}
	if err := ap.Deny(context.Background(), DenyRequest{GatewayID: gw, PrincipalSub: "ana", Code: "github"}); err != nil {
		t.Fatalf("deny of an already-denied request must be idempotent, got %v", err)
	}
	if len(installs.upserts) != 0 {
		t.Fatal("nothing may change")
	}
}

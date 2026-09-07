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
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
)

// TestApprover_Approve_ExtendsExistingCodeGrant: approving a request from a
// principal outside a code grant that names other groups adds their subject to
// that same grant, preserving the groups already on it.
func TestApprover_Approve_ExtendsExistingCodeGrant(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	installs := &fakeInstalls{findValue: pendingInstall(t, gw, "ana", "github")}
	regs := &fakeRegistries{items: []*registrydomain.Registry{shelfRegistry("github")}}
	grants := grantsOf(codeGrant(gw, "github", []string{"sre"}, nil))
	a := newApproverWith(t, installs, regs, grants, nil)

	if err := a.Approve(context.Background(), ApproveRequest{GatewayID: gw, PrincipalSub: "ana", Code: "github"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if len(grants.upserts) != 1 {
		t.Fatalf("approve must write the grant once, got %d", len(grants.upserts))
	}
	g := grants.upserts[0]
	if len(g.Users) != 1 || g.Users[0] != "ana" {
		t.Fatalf("approve must grant the requester, got users=%v", g.Users)
	}
	if len(g.Groups) != 1 || g.Groups[0] != "sre" {
		t.Fatalf("existing group grant must be preserved, got %v", g.Groups)
	}
	// The grant now admits the requester on the installer's own gate.
	if !storeaccessdomain.Index(grants.items).CodeAllows("github", nil, "ana") {
		t.Fatal("after approve the requester must pass the grant")
	}
}

// TestApprover_Approve_BoundRequestGrantsThatInstanceOnly: a request bound to
// one configured instance is approved for that instance — the code-level grant
// and the other instances stay untouched.
func TestApprover_Approve_BoundRequestGrantsThatInstanceOnly(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	finance := namedRegistry("github", "finance")
	analytics := namedRegistry("github", "analytics")
	p := pendingInstall(t, gw, "ana", "github")
	p.RegistryID = finance.ID
	installs := &fakeInstalls{findValue: p}
	regs := &fakeRegistries{items: []*registrydomain.Registry{finance, analytics}}
	grants := &fakeGrants{}
	a := newApproverWith(t, installs, regs, grants, nil)

	if err := a.Approve(context.Background(), ApproveRequest{GatewayID: gw, PrincipalSub: "ana", InstanceID: p.ID.String()}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if len(grants.upserts) != 1 || grants.upserts[0].RegistryID != finance.ID {
		t.Fatalf("approve must grant the bound instance, got %+v", grants.upserts)
	}
	set := storeaccessdomain.Index(grants.items)
	if !set.InstanceAllows("github", finance.ID, nil, "ana") {
		t.Fatal("requester must be allowed on the bound instance")
	}
	if set.InstanceAllows("github", analytics.ID, nil, "ana") || set.CodeAllows("github", nil, "ana") {
		t.Fatal("approve must not widen the grant beyond the bound instance")
	}
}

// TestApprover_Approve_BoundRequestInstanceGone: the bound instance was deleted
// meanwhile — the request cannot be approved onto nothing.
func TestApprover_Approve_BoundRequestInstanceGone(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	p := pendingInstall(t, gw, "ana", "github")
	p.RegistryID = ids.New[ids.RegistryKind]()
	installs := &fakeInstalls{findValue: p}
	regs := &fakeRegistries{items: []*registrydomain.Registry{shelfRegistry("github")}}
	a := newApproverT(t, installs, regs)
	err := a.Approve(context.Background(), ApproveRequest{GatewayID: gw, PrincipalSub: "ana", InstanceID: p.ID.String()})
	if !errors.Is(err, ErrNotShelved) {
		t.Fatalf("expected ErrNotShelved, got %v", err)
	}
	if len(installs.upserts) != 0 {
		t.Fatal("nothing may change")
	}
}

// TestApprover_Approve_NotShelved_MaterialisesWithEnsurer: a Selected principal
// may request a catalog server nobody connected yet; approving it materialises
// the registry (when an ensurer is wired), grants the code and installs, instead
// of bouncing the admin to "connect it first".
func TestApprover_Approve_NotShelved_MaterialisesWithEnsurer(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	installs := &fakeInstalls{findValue: pendingInstall(t, gw, "ana", "github")}
	regs := &fakeRegistries{}
	ensurer := &fakeEnsurer{addTo: regs}
	grants := &fakeGrants{}
	a := newApproverWith(t, installs, regs, grants, ensurer)

	if err := a.Approve(context.Background(), ApproveRequest{GatewayID: gw, PrincipalSub: "ana", Code: "github"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if len(ensurer.ensured) != 1 || ensurer.ensured[0] != "github" {
		t.Fatalf("approve must materialise the missing registry, ensured=%v", ensurer.ensured)
	}
	if len(regs.items) != 1 {
		t.Fatalf("materialised registry must exist, got %+v", regs.items)
	}
	if len(grants.upserts) != 1 || grants.upserts[0].IsInstance() || !storeaccessdomain.Index(grants.items).CodeAllows("github", nil, "ana") {
		t.Fatalf("approve must grant the code to the requester, got %+v", grants.upserts)
	}
	if len(installs.upserts) != 1 || installs.upserts[0].Status != installationdomain.StatusInstalled {
		t.Fatalf("want one installed upsert, got %+v", installs.upserts)
	}
}

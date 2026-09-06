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
	"testing"

	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func newApproverWithEnsurer(t *testing.T, installs *fakeInstalls, regs *fakeRegistries, ensurer RegistryEnsurer) Approver {
	t.Helper()
	cat := fakeCatalog{entries: map[string]catalogdomain.MCPServer{
		"github": {Code: "github", DisplayName: "GitHub"},
	}}
	a, err := NewApprover(cat, regs, installs, WithApproverEnsurer(ensurer))
	if err != nil {
		t.Fatalf("NewApprover: %v", err)
	}
	return a
}

// TestApprover_Approve_GrantsRequesterOnRestrictedShelf: approving is granting.
// A request from a principal outside the shelf's group grant, once approved,
// adds that principal's subject to store.users so their next install is instant
// and the Access page shows the grant.
func TestApprover_Approve_GrantsRequesterOnRestrictedShelf(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	installs := &fakeInstalls{findValue: pendingInstall(t, gw, "ana", "github")}
	regs := &fakeRegistries{items: []*registrydomain.Registry{
		shelfRegistry("github", &registrydomain.MCPStoreConfig{Available: true, Groups: []string{"sre"}}),
	}}
	a := newApproverT(t, installs, regs)

	if err := a.Approve(context.Background(), ApproveRequest{GatewayID: gw, PrincipalSub: "ana", Code: "github"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if len(regs.updated) != 1 {
		t.Fatalf("approve must update the shelf grant once, got %d updates", len(regs.updated))
	}
	users := regs.updated[0].MCPTarget.StoreUsers()
	if len(users) != 1 || users[0] != "ana" {
		t.Fatalf("approve must grant the requester, got users=%v", users)
	}
	if groups := regs.updated[0].MCPTarget.StoreGroups(); len(groups) != 1 || groups[0] != "sre" {
		t.Fatalf("existing group grant must be preserved, got %v", groups)
	}
	if len(installs.upserts) != 1 || installs.upserts[0].Status != installationdomain.StatusInstalled {
		t.Fatalf("want one installed upsert, got %+v", installs.upserts)
	}
	// The grant now admits the requester on the installer's own gate.
	if !storeAccessAllows(regs.updated[0].MCPTarget.StoreGroups(), regs.updated[0].MCPTarget.StoreUsers(), nil, "ana") {
		t.Fatal("after approve the requester must pass the store grant")
	}
}

// TestApprover_Approve_NotShelved_MaterialisesWithEnsurer: a Selected principal
// may request a catalog server nobody shelved yet; approving it materialises the
// shelf registry (when an ensurer is wired) and installs, instead of bouncing
// the admin to "connect it first".
func TestApprover_Approve_NotShelved_MaterialisesWithEnsurer(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	installs := &fakeInstalls{findValue: pendingInstall(t, gw, "ana", "github")}
	regs := &fakeRegistries{}
	ensurer := &fakeEnsurer{addTo: regs}
	a := newApproverWithEnsurer(t, installs, regs, ensurer)

	if err := a.Approve(context.Background(), ApproveRequest{GatewayID: gw, PrincipalSub: "ana", Code: "github"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if len(ensurer.ensured) != 1 || ensurer.ensured[0] != "github" {
		t.Fatalf("approve must materialise the missing registry, ensured=%v", ensurer.ensured)
	}
	if len(regs.items) != 1 || !regs.items[0].MCPTarget.StoreAvailable() {
		t.Fatalf("materialised registry must be on the shelf, got %+v", regs.items)
	}
	if len(installs.upserts) != 1 || installs.upserts[0].Status != installationdomain.StatusInstalled {
		t.Fatalf("want one installed upsert, got %+v", installs.upserts)
	}
}

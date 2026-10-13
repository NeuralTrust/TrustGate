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

// orphanRequest is a pending request bound to an instance that was deleted.
func orphanRequest(t *testing.T, gw ids.GatewayID, code string) *installationdomain.Installation {
	t.Helper()
	p := pendingInstall(t, gw, "ana", code)
	p.RegistryID = ids.New[ids.RegistryKind]()
	return p
}

func approveByInstance(a Approver, gw ids.GatewayID, p *installationdomain.Installation) error {
	return a.Approve(context.Background(), ApproveRequest{GatewayID: gw, PrincipalSub: "ana", InstanceID: p.ID.String()})
}

// installsWithoutRebind is an installation store that cannot rebind, like the
// data-plane proxy.
type installsWithoutRebind struct {
	installationdomain.Repository
}

func TestApprover_Approve_OrphanMovesOntoTheCurrentInstance(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	current := shelfRegistry("github")
	p := orphanRequest(t, gw, "github")
	installs := &fakeInstalls{findValue: p}
	grants := &fakeGrants{}
	a := newApproverWith(t, installs, &fakeRegistries{items: []*registrydomain.Registry{current}}, grants, nil)

	if err := approveByInstance(a, gw, p); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if len(installs.rebinds) != 1 || installs.rebinds[0] != current.ID {
		t.Fatalf("the request must be rebound to the current instance, got %v", installs.rebinds)
	}
	if len(installs.upserts) != 1 || installs.upserts[0].RegistryID != current.ID || installs.upserts[0].Status != installationdomain.StatusInstalled {
		t.Fatalf("the request must be installed on the current instance, got %+v", installs.upserts)
	}
	if len(grants.upserts) != 1 || grants.upserts[0].IsInstance() {
		t.Fatalf("a sole instance is granted as the server, got %+v", grants.upserts)
	}
}

func TestApprover_Approve_OrphanWithNoInstanceLeftMaterialises(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	p := orphanRequest(t, gw, "github")
	installs := &fakeInstalls{findValue: p}
	regs := &fakeRegistries{}
	ensurer := &fakeEnsurer{addTo: regs}
	a := newApproverWith(t, installs, regs, &fakeGrants{}, ensurer)

	if err := approveByInstance(a, gw, p); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if len(installs.rebinds) != 1 || !installs.rebinds[0].IsNil() {
		t.Fatalf("the request must become code-level, got %v", installs.rebinds)
	}
	if len(ensurer.ensured) != 1 || p.Status != installationdomain.StatusInstalled {
		t.Fatalf("approve must materialise and install, ensured=%v status=%q", ensurer.ensured, p.Status)
	}
}

func TestApprover_Approve_OrphanIsStale(t *testing.T) {
	_, customCode := customServer("Internal tools")
	cases := []struct {
		name      string
		code      string
		instances []*registrydomain.Registry
		rebindErr error
	}{
		{
			name:      "several instances left: picking one is the admin's call",
			code:      "github",
			instances: []*registrydomain.Registry{namedRegistry("github", "finance"), namedRegistry("github", "analytics")},
		},
		{
			name: "deleted custom server",
			code: customCode,
		},
		{
			name:      "requester already holds a request for the current instance",
			code:      "github",
			instances: []*registrydomain.Registry{shelfRegistry("github")},
			rebindErr: installationdomain.ErrInstanceExists,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gw := ids.New[ids.GatewayKind]()
			p := orphanRequest(t, gw, tc.code)
			installs := &fakeInstalls{findValue: p, rebindErr: tc.rebindErr}
			grants := &fakeGrants{}
			a := newApproverWith(t, installs, &fakeRegistries{items: tc.instances}, grants, &fakeEnsurer{})

			err := approveByInstance(a, gw, p)
			if !errors.Is(err, installationdomain.ErrStaleRequest) {
				t.Fatalf("want ErrStaleRequest, got %v", err)
			}
			if len(installs.upserts) != 0 || len(grants.upserts) != 0 || p.Status != installationdomain.StatusPendingApproval {
				t.Fatalf("a stale request must change nothing, upserts=%d grants=%d status=%q", len(installs.upserts), len(grants.upserts), p.Status)
			}
		})
	}
}

func TestApprover_Approve_OrphanIsStaleWithoutARebinder(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	p := orphanRequest(t, gw, "github")
	installs := &fakeInstalls{findValue: p}
	cat := fakeCatalog{entries: map[string]catalogdomain.MCPServer{"github": {Code: "github", SelfService: true}}}
	a, err := NewApprover(cat, &fakeRegistries{items: []*registrydomain.Registry{shelfRegistry("github")}}, installsWithoutRebind{installs}, &fakeGrants{})
	if err != nil {
		t.Fatalf("NewApprover: %v", err)
	}
	if err := approveByInstance(a, gw, p); !errors.Is(err, installationdomain.ErrStaleRequest) {
		t.Fatalf("want ErrStaleRequest, got %v", err)
	}
}

func TestApprover_Approve_DeletedCustomServerByCodeIsStale(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	_, code := customServer("Internal tools")
	installs := &fakeInstalls{findValue: pendingInstall(t, gw, "ana", code)}
	a := newApproverWith(t, installs, &fakeRegistries{}, &fakeGrants{}, &fakeEnsurer{})
	err := a.Approve(context.Background(), ApproveRequest{GatewayID: gw, PrincipalSub: "ana", Code: code})
	if !errors.Is(err, installationdomain.ErrStaleRequest) {
		t.Fatalf("a deleted custom server cannot be approved onto, got %v", err)
	}
}

func TestApprover_ListPending_FlagsOnlyRequestsApproveWouldRefuse(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	live, liveCode := customServer("Internal tools")
	_, goneCode := customServer("Gone tools")
	finance, analytics := namedRegistry("box", "finance"), namedRegistry("box", "analytics")

	bound := pendingInstall(t, gw, "ana", liveCode)
	bound.RegistryID = live.ID
	goneCustom := orphanRequest(t, gw, goneCode)
	rebindable := orphanRequest(t, gw, "github")
	ambiguous := orphanRequest(t, gw, "box")
	installs := &fakeInstalls{pending: []*installationdomain.Installation{bound, goneCustom, rebindable, ambiguous}}
	regs := &fakeRegistries{items: []*registrydomain.Registry{live, shelfRegistry("github"), finance, analytics}}
	a := newApproverWith(t, installs, regs, &fakeGrants{}, nil)

	pending, err := a.ListPending(context.Background(), gw)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	want := map[string]bool{
		bound.ID.String():      false,
		goneCustom.ID.String(): true,
		rebindable.ID.String(): false,
		ambiguous.ID.String():  true,
	}
	if len(pending) != len(want) {
		t.Fatalf("pending = %d rows, want %d", len(pending), len(want))
	}
	for _, row := range pending {
		if row.ServerDeleted != want[row.InstanceID] {
			t.Errorf("%s (%s): ServerDeleted = %v, want %v", row.InstanceID, row.Code, row.ServerDeleted, want[row.InstanceID])
		}
	}
}

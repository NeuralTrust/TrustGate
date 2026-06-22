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

package consumer

import (
	"testing"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
)

func routable(slug string, active bool) RoutableConsumer {
	return RoutableConsumer{
		Consumer: &domain.Consumer{
			ID:        ids.New[ids.ConsumerKind](),
			GatewayID: ids.New[ids.GatewayKind](),
			Slug:      slug,
			Active:    active,
		},
	}
}

func TestData_MatchSlug(t *testing.T) {
	t.Parallel()
	d := NewData(ids.New[ids.GatewayKind](), []RoutableConsumer{routable("X84Yhsy8", true)})

	if _, ok := d.MatchSlug("X84Yhsy8"); !ok {
		t.Fatal("MatchSlug on known slug returned ok=false")
	}
	if _, ok := d.MatchSlug("unknown1"); ok {
		t.Fatal("MatchSlug on unknown slug returned ok=true")
	}
}

func TestData_MatchSlug_SkipsInactiveConsumers(t *testing.T) {
	t.Parallel()
	d := NewData(ids.New[ids.GatewayKind](), []RoutableConsumer{routable("X84Yhsy8", false)})

	if _, ok := d.MatchSlug("X84Yhsy8"); ok {
		t.Fatal("inactive consumer must not be routable")
	}
}

func mcpRegistry(gatewayID ids.GatewayID) *registrydomain.Registry {
	return &registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		GatewayID: gatewayID,
		Type:      registrydomain.TypeMCP,
		Enabled:   true,
	}
}

func TestData_EffectiveRegistries_InlineReturnsDirectRegistries(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	reg := mcpRegistry(gatewayID)
	rc := routable("inline1x", true)
	rc.Consumer.RoutingMode = domain.RoutingModeInline
	rc.Registries = []*registrydomain.Registry{reg}
	d := NewData(gatewayID, []RoutableConsumer{rc})

	got := d.EffectiveRegistries(&d.Consumers[0])
	if len(got) != 1 || got[0].ID != reg.ID {
		t.Fatalf("inline EffectiveRegistries = %v, want [%s]", got, reg.ID)
	}
}

func TestData_EffectiveRegistries_RoleBasedUnionsRoleRegistries(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	regA := mcpRegistry(gatewayID)
	regB := mcpRegistry(gatewayID)
	roleID := ids.New[ids.RoleKind]()
	otherRoleID := ids.New[ids.RoleKind]()

	rc := routable("rolebsd1", true)
	rc.Consumer.RoutingMode = domain.RoutingModeRoleBased
	rc.Consumer.RoleIDs = []ids.RoleID{roleID}

	roles := []*roledomain.Role{
		{ID: roleID, RegistryIDs: []ids.RegistryID{regA.ID, regB.ID}},
		{ID: otherRoleID, RegistryIDs: []ids.RegistryID{mcpRegistry(gatewayID).ID}},
	}
	d := NewData(gatewayID, []RoutableConsumer{rc}, roles)
	d.SetRegistryIndex(map[ids.RegistryID]*registrydomain.Registry{
		regA.ID: regA,
		regB.ID: regB,
	})

	got := d.EffectiveRegistries(&d.Consumers[0])
	if len(got) != 2 {
		t.Fatalf("role_based EffectiveRegistries len = %d, want 2 (got %v)", len(got), got)
	}
	seen := map[ids.RegistryID]bool{}
	for _, reg := range got {
		seen[reg.ID] = true
	}
	if !seen[regA.ID] || !seen[regB.ID] {
		t.Fatalf("role_based EffectiveRegistries missing role registries: %v", got)
	}
}

func TestData_EffectiveRegistries_RoleBasedSkipsUnassignedRoles(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	reg := mcpRegistry(gatewayID)
	assignedRole := ids.New[ids.RoleKind]()
	unassignedRole := ids.New[ids.RoleKind]()

	rc := routable("rolebsd2", true)
	rc.Consumer.RoutingMode = domain.RoutingModeRoleBased
	rc.Consumer.RoleIDs = []ids.RoleID{assignedRole}

	roles := []*roledomain.Role{
		{ID: unassignedRole, RegistryIDs: []ids.RegistryID{reg.ID}},
	}
	d := NewData(gatewayID, []RoutableConsumer{rc}, roles)
	d.SetRegistryIndex(map[ids.RegistryID]*registrydomain.Registry{reg.ID: reg})

	if got := d.EffectiveRegistries(&d.Consumers[0]); len(got) != 0 {
		t.Fatalf("EffectiveRegistries from unassigned role = %v, want empty", got)
	}
}

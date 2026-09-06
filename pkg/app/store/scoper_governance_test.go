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

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func withPrincipalGroups(sub string, groups ...string) context.Context {
	return identity.WithPrincipal(context.Background(), &identity.Principal{
		Subject: sub,
		Claims:  map[string]any{identity.ClaimGroups: groups},
	})
}

func snowflakeShelf(store *registrydomain.MCPStoreConfig) *registrydomain.Registry {
	return &registrydomain.Registry{
		ID:   ids.New[ids.RegistryKind](),
		Name: "Snowflake",
		MCPTarget: &registrydomain.MCPTarget{
			Code:         "snowflake",
			URL:          "https://acme/api/v2/databases/{database}/mcp",
			URLVariables: []registrydomain.MCPURLVariable{{Name: "database", Required: true}},
			Store:        store,
		},
	}
}

// TestScoperSingleConfiguredInstanceCarriesOverlay guards fix 4: a code with one
// active install that carries config is exposed under the shelf's own id and
// name, but on a clone whose target carries the config overlay — so the dial-time
// resolver never falls back to the ambiguous by-code Find.
func TestScoperSingleConfiguredInstanceCarriesOverlay(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	shelf := snowflakeShelf(nil)
	only, _ := installationdomain.New(gw, "ana", "snowflake", "ana", map[string]string{"database": "analytics"})
	sc, _ := NewScoper(
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{only}},
		&fakeRegistries{items: []*registrydomain.Registry{shelf}},
	)
	rc := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}
	scoped, err := sc.Scope(withOpenPrincipal("ana"), rc)
	if err != nil {
		t.Fatalf("Scope: %v", err)
	}
	if len(scoped.Registries) != 1 {
		t.Fatalf("expected one registry, got %d", len(scoped.Registries))
	}
	got := scoped.Registries[0]
	if got.ID != shelf.ID || got.Name != "Snowflake" {
		t.Fatalf("single instance must keep the shelf id and name (no relabel), got id=%s name=%q", got.ID, got.Name)
	}
	if got.MCPTarget.InstanceConfig["database"] != "analytics" {
		t.Fatalf("single configured instance must carry its config overlay, got %+v", got.MCPTarget.InstanceConfig)
	}
	if got == shelf || shelf.MCPTarget.InstanceConfig != nil {
		t.Fatal("the shared shelf registry must not be mutated")
	}
}

func TestScoperSingleUnconfiguredInstanceExposesShelfAsIs(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	shelf := githubRegistry()
	sc, _ := NewScoper(
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{mustInstall(t, gw, "ana", "github")}},
		&fakeRegistries{items: []*registrydomain.Registry{shelf}},
	)
	rc := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}
	scoped, _ := sc.Scope(withOpenPrincipal("ana"), rc)
	if len(scoped.Registries) != 1 || scoped.Registries[0] != shelf {
		t.Fatal("an install without config exposes the shelf registry pointer unchanged")
	}
}

// TestScoperHidesInstallWhenGrantTightened guards fix 4's second half: an
// install whose shelf registry now names groups the principal is not in is not
// exposed — tightening a grant after the install revokes exposure.
func TestScoperHidesInstallWhenGrantTightened(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	shelf := snowflakeShelf(&registrydomain.MCPStoreConfig{Available: true, Groups: []string{"data-eng"}})
	installed := mustInstall(t, gw, "ana", "snowflake")
	sc, _ := NewScoper(
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{installed}},
		&fakeRegistries{items: []*registrydomain.Registry{shelf}},
	)
	rc := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}

	excluded, err := sc.Scope(withPrincipalGroups("ana", "marketing"), rc)
	if err != nil {
		t.Fatalf("Scope: %v", err)
	}
	if len(excluded.Registries) != 0 {
		t.Fatalf("a principal outside the grant must not see the install, got %d", len(excluded.Registries))
	}
	noGroups, _ := sc.Scope(withPrincipal("ana"), rc)
	if len(noGroups.Registries) != 0 {
		t.Fatal("a principal with no groups must not see a group-gated install")
	}

	member, err := sc.Scope(withPrincipalGroups("ana", "data-eng"), rc)
	if err != nil {
		t.Fatalf("Scope: %v", err)
	}
	if len(member.Registries) != 1 {
		t.Fatalf("a group member must still see the install, got %d", len(member.Registries))
	}
}

func TestScoperUserGrantAdmitsSubject(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	shelf := snowflakeShelf(&registrydomain.MCPStoreConfig{Available: true, Users: []string{"ana"}})
	sc, _ := NewScoper(
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{mustInstall(t, gw, "ana", "snowflake")}},
		&fakeRegistries{items: []*registrydomain.Registry{shelf}},
	)
	rc := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}
	scoped, _ := sc.Scope(withPrincipal("ana"), rc)
	if len(scoped.Registries) != 1 {
		t.Fatal("a subject named in the user grant must see the install")
	}
}

// Multi-instance exposure is also gated: both clones disappear when excluded.
func TestScoperGrantAppliesToEveryInstance(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	shelf := snowflakeShelf(&registrydomain.MCPStoreConfig{Available: true, Groups: []string{"data-eng"}})
	a, _ := installationdomain.New(gw, "ana", "snowflake", "ana", map[string]string{"database": "a"})
	b, _ := installationdomain.New(gw, "ana", "snowflake", "ana", map[string]string{"database": "b"})
	sc, _ := NewScoper(
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{a, b}},
		&fakeRegistries{items: []*registrydomain.Registry{shelf}},
	)
	rc := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}
	if scoped, _ := sc.Scope(withPrincipalGroups("ana", "marketing"), rc); len(scoped.Registries) != 0 {
		t.Fatalf("excluded principal must see no instances, got %d", len(scoped.Registries))
	}
	if scoped, _ := sc.Scope(withPrincipalGroups("ana", "data-eng"), rc); len(scoped.Registries) != 2 {
		t.Fatalf("member must see both instances, got %d", len(scoped.Registries))
	}
}

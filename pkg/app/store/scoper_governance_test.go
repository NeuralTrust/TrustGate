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
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
)

func withPrincipalGroups(sub string, groups ...string) context.Context {
	return identity.WithPrincipal(context.Background(), &identity.Principal{
		Subject: sub,
		Claims:  map[string]any{identity.ClaimGroups: groups},
	})
}

func snowflakeShelf() *registrydomain.Registry {
	return &registrydomain.Registry{
		ID:   ids.New[ids.RegistryKind](),
		Name: "Snowflake",
		MCPTarget: &registrydomain.MCPTarget{
			Code:         "snowflake",
			URL:          "https://acme/api/v2/databases/{database}/mcp",
			URLVariables: []registrydomain.MCPURLVariable{{Name: "database", Required: true}},
		},
	}
}

// newScoperT wires a scoper over the given installs, registries and grants.
func newScoperT(t *testing.T, installs *fakeInstalls, regs *fakeRegistries, grants storeaccessdomain.Reader) Scoper {
	t.Helper()
	sc, err := NewScoper(installs, regs, grants)
	if err != nil {
		t.Fatalf("NewScoper: %v", err)
	}
	return sc
}

// TestScoperSingleConfiguredInstanceCarriesOverlay guards fix 4: a code with one
// active install that carries config is exposed under the shelf's own id and
// name, but on a clone whose target carries the config overlay — so the dial-time
// resolver never falls back to the ambiguous by-code Find.
func TestScoperSingleConfiguredInstanceCarriesOverlay(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	shelf := snowflakeShelf()
	only, _ := installationdomain.New(gw, "ana", "snowflake", "ana", map[string]string{"database": "analytics"})
	sc := newScoperT(t,
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{only}},
		&fakeRegistries{items: []*registrydomain.Registry{shelf}},
		nil,
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
	sc := newScoperT(t,
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{mustInstall(t, gw, "ana", "github")}},
		&fakeRegistries{items: []*registrydomain.Registry{shelf}},
		nil,
	)
	rc := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}
	scoped, _ := sc.Scope(withOpenPrincipal("ana"), rc)
	if len(scoped.Registries) != 1 || scoped.Registries[0] != shelf {
		t.Fatal("an install without config exposes the shelf registry pointer unchanged")
	}
}

// TestScoperHidesInstallWhenGrantTightened guards fix 4's second half: an
// install whose code grant now names groups the principal is not in is not
// exposed — tightening a grant after the install revokes exposure.
func TestScoperHidesInstallWhenGrantTightened(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	shelf := snowflakeShelf()
	installed := mustInstall(t, gw, "ana", "snowflake")
	sc := newScoperT(t,
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{installed}},
		&fakeRegistries{items: []*registrydomain.Registry{shelf}},
		grantsOf(codeGrant(gw, "snowflake", []string{"data-eng"}, nil)),
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
	shelf := snowflakeShelf()
	sc := newScoperT(t,
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{mustInstall(t, gw, "ana", "snowflake")}},
		&fakeRegistries{items: []*registrydomain.Registry{shelf}},
		grantsOf(codeGrant(gw, "snowflake", nil, []string{"ana"})),
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
	shelf := snowflakeShelf()
	a, _ := installationdomain.New(gw, "ana", "snowflake", "ana", map[string]string{"database": "a"})
	b, _ := installationdomain.New(gw, "ana", "snowflake", "ana", map[string]string{"database": "b"})
	sc := newScoperT(t,
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{a, b}},
		&fakeRegistries{items: []*registrydomain.Registry{shelf}},
		grantsOf(codeGrant(gw, "snowflake", []string{"data-eng"}, nil)),
	)
	rc := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}
	if scoped, _ := sc.Scope(withPrincipalGroups("ana", "marketing"), rc); len(scoped.Registries) != 0 {
		t.Fatalf("excluded principal must see no instances, got %d", len(scoped.Registries))
	}
	if scoped, _ := sc.Scope(withPrincipalGroups("ana", "data-eng"), rc); len(scoped.Registries) != 2 {
		t.Fatalf("member must see both instances, got %d", len(scoped.Registries))
	}
}

// TestScoperInstanceGrantExposesOnlyThatInstance: under Selected an install
// bound to a granted instance is exposed; an install bound to an ungranted
// instance of the same code is not, and neither is one on the canonical
// instance when only another instance is granted.
func TestScoperInstanceGrantExposesOnlyThatInstance(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	finance := namedRegistry("snowflake", "Snowflake (finance)")
	analytics := namedRegistry("snowflake", "Snowflake (analytics)")
	onFinance := mustInstall(t, gw, "ana", "snowflake")
	onFinance.RegistryID = finance.ID
	onAnalytics := mustInstall(t, gw, "ana", "snowflake")
	onAnalytics.RegistryID = analytics.ID
	sc := newScoperT(t,
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{onFinance, onAnalytics}},
		&fakeRegistries{items: []*registrydomain.Registry{finance, analytics}},
		grantsOf(instanceGrant(gw, "snowflake", finance.ID, []string{"finance"}, nil)),
	)
	rc := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}
	scoped, err := sc.Scope(withPrincipalGroups("ana", "finance"), rc)
	if err != nil {
		t.Fatalf("Scope: %v", err)
	}
	if len(scoped.Registries) != 1 || scoped.Registries[0].Name != "Snowflake (finance)" {
		t.Fatalf("only the granted instance may be exposed, got %+v", names(scoped.Registries))
	}
	// Under All both are exposed, each as its own instance clone.
	open, _ := sc.Scope(appgateway.WithGateway(withPrincipalGroups("ana", "finance"), &gatewaydomain.Gateway{}), rc)
	if len(open.Registries) != 2 {
		t.Fatalf("All must expose both bound instances, got %d", len(open.Registries))
	}
}

// TestScoperBoundInstallFollowsItsRegistry: an install bound to a registry
// exposes that registry even when it is not the code's canonical (oldest) one,
// and goes dormant when the registry is deleted or re-pointed to another code.
func TestScoperBoundInstallFollowsItsRegistry(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	first := namedRegistry("snowflake", "first")
	second := namedRegistry("snowflake", "second")
	bound := mustInstall(t, gw, "ana", "snowflake")
	bound.RegistryID = second.ID
	installs := &fakeInstalls{byPrincipal: []*installationdomain.Installation{bound}}
	rc := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}

	sc := newScoperT(t, installs, &fakeRegistries{items: []*registrydomain.Registry{first, second}}, nil)
	scoped, _ := sc.Scope(withOpenPrincipal("ana"), rc)
	if len(scoped.Registries) != 1 || scoped.Registries[0].ID != second.ID {
		t.Fatalf("bound install must expose its own registry, got %+v", names(scoped.Registries))
	}

	gone := newScoperT(t, installs, &fakeRegistries{items: []*registrydomain.Registry{first}}, nil)
	if scoped, _ := gone.Scope(withOpenPrincipal("ana"), rc); len(scoped.Registries) != 0 {
		t.Fatal("an install bound to a deleted registry must not fall back to another instance")
	}

	repointed := namedRegistry("github", "was-snowflake")
	repointed.ID = second.ID
	moved := newScoperT(t, installs, &fakeRegistries{items: []*registrydomain.Registry{first, repointed}}, nil)
	if scoped, _ := moved.Scope(withOpenPrincipal("ana"), rc); len(scoped.Registries) != 0 {
		t.Fatal("a registry re-pointed to another code must not leak through a stale binding")
	}
}

func names(regs []*registrydomain.Registry) []string {
	out := make([]string, 0, len(regs))
	for _, r := range regs {
		out = append(out, r.Name)
	}
	return out
}

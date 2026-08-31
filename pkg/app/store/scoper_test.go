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

func mustInstall(t *testing.T, gw ids.GatewayID, sub, code string) *installationdomain.Installation {
	t.Helper()
	in, err := installationdomain.New(gw, sub, code, sub, nil)
	if err != nil {
		t.Fatalf("new install: %v", err)
	}
	return in
}

func withPrincipal(sub string) context.Context {
	return identity.WithPrincipal(context.Background(), &identity.Principal{Subject: sub})
}

func githubRegistry() *registrydomain.Registry {
	return &registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		MCPTarget: &registrydomain.MCPTarget{Code: "github"},
	}
}

func TestScoperSurfacesInstalledRegistries(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := githubRegistry()
	installs := &fakeInstalls{byPrincipal: []*installationdomain.Installation{mustInstall(t, gw, "ana", "github")}}
	regs := &fakeRegistries{items: []*registrydomain.Registry{reg, {
		ID: ids.New[ids.RegistryKind](), MCPTarget: &registrydomain.MCPTarget{Code: "salesforce"},
	}}}

	sc, err := NewScoper(installs, regs)
	if err != nil {
		t.Fatalf("NewScoper: %v", err)
	}
	rc := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}
	scoped, err := sc.Scope(withPrincipal("ana"), rc)
	if err != nil {
		t.Fatalf("Scope: %v", err)
	}
	if len(scoped.Registries) != 1 || scoped.Registries[0].ID != reg.ID {
		t.Fatalf("must surface only the installed github registry, got %+v", scoped.Registries)
	}
	// The shared synthetic Store consumer must not be mutated.
	if len(rc.Registries) != 0 {
		t.Fatal("the source Store consumer must not be mutated")
	}
}

func TestScoperLeavesRegularConsumerUntouched(t *testing.T) {
	sc, _ := NewScoper(&fakeInstalls{}, &fakeRegistries{})
	rc := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{
		ID: ids.New[ids.ConsumerKind](), Slug: "regular", Type: consumerdomain.TypeMCP,
	}}
	scoped, err := sc.Scope(withPrincipal("ana"), rc)
	if err != nil {
		t.Fatalf("Scope: %v", err)
	}
	if scoped != rc {
		t.Fatal("a non-Store consumer must be returned unchanged")
	}
}

func TestScoperNoInstallsLeavesStoreEmpty(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	sc, _ := NewScoper(&fakeInstalls{}, &fakeRegistries{items: []*registrydomain.Registry{githubRegistry()}})
	rc := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}
	scoped, err := sc.Scope(withPrincipal("ana"), rc)
	if err != nil {
		t.Fatalf("Scope: %v", err)
	}
	if len(scoped.Registries) != 0 {
		t.Fatalf("no installs must surface no registries, got %+v", scoped.Registries)
	}
}

func TestScoperWithoutPrincipalIsNoop(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	sc, _ := NewScoper(&fakeInstalls{byPrincipal: []*installationdomain.Installation{mustInstall(t, gw, "ana", "github")}},
		&fakeRegistries{items: []*registrydomain.Registry{githubRegistry()}})
	rc := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}
	scoped, err := sc.Scope(context.Background(), rc)
	if err != nil {
		t.Fatalf("Scope: %v", err)
	}
	if scoped != rc {
		t.Fatal("without an authenticated principal the Store must be returned unchanged")
	}
}

func TestScoperIgnoresRevokedInstalls(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	revoked := mustInstall(t, gw, "ana", "github")
	revoked.Status = installationdomain.StatusRevoked
	sc, _ := NewScoper(
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{revoked}},
		&fakeRegistries{items: []*registrydomain.Registry{githubRegistry()}},
	)
	rc := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}
	scoped, _ := sc.Scope(withPrincipal("ana"), rc)
	if len(scoped.Registries) != 0 {
		t.Fatal("a revoked install must not surface its registry")
	}
}

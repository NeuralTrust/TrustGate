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

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func disabledRegistry(code, name string) *registrydomain.Registry {
	reg := namedRegistry(code, name)
	reg.Enabled = false
	return reg
}

func TestInstallNamedDisabledInstanceIsRefused(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	off := disabledRegistry("github", "off")
	on := namedRegistry("github", "on")
	installs := &fakeInstalls{}
	inst := newInstaller(t, &fakeRegistries{items: []*registrydomain.Registry{off, on}}, installs)

	in := openReq(gw, "github")
	in.RegistryID = off.ID
	if _, err := inst.Install(context.Background(), in); !errors.Is(err, ErrServerDisabled) {
		t.Fatalf("a turned-off instance must not install, got %v", err)
	}
	in.RegistryID = ids.New[ids.RegistryKind]()
	if _, err := inst.Install(context.Background(), in); !errors.Is(err, ErrUnknownInstance) {
		t.Fatalf("an unknown instance must still be reported as unknown, got %v", err)
	}
	if len(installs.upserts) != 0 {
		t.Fatalf("a refused install must record nothing, got %+v", installs.upserts)
	}
}

func TestInstallEveryInstanceDisabledIsRefusedWithoutMaterialising(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{disabledRegistry("github", "off")}}
	ensurer := &fakeEnsurer{addTo: regs}
	installs := &fakeInstalls{}
	inst := newInstallerWithEnsurer(t, regs, installs, ensurer)

	for name, in := range map[string]InstallRequest{"open": openReq(gw, "github"), "selected": req(gw, "github")} {
		if _, err := inst.Install(context.Background(), in); !errors.Is(err, ErrServerDisabled) {
			t.Fatalf("%s: a server whose every instance is off must be refused, got %v", name, err)
		}
	}
	if len(ensurer.ensured) != 0 {
		t.Fatalf("a turned-off server must not be materialised again, got %+v", ensurer.ensured)
	}
	if len(installs.upserts) != 0 {
		t.Fatalf("a refused install must record nothing, got %+v", installs.upserts)
	}
}

func TestInstallSkipsDisabledInstanceAndBindsTheEnabledOne(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	off := disabledRegistry("github", "off")
	on := namedRegistry("github", "on")
	installs := &fakeInstalls{}
	res, err := newInstaller(t, &fakeRegistries{items: []*registrydomain.Registry{off, on}}, installs).
		Install(context.Background(), openReq(gw, "github"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.RequiresInstanceChoice || res.Status != installationdomain.StatusInstalled {
		t.Fatalf("the one enabled instance must install without a choice, got %+v", res)
	}
	// Left implicit, the binding would resolve to the oldest registry of the
	// code, which is the turned-off one.
	if len(installs.upserts) != 1 || installs.upserts[0].RegistryID != on.ID {
		t.Fatalf("the install must be bound to the enabled instance, got %+v", installs.upserts)
	}
}

func scopeStore(t *testing.T, sc Scoper, gw ids.GatewayID, sub string) []*registrydomain.Registry {
	t.Helper()
	scoped, err := sc.Scope(withOpenPrincipal(sub), &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)})
	if err != nil {
		t.Fatalf("Scope: %v", err)
	}
	return scoped.Registries
}

func TestScoperHidesInstallOfDisabledInstance(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := githubRegistry()
	install := mustInstall(t, gw, "ana", "github")
	install.RegistryID = reg.ID
	regs := &fakeRegistries{items: []*registrydomain.Registry{reg}}
	sc := newScoperT(t, &fakeInstalls{byPrincipal: []*installationdomain.Installation{install}}, regs, nil)

	if got := scopeStore(t, sc, gw, "ana"); len(got) != 1 {
		t.Fatalf("an enabled instance must be exposed, got %+v", got)
	}
	reg.Enabled = false
	if got := scopeStore(t, sc, gw, "ana"); len(got) != 0 {
		t.Fatalf("a turned-off instance must not be exposed, got %+v", got)
	}
}

func TestScoperDoesNotMoveUnboundInstallOffDisabledInstance(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	off := disabledRegistry("github", "oldest")
	on := namedRegistry("github", "newer")
	install := mustInstall(t, gw, "ana", "github")
	sc := newScoperT(t,
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{install}},
		&fakeRegistries{items: []*registrydomain.Registry{off, on}},
		nil)

	if got := scopeStore(t, sc, gw, "ana"); len(got) != 0 {
		t.Fatalf("an unbound install of a turned-off instance must stay dormant, not move to %+v", got)
	}
}

func TestScoperTurningAnInstanceOffDoesNotRenameItsSibling(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	finance := namedRegistry("github", "finance")
	analytics := namedRegistry("github", "analytics")
	onFinance := mustInstall(t, gw, "ana", "github")
	onFinance.RegistryID = finance.ID
	onAnalytics := mustInstall(t, gw, "ana", "github")
	onAnalytics.RegistryID = analytics.ID
	sc := newScoperT(t,
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{onFinance, onAnalytics}},
		&fakeRegistries{items: []*registrydomain.Registry{finance, analytics}},
		nil)

	before := scopeStore(t, sc, gw, "ana")
	if len(before) != 2 {
		t.Fatalf("both instances must be exposed, got %+v", before)
	}
	finance.Enabled = false
	after := scopeStore(t, sc, gw, "ana")
	if len(after) != 1 || after[0].InstanceOf != analytics.ID {
		t.Fatalf("only the enabled instance must be exposed, got %+v", after)
	}
	var sibling *registrydomain.Registry
	for _, reg := range before {
		if reg.InstanceOf == analytics.ID {
			sibling = reg
		}
	}
	if sibling == nil || after[0].ID != sibling.ID || after[0].Name != sibling.Name {
		t.Fatalf("the sibling must keep the id and name its tools are named from, got %+v, was %+v", after[0], sibling)
	}
}

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

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// adminRow is an admin instance of kibana whose URL fixes some of the catalog
// placeholders and keeps the rest.
func adminRow(url string) *registrydomain.Registry {
	reg := shelfRegistry("kibana")
	reg.MCPTarget.URL = url
	return reg
}

func configNames(vars []registrydomain.MCPURLVariable) []string {
	out := make([]string, 0, len(vars))
	for _, v := range vars {
		out = append(out, v.Name)
	}
	return out
}

// The admin row fixed the host, so the install asks only for the space.
func TestInstall_DoesNotAskForAVariableTheAdminRowPins(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{adminRow("https://acme.kb.example.com/s/{space}/mcp")}}
	installs := &fakeInstalls{}

	res, err := newInstaller(t, regs, installs).Install(context.Background(), openReq(gw, "kibana"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if got := configNames(res.ConfigVariables); !res.RequiresConfig || len(got) != 1 || got[0] != "space" {
		t.Fatalf("want only the unpinned space requested, got %+v", res)
	}
	if len(installs.upserts) != 0 {
		t.Fatalf("a requires-config result records nothing, got %+v", installs.upserts)
	}
}

// A pinned value the caller still sends is dropped, not validated and not
// stored: the dial uses the admin row's URL whatever it is. The unpinned value
// is stored and used as before.
func TestInstall_IgnoresAPinnedValueAndKeepsTheUnpinnedOne(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{adminRow("https://acme.kb.example.com/s/{space}/mcp")}}
	installs := &fakeInstalls{}
	in := openReq(gw, "kibana")
	in.Config = map[string]string{"host": "-not/a/host", "space": "default"}

	res, err := newInstaller(t, regs, installs).Install(context.Background(), in)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.RequiresConfig || res.Status != installationdomain.StatusInstalled {
		t.Fatalf("want an install, got %+v", res)
	}
	cfg := installs.upserts[0].Config
	if len(cfg) != 1 || cfg["space"] != "default" {
		t.Fatalf("want only the unpinned value stored, got %+v", cfg)
	}
}

// Every placeholder pinned: nothing to ask, nothing to store.
func TestInstall_FullyPinnedAdminRowInstallsWithoutConfig(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{adminRow("https://acme.kb.example.com/s/default/mcp")}}
	installs := &fakeInstalls{}

	res, err := newInstaller(t, regs, installs).Install(context.Background(), openReq(gw, "kibana"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.RequiresConfig || len(res.ConfigVariables) != 0 || res.Status != installationdomain.StatusInstalled {
		t.Fatalf("want an install with nothing asked, got %+v", res)
	}
	if cfg := installs.upserts[0].Config; len(cfg) != 0 {
		t.Fatalf("want no config stored, got %+v", cfg)
	}
}

// An admin row that keeps the catalog template pins nothing.
func TestInstall_TemplatedAdminRowStillAsksForEveryVariable(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{adminRow("https://{host}/s/{space}/mcp")}}

	res, err := newInstaller(t, regs, &fakeInstalls{}).Install(context.Background(), openReq(gw, "kibana"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if got := configNames(res.ConfigVariables); len(got) != 2 {
		t.Fatalf("want both variables requested, got %v", got)
	}
}

// No admin row: the registry is materialised from the catalog and every
// declared variable is asked for, as before.
func TestInstall_WithoutAnAdminRowAsksForEveryVariable(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{}

	res, err := newInstallerWithEnsurer(t, regs, &fakeInstalls{}, &fakeEnsurer{addTo: regs}).
		Install(context.Background(), openReq(gw, "kibana"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if got := configNames(res.ConfigVariables); !res.RequiresConfig || len(got) != 2 || got[0] != "host" || got[1] != "space" {
		t.Fatalf("want host and space requested, got %+v", res)
	}
}

// The instance the install names is the one whose pins count.
func TestInstall_NamedInstanceDecidesWhatIsPinned(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	pinned := adminRow("https://acme.kb.example.com/s/{space}/mcp")
	templated := adminRow("https://{host}/s/{space}/mcp")
	regs := &fakeRegistries{items: []*registrydomain.Registry{pinned, templated}}

	in := openReq(gw, "kibana")
	in.RegistryID = templated.ID
	res, err := newInstaller(t, regs, &fakeInstalls{}).Install(context.Background(), in)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if got := configNames(res.ConfigVariables); len(got) != 2 {
		t.Fatalf("the templated instance pins nothing, got %v", got)
	}

	in.RegistryID = pinned.ID
	res, err = newInstaller(t, regs, &fakeInstalls{}).Install(context.Background(), in)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if got := configNames(res.ConfigVariables); len(got) != 1 || got[0] != "space" {
		t.Fatalf("the pinned instance fixes the host, got %v", got)
	}
}

func TestPrincipalPreview_PinnedVariableIsNeverMissing(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	row := mustInstall(t, gw, "ana", "kibana")
	p, err := NewPrincipalPreview(
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{row}},
		&fakeRegistries{items: []*registrydomain.Registry{adminRow("https://acme.kb.example.com/s/{space}/mcp")}},
		testCatalog(), nil,
	)
	if err != nil {
		t.Fatalf("NewPrincipalPreview: %v", err)
	}
	state, err := p.Preview(context.Background(), gw, "ana")
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if got := state.Installs[0].NeedsConfig; len(got) != 1 || got[0] != "space" {
		t.Fatalf("want only space missing, got %v", got)
	}
}

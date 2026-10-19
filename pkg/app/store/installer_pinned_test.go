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
	"strings"
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

// The admin row fixed the host, so the install asks only for the space.
func TestInstall_DoesNotAskForAVariableTheAdminRowPins(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{adminRow("https://acme.kb.example.com/s/{space}/mcp")}}
	installs := &fakeInstalls{}

	_, err := newInstaller(t, regs, installs).Install(context.Background(), openReq(gw, "kibana"))
	if err == nil || !errors.Is(err, ErrConfigInvalid) || !strings.Contains(err.Error(), `variable "space" must be set by an admin`) {
		t.Fatalf("the remaining placeholder must be filled by an admin, got %v", err)
	}
	if len(installs.upserts) != 0 {
		t.Fatalf("nothing is recorded, got %+v", installs.upserts)
	}
}

// Host and space are both registry variables. An employee who still sends
// either is refused, and nothing is stored. Map iteration picks which name
// the error quotes.
func TestInstall_IgnoresAPinnedValueAndKeepsTheUnpinnedOne(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{adminRow("https://acme.kb.example.com/s/{space}/mcp")}}
	installs := &fakeInstalls{}
	in := openReq(gw, "kibana")
	in.Config = map[string]string{"host": "-not/a/host", "space": "default"}

	_, err := newInstaller(t, regs, installs).Install(context.Background(), in)
	if err == nil || !errors.Is(err, ErrConfigInvalid) || !strings.Contains(err.Error(), "is set by an admin") {
		t.Fatalf("an employee host or space must be refused, got %v", err)
	}
	if len(installs.upserts) != 0 {
		t.Fatalf("nothing is recorded, got %+v", installs.upserts)
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

	_, err := newInstaller(t, regs, &fakeInstalls{}).Install(context.Background(), openReq(gw, "kibana"))
	if err == nil || !errors.Is(err, ErrConfigInvalid) || !strings.Contains(err.Error(), "must be set by an admin") {
		t.Fatalf("a catalog template must be filled by an admin, got %v", err)
	}
}

// No admin row: the registry is materialised from the catalog and every
// declared variable is asked for, as before.
func TestInstall_WithoutAnAdminRowAsksForEveryVariable(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{}

	_, err := newInstallerWithEnsurer(t, regs, &fakeInstalls{}, &fakeEnsurer{addTo: regs}).
		Install(context.Background(), openReq(gw, "kibana"))
	if err == nil || !errors.Is(err, ErrConfigInvalid) || !strings.Contains(err.Error(), "must be set by an admin") {
		t.Fatalf("a materialised template must be filled by an admin, got %v", err)
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
	if _, err := newInstaller(t, regs, &fakeInstalls{}).Install(context.Background(), in); err == nil || !strings.Contains(err.Error(), `variable "host" must be set by an admin`) {
		t.Fatalf("the templated instance must be filled by an admin, got %v", err)
	}

	in.RegistryID = pinned.ID
	if _, err := newInstaller(t, regs, &fakeInstalls{}).Install(context.Background(), in); err == nil || !strings.Contains(err.Error(), `variable "space" must be set by an admin`) {
		t.Fatalf("the remaining placeholder must be filled by an admin, got %v", err)
	}
}

// A row written when host was still per-user stores it. The admin URL has
// since fixed host, so a reinstall only carries space. That is the same
// instance: a second row would rename the tools and make an uninstall
// without an id ambiguous.
func TestInstall_ReinstallOverARowThatStoresAPinnedKey(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	row := adminRow("https://acme.kb.example.com/s/{space}/mcp")
	old, err := installationdomain.New(gw, "ana", "kibana", "ana", map[string]string{
		"host":  "acme.kb.example.com",
		"space": "default",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	installs := &fakeInstalls{byCode: []*installationdomain.Installation{old}}
	in := openReq(gw, "kibana")
	in.Config = map[string]string{"space": "default"}

	_, err = newInstaller(t, &fakeRegistries{items: []*registrydomain.Registry{row}}, installs).Install(context.Background(), in)
	if err == nil || !errors.Is(err, ErrConfigInvalid) || !strings.Contains(err.Error(), `variable "space" is set by an admin`) {
		t.Fatalf("space is a registry variable, got %v", err)
	}
}

// The pinned key is ignored on both sides, not the whole config: a different
// space is still a second instance.
func TestInstall_ReinstallWithADifferentUnpinnedValueIsANewRow(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	row := adminRow("https://acme.kb.example.com/s/{space}/mcp")
	old, err := installationdomain.New(gw, "ana", "kibana", "ana", map[string]string{
		"host":  "acme.kb.example.com",
		"space": "default",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	installs := &fakeInstalls{byCode: []*installationdomain.Installation{old}}
	in := openReq(gw, "kibana")
	in.Config = map[string]string{"space": "finance"}

	_, err = newInstaller(t, &fakeRegistries{items: []*registrydomain.Registry{row}}, installs).Install(context.Background(), in)
	if err == nil || !errors.Is(err, ErrConfigInvalid) || !strings.Contains(err.Error(), `variable "space" is set by an admin`) {
		t.Fatalf("a different space is a different registry row, got %v", err)
	}
}

// Two rows that differ only by a key the serving URL now pins are one
// instance. Counting both renames each one's tools.
func TestDistinctInstalls_PinnedKeyDoesNotSplitTheInstance(t *testing.T) {
	shelf := adminRow("https://acme.kb.example.com/s/{space}/mcp")
	old := &installationdomain.Installation{
		ID: ids.New[ids.InstallationKind](), CatalogCode: "kibana",
		Status: installationdomain.StatusInstalled,
		Config: map[string]string{"host": "acme.kb.example.com", "space": "default"},
	}
	fresh := &installationdomain.Installation{
		ID: ids.New[ids.InstallationKind](), CatalogCode: "kibana",
		Status: installationdomain.StatusInstalled,
		Config: map[string]string{"space": "default"},
	}
	other := &installationdomain.Installation{
		ID: ids.New[ids.InstallationKind](), CatalogCode: "kibana",
		Status: installationdomain.StatusInstalled,
		Config: map[string]string{"host": "acme.kb.example.com", "space": "finance"},
	}
	byID := map[ids.RegistryID]*registrydomain.Registry{shelf.ID: shelf}
	byCode := map[string][]*registrydomain.Registry{"kibana": {shelf}}

	got, counts := distinctInstalls([]*installationdomain.Installation{old, fresh}, byID, byCode)
	if len(got) != 1 || counts["kibana"] != 1 {
		t.Fatalf("pinned host must not split the instance, got %d (count %d)", len(got), counts["kibana"])
	}
	got, counts = distinctInstalls([]*installationdomain.Installation{old, other}, byID, byCode)
	if len(got) != 2 || counts["kibana"] != 2 {
		t.Fatalf("a different space stays two instances, got %d (count %d)", len(got), counts["kibana"])
	}
}

// A fixed MCP URL with a manual client whose authorize and token URLs still
// template the tenant does not pin that variable: the connect path fills it.
func TestInstall_OAuthTemplateKeepsTheVariable(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	row := shelfRegistry("com.aha/mcp")
	row.MCPTarget.URL = "https://acme.aha.io/api/v1/mcp"
	row.MCPTarget.Auth = &registrydomain.MCPAuth{
		Mode:         registrydomain.MCPAuthModeForwarded,
		Registration: registrydomain.RegistrationManual,
		ClientID:     "admin-client",
		AuthorizeURL: "https://{domain}.aha.io/oauth/authorize",
		TokenURL:     "https://{domain}.aha.io/oauth/token",
	}

	res, err := newInstaller(t, &fakeRegistries{items: []*registrydomain.Registry{row}}, &fakeInstalls{}).
		Install(context.Background(), openReq(gw, "com.aha/mcp"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.RequiresConfig || len(res.ConfigVariables) != 0 || res.Status != installationdomain.StatusInstalled {
		t.Fatalf("the admin URL supplies domain even while the oauth templates name it, got %+v", res)
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
	if got := state.Installs[0].NeedsConfig; len(got) != 0 {
		t.Fatalf("a non-secret variable is not missing employee config, got %v", got)
	}
}

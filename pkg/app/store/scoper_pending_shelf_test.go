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
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// indexedRegistries is the data-plane registry read: by id and by catalog code,
// which is what the snapshot adapter implements. Items are the whole snapshot.
type indexedRegistries struct {
	items []*registrydomain.Registry
	err   error
}

func (r indexedRegistries) List(context.Context, registrydomain.ListFilter) ([]*registrydomain.Registry, int, error) {
	if r.err != nil {
		return nil, 0, r.err
	}
	return r.items, len(r.items), nil
}

func (r indexedRegistries) ListByGateway(context.Context, ids.GatewayID) ([]*registrydomain.Registry, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.items, nil
}

func (r indexedRegistries) ListByGatewayAndIDs(_ context.Context, _ ids.GatewayID, want []ids.RegistryID) ([]*registrydomain.Registry, error) {
	if r.err != nil {
		return nil, r.err
	}
	var out []*registrydomain.Registry
	for _, reg := range r.items {
		for _, id := range want {
			if reg != nil && reg.ID == id {
				out = append(out, reg)
			}
		}
	}
	return out, nil
}

func (r indexedRegistries) ListByGatewayAndCatalogCode(_ context.Context, _ ids.GatewayID, code string) ([]*registrydomain.Registry, error) {
	if r.err != nil {
		return nil, r.err
	}
	var out []*registrydomain.Registry
	for _, reg := range r.items {
		if reg != nil && registrydomain.StoreCode(reg) == code {
			out = append(out, reg)
		}
	}
	return out, nil
}

func deepWikiEntry() catalogdomain.MCPServer {
	return catalogdomain.MCPServer{
		Code:        "com.deepwiki/mcp",
		DisplayName: "DeepWiki",
		URL:         "https://mcp.deepwiki.com/mcp",
		Transport:   "streamable-http",
		SelfService: true,
	}
}

func pendingCatalog(entries ...catalogdomain.MCPServer) fakeCatalog {
	m := map[string]catalogdomain.MCPServer{}
	for _, e := range entries {
		m[e.Code] = e
	}
	return fakeCatalog{entries: m}
}

func scopePending(t *testing.T, sc Scoper, gw ids.GatewayID, ctx context.Context) *appconsumer.RoutableConsumer {
	t.Helper()
	rc := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}
	scoped, err := sc.Scope(ctx, rc)
	if err != nil {
		t.Fatalf("Scope: %v", err)
	}
	return scoped
}

func TestScoperServesJustInstalledServerBeforeSnapshot(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	in := mustInstall(t, gw, "ana", "com.deepwiki/mcp")
	sc, err := NewScoper(
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{in}},
		indexedRegistries{},
		nil,
		WithScoperCatalog(pendingCatalog(deepWikiEntry())),
	)
	if err != nil {
		t.Fatalf("NewScoper: %v", err)
	}

	first := scopePending(t, sc, gw, withOpenPrincipal("ana"))
	second := scopePending(t, sc, gw, withOpenPrincipal("ana"))
	if len(first.Registries) != 1 {
		t.Fatalf("a just-installed server must be on the surface before the snapshot, got %d", len(first.Registries))
	}
	reg := first.Registries[0]
	if reg.MCPTarget == nil || reg.MCPTarget.URL != "https://mcp.deepwiki.com/mcp" {
		t.Fatalf("pending shelf must dial the catalog URL, got %+v", reg.MCPTarget)
	}
	if !reg.Enabled || reg.Name != "DeepWiki" {
		t.Fatalf("pending shelf must be the catalog registry, got %+v", reg)
	}
	wantID := pendingShelfID(gw, "com.deepwiki/mcp")
	if reg.ID != wantID || second.Registries[0].ID != wantID {
		t.Fatalf("pending shelf id must be stable across replicas, got %s then %s, want %s", reg.ID, second.Registries[0].ID, wantID)
	}
	if !reg.UpdatedAt.Equal(in.UpdatedAt) {
		t.Fatalf("pending shelf UpdatedAt = %s, want the install's %s", reg.UpdatedAt, in.UpdatedAt)
	}
}

func TestScoperPendingShelfStopsAtTheWindow(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	fresh := mustInstall(t, gw, "ana", "com.deepwiki/mcp")
	fresh.UpdatedAt = now.Add(-pendingShelfWindow)
	stale := mustInstall(t, gw, "ana", "github")
	stale.UpdatedAt = now.Add(-pendingShelfWindow - time.Second)
	zero := mustInstall(t, gw, "ana", "snowflake")
	zero.UpdatedAt = time.Time{}
	ahead := mustInstall(t, gw, "ana", "brightdata")
	ahead.UpdatedAt = now.Add(pendingShelfSkew + time.Second)

	cat := testCatalog()
	cat.entries["com.deepwiki/mcp"] = deepWikiEntry()
	sc, err := NewScoper(
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{fresh, stale, zero, ahead}},
		indexedRegistries{},
		nil,
		WithScoperCatalog(cat),
		withScoperClock(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("NewScoper: %v", err)
	}
	scoped := scopePending(t, sc, gw, withOpenPrincipal("ana"))
	if len(scoped.Registries) != 1 || scoped.Registries[0].MCPTarget.Code != "com.deepwiki/mcp" {
		t.Fatalf("only the install inside the window is served, got %+v", scoped.Registries)
	}
}

func TestScoperSnapshotRegistryWinsOverPendingShelf(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	in := mustInstall(t, gw, "ana", "com.deepwiki/mcp")
	shelf := &registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		Name:      "DeepWiki",
		Enabled:   true,
		CreatedAt: in.UpdatedAt.Add(-time.Hour),
		MCPTarget: &registrydomain.MCPTarget{Code: "com.deepwiki/mcp", URL: "https://snapshot.example/mcp"},
	}
	sc, _ := NewScoper(
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{in}},
		indexedRegistries{items: []*registrydomain.Registry{shelf}},
		nil,
		WithScoperCatalog(pendingCatalog(deepWikiEntry())),
	)
	scoped := scopePending(t, sc, gw, withOpenPrincipal("ana"))
	if len(scoped.Registries) != 1 || scoped.Registries[0].ID != shelf.ID {
		t.Fatalf("the snapshot registry must replace the pending shelf, got %+v", scoped.Registries)
	}
	if scoped.Registries[0].MCPTarget.URL != shelf.MCPTarget.URL {
		t.Fatalf("URL = %q, want the snapshot's", scoped.Registries[0].MCPTarget.URL)
	}
}

func TestScoperDisabledSnapshotRegistryStaysDormant(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	in := mustInstall(t, gw, "ana", "com.deepwiki/mcp")
	shelf := &registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		Enabled:   false,
		MCPTarget: &registrydomain.MCPTarget{Code: "com.deepwiki/mcp", URL: "https://snapshot.example/mcp"},
	}
	sc, _ := NewScoper(
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{in}},
		indexedRegistries{items: []*registrydomain.Registry{shelf}},
		nil,
		WithScoperCatalog(pendingCatalog(deepWikiEntry())),
	)
	scoped := scopePending(t, sc, gw, withOpenPrincipal("ana"))
	if len(scoped.Registries) != 0 {
		t.Fatalf("a disabled snapshot registry must not be replaced by the catalog, got %+v", scoped.Registries)
	}
}

func TestScoperBoundInstallDoesNotSubstitutePendingShelf(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	in := mustInstall(t, gw, "ana", "com.deepwiki/mcp")
	in.RegistryID = ids.New[ids.RegistryKind]()
	sc, _ := NewScoper(
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{in}},
		indexedRegistries{},
		nil,
		WithScoperCatalog(pendingCatalog(deepWikiEntry())),
	)
	scoped := scopePending(t, sc, gw, withOpenPrincipal("ana"))
	if len(scoped.Registries) != 0 {
		t.Fatalf("an install bound to a missing registry stays dormant, got %+v", scoped.Registries)
	}
}

func TestScoperPendingShelfRequiresSelfService(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	entry := deepWikiEntry()
	entry.SelfService = false
	in := mustInstall(t, gw, "ana", entry.Code)
	sc, _ := NewScoper(
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{in}},
		indexedRegistries{},
		nil,
		WithScoperCatalog(pendingCatalog(entry)),
	)
	scoped := scopePending(t, sc, gw, withOpenPrincipal("ana"))
	if len(scoped.Registries) != 0 {
		t.Fatalf("a server that needs an admin credential must wait for its registry, got %+v", scoped.Registries)
	}
}

func TestScoperPendingShelfHonorsGrants(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	in := mustInstall(t, gw, "ana", "com.deepwiki/mcp")
	cat := pendingCatalog(deepWikiEntry())
	installs := &fakeInstalls{byPrincipal: []*installationdomain.Installation{in}}

	closed, _ := NewScoper(installs, indexedRegistries{}, nil, WithScoperCatalog(cat))
	if got := scopePending(t, closed, gw, withPrincipal("ana")); len(got.Registries) != 0 {
		t.Fatalf("curated mode with no grant must not expose the pending shelf, got %+v", got.Registries)
	}

	open, _ := NewScoper(installs, indexedRegistries{}, grantsOf(codeGrant(gw, in.CatalogCode, nil, []string{"ana"})), WithScoperCatalog(cat))
	if got := scopePending(t, open, gw, withPrincipal("ana")); len(got.Registries) != 1 {
		t.Fatalf("a code grant must expose the pending shelf, got %d", len(got.Registries))
	}
}

func TestScoperInactiveInstallIsNotPending(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	revoked := mustInstall(t, gw, "ana", "com.deepwiki/mcp")
	revoked.Status = installationdomain.StatusRevoked
	pending := mustInstall(t, gw, "ana", "github")
	pending.Status = installationdomain.StatusPendingApproval
	sc, _ := NewScoper(
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{revoked, pending}},
		indexedRegistries{},
		nil,
		WithScoperCatalog(pendingCatalog(deepWikiEntry(), testCatalog().entries["github"])),
	)
	scoped := scopePending(t, sc, gw, withOpenPrincipal("ana"))
	if len(scoped.Registries) != 0 {
		t.Fatalf("revoked and pending installs stay off the surface, got %+v", scoped.Registries)
	}
}

func TestScoperRegistryReadErrorDoesNotSynthesize(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	in := mustInstall(t, gw, "ana", "com.deepwiki/mcp")
	sc, err := NewScoper(
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{in}},
		indexedRegistries{err: errors.New("snapshot unavailable")},
		nil,
		WithScoperCatalog(pendingCatalog(deepWikiEntry())),
	)
	if err != nil {
		t.Fatalf("NewScoper: %v", err)
	}
	rc := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}
	if _, err := sc.Scope(withOpenPrincipal("ana"), rc); err == nil {
		t.Fatal("a failed registry read must still fail the scope")
	}
}

func TestInstallThenScopeBeforeSnapshot(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{}
	installs := &fakeInstalls{}
	ensurer := &fakeEnsurer{}
	res, err := newInstallerWith(t, regs, installs, nil, ensurer).Install(withOpenPrincipal("ana"), openReq(gw, "github"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.Status != installationdomain.StatusInstalled || res.Pending || !res.RegistryID.IsNil() {
		t.Fatalf("first install must record an unbound installed row, got %+v", res)
	}
	if len(ensurer.ensured) != 1 || len(regs.items) != 0 {
		t.Fatalf("ensure must succeed without the registry reaching this replica, ensured=%v regs=%d", ensurer.ensured, len(regs.items))
	}
	installs.byPrincipal = installs.upserts

	sc, err := NewScoper(installs, regs, nil, WithScoperCatalog(testCatalog()))
	if err != nil {
		t.Fatalf("NewScoper: %v", err)
	}
	scoped := scopePending(t, sc, gw, withOpenPrincipal("ana"))
	if len(scoped.Registries) != 1 || scoped.Registries[0].MCPTarget.URL != "https://mcp.github.com" {
		t.Fatalf("tools/list's registry source must include the install immediately, got %+v", scoped.Registries)
	}
}

func TestScoperPendingShelfKeepsPerUserConfig(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	in, err := installationdomain.New(gw, "ana", "snowflake", "ana", map[string]string{"database": "analytics"})
	if err != nil {
		t.Fatalf("new install: %v", err)
	}
	sc, _ := NewScoper(
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{in}},
		indexedRegistries{},
		nil,
		WithScoperCatalog(testCatalog()),
	)
	scoped := scopePending(t, sc, gw, withOpenPrincipal("ana"))
	if len(scoped.Registries) != 1 {
		t.Fatalf("got %d registries", len(scoped.Registries))
	}
	reg := scoped.Registries[0]
	if reg.MCPTarget.InstanceConfig["database"] != "analytics" {
		t.Fatalf("config overlay = %+v", reg.MCPTarget.InstanceConfig)
	}
	// One instance keeps the shelf id; the overlay is what the dial reads.
	if reg.ID != pendingShelfID(gw, "snowflake") || reg.InstanceOf != reg.ID {
		t.Fatalf("id = %s InstanceOf = %s, want the pending shelf for both", reg.ID, reg.InstanceOf)
	}
}

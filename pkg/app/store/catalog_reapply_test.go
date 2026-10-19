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
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type countingSaver struct {
	calls int
	err   error
}

func (s *countingSaver) SaveCatalogTarget(context.Context, *registrydomain.Registry) error {
	s.calls++
	return s.err
}

type fakeBound struct {
	found bool
	err   error
	calls int
}

func (f *fakeBound) ExistsBound(context.Context, ids.GatewayID, string) (bool, error) {
	f.calls++
	return f.found, f.err
}

type fakeDCR struct {
	found bool
	err   error
	calls int
}

func (f *fakeDCR) HasDynamicClient(context.Context, ids.GatewayID, string) (bool, error) {
	f.calls++
	return f.found, f.err
}

func testReapplyCatalog(t *testing.T) appcatalog.MCPServerCatalog {
	t.Helper()
	catalog, err := appcatalog.NewMCPServerCatalog(nil)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	return catalog
}

func previousRegistry(t *testing.T, gatewayID ids.GatewayID, code string) *registrydomain.Registry {
	t.Helper()
	server, ok, err := previousServer(code)
	if err != nil || !ok {
		t.Fatalf("previous %s: ok=%v err=%v", code, ok, err)
	}
	shape, err := storedCatalogShape(server)
	if err != nil {
		t.Fatalf("shape %s: %v", code, err)
	}
	return &registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		GatewayID: gatewayID,
		Name:      code,
		Type:      registrydomain.TypeMCP,
		Enabled:   true,
		MCPTarget: shape,
	}
}

func TestPreviousFingerprintsDifferFromCurrentAndSkipAmbiguous(t *testing.T) {
	loadPreviousCatalog()
	if previousLoadErr != nil {
		t.Fatal(previousLoadErr)
	}
	if len(previousByCode) == 0 {
		t.Fatal("previous table is empty")
	}
	catalog := testReapplyCatalog(t)
	for code, previous := range previousByCode {
		entry, ok := catalog.GetByCode(code)
		if !ok {
			t.Fatalf("current catalog missing %s", code)
		}
		shape, err := storedCatalogShape(entry)
		if err != nil {
			t.Fatalf("current shape %s: %v", code, err)
		}
		current, err := catalogFingerprint(shape)
		if err != nil {
			t.Fatal(err)
		}
		if current == previous {
			t.Fatalf("%s previous fingerprint equals the current catalog", code)
		}
	}
	for _, code := range ambiguousCatalogCodes {
		if _, ok := previousByCode[code]; ok {
			t.Fatalf("ambiguous code %s is in the previous table", code)
		}
	}
	server, ok, err := previousServer("com.excalidraw/mcp")
	if err != nil || !ok || server.URL != "https://mcp.excalidraw.com" {
		t.Fatalf("excalidraw previous url = %q ok=%v err=%v", server.URL, ok, err)
	}
}

func TestReapplyExactPreviousWithoutCredentials(t *testing.T) {
	catalog := testReapplyCatalog(t)
	gatewayID := ids.New[ids.GatewayKind]()
	reg := previousRegistry(t, gatewayID, "com.excalidraw/mcp")
	reg.MCPTarget.Origin = registrydomain.MCPOriginStore
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	saver := &countingSaver{}
	reapply, err := NewCatalogReapply(catalog, saver, nil, nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	reapply.Reapply(ctx, gatewayID, []*registrydomain.Registry{reg})
	if saver.calls != 1 {
		t.Fatalf("saves = %d, want 1", saver.calls)
	}
	if reg.MCPTarget.URL != "https://mcp.excalidraw.com/mcp" {
		t.Fatalf("url = %s", reg.MCPTarget.URL)
	}
	if reg.MCPTarget.Origin != registrydomain.MCPOriginStore {
		t.Fatalf("origin = %q", reg.MCPTarget.Origin)
	}
	if !strings.Contains(buf.String(), "mcp_catalog_reapplied") || !strings.Contains(buf.String(), reg.ID.String()) {
		t.Fatalf("audit log = %s", buf.String())
	}
	reapply.Reapply(ctx, gatewayID, []*registrydomain.Registry{reg})
	if saver.calls != 1 {
		t.Fatalf("second run saves = %d, want 1", saver.calls)
	}
}

func TestReapplyLeavesCredentialsUntouched(t *testing.T) {
	catalog := testReapplyCatalog(t)
	gatewayID := ids.New[ids.GatewayKind]()
	reg := previousRegistry(t, gatewayID, "com.excalidraw/mcp")
	reg.MCPTarget.Auth.Value = "secret"
	saver := &countingSaver{}
	reapply, err := NewCatalogReapply(catalog, saver, nil, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	reapply.Reapply(context.Background(), gatewayID, []*registrydomain.Registry{reg})
	if saver.calls != 0 || reg.MCPTarget.URL != "https://mcp.excalidraw.com" {
		t.Fatalf("credential row changed: saves=%d url=%s", saver.calls, reg.MCPTarget.URL)
	}
}

func TestReapplyLeavesAdminCustomizationUntouched(t *testing.T) {
	catalog := testReapplyCatalog(t)
	gatewayID := ids.New[ids.GatewayKind]()
	reg := previousRegistry(t, gatewayID, "com.excalidraw/mcp")
	reg.MCPTarget.URL = "https://diagrams.example.com/mcp"
	saver := &countingSaver{}
	reapply, err := NewCatalogReapply(catalog, saver, nil, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	reapply.Reapply(context.Background(), gatewayID, []*registrydomain.Registry{reg})
	if saver.calls != 0 || reg.MCPTarget.URL != "https://diagrams.example.com/mcp" {
		t.Fatalf("custom url changed: saves=%d url=%s", saver.calls, reg.MCPTarget.URL)
	}
}

func TestReapplyLeavesUnknownValueUntouched(t *testing.T) {
	catalog := testReapplyCatalog(t)
	gatewayID := ids.New[ids.GatewayKind]()
	reg := previousRegistry(t, gatewayID, "com.excalidraw/mcp")
	reg.MCPTarget.URL = "https://mcp.excalidraw.com/v0"
	saver := &countingSaver{}
	reapply, err := NewCatalogReapply(catalog, saver, nil, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	reapply.Reapply(context.Background(), gatewayID, []*registrydomain.Registry{reg})
	if saver.calls != 0 || reg.MCPTarget.URL != "https://mcp.excalidraw.com/v0" {
		t.Fatalf("unknown url changed: saves=%d url=%s", saver.calls, reg.MCPTarget.URL)
	}
}

func TestReapplyForwardedCredentialsAndNilProbeBlock(t *testing.T) {
	catalog := testReapplyCatalog(t)
	gatewayID := ids.New[ids.GatewayKind]()
	reg := previousRegistry(t, gatewayID, "com.vercel/mcp")
	original, err := catalogFingerprint(reg.MCPTarget)
	if err != nil {
		t.Fatal(err)
	}
	saver := &countingSaver{}
	reapply, err := NewCatalogReapply(catalog, saver, nil, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	reapply.Reapply(ctx, gatewayID, []*registrydomain.Registry{reg})
	held, err := catalogFingerprint(reg.MCPTarget)
	if err != nil {
		t.Fatal(err)
	}
	if saver.calls != 0 || held != original {
		t.Fatalf("nil probe updated vercel: saves=%d", saver.calls)
	}

	bound := &fakeBound{}
	dcr := &fakeDCR{}
	reapply.vault = bound
	reapply.dcr = dcr
	reapply.Reapply(ctx, gatewayID, []*registrydomain.Registry{reg})
	held, err = catalogFingerprint(reg.MCPTarget)
	if err != nil {
		t.Fatal(err)
	}
	if saver.calls != 1 || held == original {
		t.Fatalf("clean forwarded row not updated: saves=%d", saver.calls)
	}
	if bound.calls == 0 || dcr.calls == 0 {
		t.Fatalf("probes not consulted: vault=%d dcr=%d", bound.calls, dcr.calls)
	}

	again := previousRegistry(t, gatewayID, "com.vercel/mcp")
	held, err = catalogFingerprint(again.MCPTarget)
	if err != nil {
		t.Fatal(err)
	}
	bound.found = true
	before := saver.calls
	reapply.Reapply(ctx, gatewayID, []*registrydomain.Registry{again})
	after, err := catalogFingerprint(again.MCPTarget)
	if err != nil {
		t.Fatal(err)
	}
	if saver.calls != before || after != held {
		t.Fatalf("vault credential did not block: saves=%d", saver.calls)
	}
}

func TestReapplyConcurrentSingleSave(t *testing.T) {
	catalog := testReapplyCatalog(t)
	gatewayID := ids.New[ids.GatewayKind]()
	reg := previousRegistry(t, gatewayID, "com.excalidraw/mcp")
	saver := &countingSaver{}
	reapply, err := NewCatalogReapply(catalog, saver, nil, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	for range 2 {
		go func() {
			defer wg.Done()
			reapply.Reapply(context.Background(), gatewayID, []*registrydomain.Registry{reg})
		}()
	}
	wg.Wait()
	if saver.calls != 1 {
		t.Fatalf("concurrent saves = %d, want 1", saver.calls)
	}
	if reg.MCPTarget.URL != "https://mcp.excalidraw.com/mcp" {
		t.Fatalf("url = %s", reg.MCPTarget.URL)
	}
}

func TestReapplyViewDoesNotPersistOrMutate(t *testing.T) {
	catalog := testReapplyCatalog(t)
	gatewayID := ids.New[ids.GatewayKind]()
	reg := previousRegistry(t, gatewayID, "com.excalidraw/mcp")
	saver := &countingSaver{}
	reapply, err := NewCatalogReapply(catalog, saver, nil, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	viewed := reapply.ViewCurrentCatalog(context.Background(), reg)
	if saver.calls != 0 {
		t.Fatalf("view saved %d", saver.calls)
	}
	if reg.MCPTarget.URL != "https://mcp.excalidraw.com" {
		t.Fatalf("view mutated the stored row: %s", reg.MCPTarget.URL)
	}
	if viewed == reg || viewed.MCPTarget.URL != "https://mcp.excalidraw.com/mcp" {
		t.Fatalf("view = %v url=%s", viewed == reg, viewed.MCPTarget.URL)
	}
}

func TestInstallRefreshUsesCurrentAuth(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	code := "io.globalping/mcp"
	reg := previousRegistry(t, gatewayID, code)
	catalog := testReapplyCatalog(t)
	saver := &countingSaver{}
	reapply, err := NewCatalogReapply(catalog, saver, nil, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	ensurer, err := NewRegistryEnsurer(catalog, &fakeRegistries{items: []*registrydomain.Registry{reg}}, refuseCreator{}, WithEnsurerReapply(reapply))
	if err != nil {
		t.Fatal(err)
	}
	installer, err := NewInstaller(catalog, &fakeRegistries{items: []*registrydomain.Registry{reg}}, &fakeInstalls{}, nil, ensurer, WithCatalogInstanceRefresh(reapply))
	if err != nil {
		t.Fatal(err)
	}
	res, err := installer.Install(context.Background(), openReq(gatewayID, code))
	if err != nil {
		t.Fatal(err)
	}
	if !res.RequiresAuth {
		t.Fatal("globalping install should require auth after the catalog correction")
	}
	if saver.calls != 1 || reg.MCPTarget.Auth == nil || reg.MCPTarget.Auth.Mode != registrydomain.MCPAuthModeForwarded {
		t.Fatalf("persisted mode = %+v saves=%d", reg.MCPTarget.Auth, saver.calls)
	}
}

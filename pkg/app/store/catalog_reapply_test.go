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
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type countingSaver struct {
	calls int
	err   error
}

func (s *countingSaver) SaveCatalogTarget(context.Context, *registrydomain.Registry, string) (bool, error) {
	s.calls++
	if s.err != nil {
		return false, s.err
	}
	return true, nil
}

// racingAdminSaver lands an admin edit on the row after decide and before the
// write, then applies the catalog target only when the locked row is still the
// previous seed. Name is never part of the write.
type racingAdminSaver struct {
	row     *registrydomain.Registry
	calls   int
	applied int
}

func (s *racingAdminSaver) SaveCatalogTarget(_ context.Context, next *registrydomain.Registry, oldFP string) (bool, error) {
	s.calls++
	s.row.Name = "Renamed by admin"
	s.row.MCPTarget.URL = "https://admin.example/mcp"
	if next == nil || next.MCPTarget == nil || !mcpTargetStillPrevious(oldFP)(s.row.MCPTarget) {
		return false, nil
	}
	s.row.MCPTarget.URL = next.MCPTarget.URL
	s.row.MCPTarget.Transport = next.MCPTarget.Transport
	s.row.MCPTarget.Auth = next.MCPTarget.Auth
	s.row.MCPTarget.URLVariables = next.MCPTarget.URLVariables
	s.applied++
	return true, nil
}

type allowNoneInstalls struct{}

func (allowNoneInstalls) ListByCatalogCode(context.Context, ids.GatewayID, string) ([]*installationdomain.Installation, error) {
	return nil, nil
}

type scriptInstalls struct {
	rows []*installationdomain.Installation
	err  error
}

func (s scriptInstalls) ListByCatalogCode(context.Context, ids.GatewayID, string) ([]*installationdomain.Installation, error) {
	return s.rows, s.err
}

type clientCatalog struct {
	appcatalog.MCPServerCatalog
	clientID string
	code     string
}

func (c clientCatalog) SharedOAuthCredentials(code string) (string, string, bool) {
	if code != c.code || c.clientID == "" {
		return "", "", false
	}
	return c.clientID, "platform-secret", true
}

type fakeBound struct {
	found bool
	err   error
	calls int
}

// appearBound is clear on the first probe and reports a token after that, so
// a credential that arrives between decide and the swap is visible.
type appearBound struct {
	calls int
}

func (f *appearBound) ExistsBound(context.Context, ids.GatewayID, string) (bool, error) {
	f.calls++
	return f.calls > 1, nil
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

func newTestReapply(t *testing.T, catalog CatalogReader, saver CatalogTargetSaver, logger *slog.Logger) *CatalogReapply {
	t.Helper()
	reapply, err := NewCatalogReapply(catalog, saver, nil, nil, allowNoneInstalls{}, logger)
	if err != nil {
		t.Fatal(err)
	}
	return reapply
}

func withClearProbes(reapply *CatalogReapply) (*fakeBound, *fakeDCR) {
	bound := &fakeBound{}
	dcr := &fakeDCR{}
	reapply.vault = bound
	reapply.dcr = dcr
	return bound, dcr
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
	if _, ok := previousByCode["dev.cube/mcp"]; ok {
		t.Fatal("cube template is in the previous table")
	}
	_, ok, err = previousServer("dev.cube/mcp")
	if err != nil || ok {
		t.Fatalf("cube previous server ok=%v err=%v", ok, err)
	}
}

func TestReapplyExactPreviousWithoutCredentials(t *testing.T) {
	catalog := testReapplyCatalog(t)
	gatewayID := ids.New[ids.GatewayKind]()
	reg := previousRegistry(t, gatewayID, "com.amplitude/mcp")
	reg.MCPTarget.Origin = registrydomain.MCPOriginStore
	before, err := catalogFingerprint(reg.MCPTarget)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	saver := &countingSaver{}
	reapply := newTestReapply(t, catalog, saver, logger)
	withClearProbes(reapply)
	ctx := context.Background()
	reapply.Reapply(ctx, gatewayID, []*registrydomain.Registry{reg})
	if saver.calls != 1 {
		t.Fatalf("saves = %d, want 1", saver.calls)
	}
	after, err := catalogFingerprint(reg.MCPTarget)
	if err != nil {
		t.Fatal(err)
	}
	if after == before {
		t.Fatal("amplitude fingerprint did not change")
	}
	if reg.MCPTarget.URL != "https://mcp.amplitude.com/mcp" {
		t.Fatalf("url = %s", reg.MCPTarget.URL)
	}
	if reg.MCPTarget.Origin != registrydomain.MCPOriginStore {
		t.Fatalf("origin = %q", reg.MCPTarget.Origin)
	}
	if reg.MCPTarget.Auth == nil || reg.MCPTarget.Auth.Registration != registrydomain.RegistrationAuto {
		t.Fatalf("auth = %+v", reg.MCPTarget.Auth)
	}
	if strings.Contains(buf.String(), "client_secret") || strings.Contains(buf.String(), "secret") {
		t.Fatalf("audit log includes a secret: %s", buf.String())
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
	reapply := newTestReapply(t, catalog, saver, slog.New(slog.DiscardHandler))
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
	reapply := newTestReapply(t, catalog, saver, slog.New(slog.DiscardHandler))
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
	reapply := newTestReapply(t, catalog, saver, slog.New(slog.DiscardHandler))
	reapply.Reapply(context.Background(), gatewayID, []*registrydomain.Registry{reg})
	if saver.calls != 0 || reg.MCPTarget.URL != "https://mcp.excalidraw.com/v0" {
		t.Fatalf("unknown url changed: saves=%d url=%s", saver.calls, reg.MCPTarget.URL)
	}
}

func TestReapplyForwardedCredentialsAndNilProbeBlock(t *testing.T) {
	catalog := testReapplyCatalog(t)
	gatewayID := ids.New[ids.GatewayKind]()
	reg := previousRegistry(t, gatewayID, "com.amplitude/mcp")
	original, err := catalogFingerprint(reg.MCPTarget)
	if err != nil {
		t.Fatal(err)
	}
	saver := &countingSaver{}
	reapply := newTestReapply(t, catalog, saver, slog.New(slog.DiscardHandler))
	ctx := context.Background()
	reapply.Reapply(ctx, gatewayID, []*registrydomain.Registry{reg})
	held, err := catalogFingerprint(reg.MCPTarget)
	if err != nil {
		t.Fatal(err)
	}
	if saver.calls != 0 || held != original {
		t.Fatalf("nil probe updated amplitude: saves=%d", saver.calls)
	}

	bound, dcr := withClearProbes(reapply)
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

	again := previousRegistry(t, gatewayID, "com.amplitude/mcp")
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
	reg := previousRegistry(t, gatewayID, "com.amplitude/mcp")
	before, err := catalogFingerprint(reg.MCPTarget)
	if err != nil {
		t.Fatal(err)
	}
	saver := &countingSaver{}
	reapply := newTestReapply(t, catalog, saver, slog.New(slog.DiscardHandler))
	withClearProbes(reapply)
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
	after, err := catalogFingerprint(reg.MCPTarget)
	if err != nil {
		t.Fatal(err)
	}
	if after == before || reg.MCPTarget.URL != "https://mcp.amplitude.com/mcp" {
		t.Fatalf("url = %s fingerprint changed=%v", reg.MCPTarget.URL, after != before)
	}
}

func TestReapplyViewDoesNotPersistOrMutate(t *testing.T) {
	catalog := testReapplyCatalog(t)
	gatewayID := ids.New[ids.GatewayKind]()
	reg := previousRegistry(t, gatewayID, "com.amplitude/mcp")
	before, err := catalogFingerprint(reg.MCPTarget)
	if err != nil {
		t.Fatal(err)
	}
	saver := &countingSaver{}
	reapply := newTestReapply(t, catalog, saver, slog.New(slog.DiscardHandler))
	withClearProbes(reapply)
	viewed := reapply.ViewCurrentCatalog(context.Background(), reg)
	if saver.calls != 0 {
		t.Fatalf("view saved %d", saver.calls)
	}
	held, err := catalogFingerprint(reg.MCPTarget)
	if err != nil {
		t.Fatal(err)
	}
	if held != before {
		t.Fatal("view mutated the stored row")
	}
	seen, err := catalogFingerprint(viewed.MCPTarget)
	if err != nil {
		t.Fatal(err)
	}
	if viewed == reg || seen == before || viewed.MCPTarget.URL != "https://mcp.amplitude.com/mcp" {
		t.Fatalf("view = %v url=%s", viewed == reg, viewed.MCPTarget.URL)
	}
}

func TestInstallRefreshUsesCurrentAuth(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	code := "io.globalping/mcp"
	reg := previousRegistry(t, gatewayID, code)
	catalog := testReapplyCatalog(t)
	saver := &countingSaver{}
	reapply := newTestReapply(t, catalog, saver, slog.New(slog.DiscardHandler))
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
	if res.RequiresAuth {
		t.Fatal("globalping install must keep working without OAuth")
	}
	if saver.calls != 0 || reg.MCPTarget.Auth == nil || reg.MCPTarget.Auth.Mode != registrydomain.MCPAuthModeNone {
		t.Fatalf("persisted mode = %+v saves=%d", reg.MCPTarget.Auth, saver.calls)
	}
	if reg.MCPTarget.URL != "https://mcp.globalping.dev/mcp" {
		t.Fatalf("url = %s", reg.MCPTarget.URL)
	}
}

func TestReapplyTokenBetweenProbeAndSwapLeavesRowUntouched(t *testing.T) {
	catalog := testReapplyCatalog(t)
	gatewayID := ids.New[ids.GatewayKind]()
	reg := previousRegistry(t, gatewayID, "com.chargebee/mcp")
	beforeURL := reg.MCPTarget.URL
	before, err := catalogFingerprint(reg.MCPTarget)
	if err != nil {
		t.Fatal(err)
	}
	saver := &countingSaver{}
	reapply := newTestReapply(t, catalog, saver, slog.New(slog.DiscardHandler))
	bound := &appearBound{}
	reapply.vault = bound
	reapply.dcr = &fakeDCR{}
	reapply.Reapply(context.Background(), gatewayID, []*registrydomain.Registry{reg})
	after, err := catalogFingerprint(reg.MCPTarget)
	if err != nil {
		t.Fatal(err)
	}
	if saver.calls != 0 || after != before || reg.MCPTarget.URL != beforeURL {
		t.Fatalf("token between probe and swap changed the row: saves=%d url=%s", saver.calls, reg.MCPTarget.URL)
	}
	if bound.calls < 2 {
		t.Fatalf("vault probes = %d, want the check repeated before the swap", bound.calls)
	}
}

func TestReapplyAdminEditBetweenReadAndWriteSurvives(t *testing.T) {
	catalog := testReapplyCatalog(t)
	gatewayID := ids.New[ids.GatewayKind]()
	reg := previousRegistry(t, gatewayID, "com.amplitude/mcp")
	reg.Name = "Amplitude"
	saver := &racingAdminSaver{row: reg}
	reapply := newTestReapply(t, catalog, saver, slog.New(slog.DiscardHandler))
	withClearProbes(reapply)
	reapply.Reapply(context.Background(), gatewayID, []*registrydomain.Registry{reg})
	if saver.calls != 1 || saver.applied != 0 {
		t.Fatalf("calls=%d applied=%d", saver.calls, saver.applied)
	}
	if reg.Name != "Renamed by admin" {
		t.Fatalf("name = %q", reg.Name)
	}
	if reg.MCPTarget.URL != "https://admin.example/mcp" {
		t.Fatalf("url = %s", reg.MCPTarget.URL)
	}
}

func TestReapplyRefusesWorkingNoAuthURLChange(t *testing.T) {
	catalog := testReapplyCatalog(t)
	gatewayID := ids.New[ids.GatewayKind]()
	reg := previousRegistry(t, gatewayID, "com.excalidraw/mcp")
	saver := &countingSaver{}
	reapply := newTestReapply(t, catalog, saver, slog.New(slog.DiscardHandler))
	reapply.Reapply(context.Background(), gatewayID, []*registrydomain.Registry{reg})
	if saver.calls != 0 || reg.MCPTarget.URL != "https://mcp.excalidraw.com" {
		t.Fatalf("excalidraw url changed: saves=%d url=%s", saver.calls, reg.MCPTarget.URL)
	}
	viewed := reapply.ViewCurrentCatalog(context.Background(), reg)
	if viewed != reg || viewed.MCPTarget.URL != "https://mcp.excalidraw.com" {
		t.Fatalf("view overlaid a working no-auth url: %s", viewed.MCPTarget.URL)
	}
}

func TestReapplyRefusesActiveInstallation(t *testing.T) {
	catalog := testReapplyCatalog(t)
	gatewayID := ids.New[ids.GatewayKind]()
	logger := slog.New(slog.DiscardHandler)
	ctx := context.Background()

	active := previousRegistry(t, gatewayID, "com.amplitude/mcp")
	before, err := catalogFingerprint(active.MCPTarget)
	if err != nil {
		t.Fatal(err)
	}
	saver := &countingSaver{}
	reapply, err := NewCatalogReapply(catalog, saver, nil, nil, scriptInstalls{
		rows: []*installationdomain.Installation{{Status: installationdomain.StatusInstalled}},
	}, logger)
	if err != nil {
		t.Fatal(err)
	}
	withClearProbes(reapply)
	reapply.Reapply(ctx, gatewayID, []*registrydomain.Registry{active})
	held, err := catalogFingerprint(active.MCPTarget)
	if err != nil {
		t.Fatal(err)
	}
	if saver.calls != 0 || held != before {
		t.Fatalf("active installation did not block: saves=%d", saver.calls)
	}

	unchecked := previousRegistry(t, gatewayID, "com.amplitude/mcp")
	reapply, err = NewCatalogReapply(catalog, saver, nil, nil, nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	withClearProbes(reapply)
	reapply.Reapply(ctx, gatewayID, []*registrydomain.Registry{unchecked})
	if saver.calls != 0 {
		t.Fatal("nil installation reader updated a row")
	}

	failed := previousRegistry(t, gatewayID, "com.amplitude/mcp")
	reapply.installs = scriptInstalls{err: errors.New("installations unavailable")}
	reapply.Reapply(ctx, gatewayID, []*registrydomain.Registry{failed})
	if saver.calls != 0 || failed.MCPTarget.URL != unchecked.MCPTarget.URL {
		t.Fatal("installation list error updated a row")
	}

	pending := previousRegistry(t, gatewayID, "com.amplitude/mcp")
	reapply.installs = scriptInstalls{
		rows: []*installationdomain.Installation{{Status: installationdomain.StatusPendingApproval}},
	}
	reapply.Reapply(ctx, gatewayID, []*registrydomain.Registry{pending})
	after, err := catalogFingerprint(pending.MCPTarget)
	if err != nil {
		t.Fatal(err)
	}
	if saver.calls != 1 || after == before {
		t.Fatalf("pending installation blocked a safe reapply: saves=%d", saver.calls)
	}
}

func TestReapplyManualWithoutClientIDRefusedUnlessShared(t *testing.T) {
	catalog := testReapplyCatalog(t)
	gatewayID := ids.New[ids.GatewayKind]()
	logger := slog.New(slog.DiscardHandler)
	ctx := context.Background()

	plain := previousRegistry(t, gatewayID, "com.vercel/mcp")
	original, err := catalogFingerprint(plain.MCPTarget)
	if err != nil {
		t.Fatal(err)
	}
	saver := &countingSaver{}
	reapply := newTestReapply(t, catalog, saver, logger)
	withClearProbes(reapply)
	reapply.Reapply(ctx, gatewayID, []*registrydomain.Registry{plain})
	held, err := catalogFingerprint(plain.MCPTarget)
	if err != nil {
		t.Fatal(err)
	}
	if saver.calls != 0 || held != original {
		t.Fatalf("manual without client_id was written: saves=%d", saver.calls)
	}

	var buf bytes.Buffer
	shared := clientCatalog{MCPServerCatalog: catalog, clientID: "platform-client", code: "com.vercel/mcp"}
	bound := previousRegistry(t, gatewayID, "com.vercel/mcp")
	sharedSaver := &countingSaver{}
	reapply = newTestReapply(t, shared, sharedSaver, slog.New(slog.NewJSONHandler(&buf, nil)))
	withClearProbes(reapply)
	reapply.Reapply(ctx, gatewayID, []*registrydomain.Registry{bound})
	if sharedSaver.calls != 1 {
		t.Fatalf("shared oauth saves = %d, want 1", sharedSaver.calls)
	}
	if bound.MCPTarget.Auth == nil || bound.MCPTarget.Auth.ClientID != "platform-client" {
		t.Fatalf("client id = %+v", bound.MCPTarget.Auth)
	}
	if bound.MCPTarget.Auth.ClientSecret != "" {
		t.Fatal("platform client secret was stored on the registry")
	}
	if bound.MCPTarget.Auth.Registration != registrydomain.RegistrationManual {
		t.Fatalf("registration = %s", bound.MCPTarget.Auth.Registration)
	}
	if strings.Contains(buf.String(), "platform-secret") || strings.Contains(buf.String(), "platform-client") {
		t.Fatalf("audit log includes oauth material: %s", buf.String())
	}
}

// These entries were not in the #1118 previous-seed table, and the new shape
// is a manual app with no client id. Re-apply must not write that shape:
// an empty client id is not a credential the row can dial with.
func TestReapplyDoesNotWriteAdminOAuthWithoutClientID(t *testing.T) {
	loadPreviousCatalog()
	if previousLoadErr != nil {
		t.Fatal(previousLoadErr)
	}
	catalog := testReapplyCatalog(t)
	gatewayID := ids.New[ids.GatewayKind]()
	saver := &countingSaver{}
	reapply := newTestReapply(t, catalog, saver, slog.New(slog.DiscardHandler))
	withClearProbes(reapply)
	for _, code := range []string{
		"com.salesforce/mcp",
		"com.salesforce/mcp-sandbox",
		"com.servicenow/mcp",
		"com.snowflake/mcp",
		"com.getdbt/mcp",
	} {
		if _, ok := previousByCode[code]; ok {
			t.Fatalf("%s is in the previous fingerprint table", code)
		}
		entry, ok := catalog.GetByCode(code)
		if !ok {
			t.Fatalf("missing %s", code)
		}
		shape, err := storedCatalogShape(entry)
		if err != nil {
			t.Fatalf("shape %s: %v", code, err)
		}
		if shape.URL != entry.URL {
			t.Fatalf("%s url = %s", code, shape.URL)
		}
		if !manualWithoutClient(shape) {
			t.Fatalf("%s stored shape is not refused for an empty client id: %+v", code, shape.Auth)
		}
		old := &registrydomain.MCPTarget{
			Code:      code,
			URL:       entry.URL,
			Transport: registrydomain.MCPTransportStreamableHTTP,
			Auth: &registrydomain.MCPAuth{
				Mode:         registrydomain.MCPAuthModeForwarded,
				Provider:     code,
				Registration: registrydomain.RegistrationAuto,
			},
		}
		if raisesAuthRequirement(old, shape) {
			t.Fatalf("%s raises the auth requirement", code)
		}
		reg := &registrydomain.Registry{
			ID:        ids.New[ids.RegistryKind](),
			GatewayID: gatewayID,
			Name:      code,
			Type:      registrydomain.TypeMCP,
			Enabled:   true,
			MCPTarget: old,
		}
		before, err := catalogFingerprint(old)
		if err != nil {
			t.Fatal(err)
		}
		reapply.Reapply(context.Background(), gatewayID, []*registrydomain.Registry{reg})
		after, err := catalogFingerprint(reg.MCPTarget)
		if err != nil {
			t.Fatal(err)
		}
		if after != before || reg.MCPTarget.Auth.Registration != registrydomain.RegistrationAuto {
			t.Fatalf("%s was re-applied: registration=%s", code, reg.MCPTarget.Auth.Registration)
		}
	}
	if saver.calls != 0 {
		t.Fatalf("saves = %d, want 0", saver.calls)
	}
}

func TestReapplyCubeTemplateIsNotPointedAtCloud(t *testing.T) {
	catalog := testReapplyCatalog(t)
	entry, ok := catalog.GetByCode("dev.cube/mcp")
	if !ok || entry.URL != "https://cubecloud.dev/mcp" {
		t.Fatalf("current cube url = %q ok=%v", entry.URL, ok)
	}
	gatewayID := ids.New[ids.GatewayKind]()
	reg := &registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		GatewayID: gatewayID,
		Name:      "dev.cube/mcp",
		Type:      registrydomain.TypeMCP,
		Enabled:   true,
		MCPTarget: &registrydomain.MCPTarget{
			Code:      "dev.cube/mcp",
			URL:       "https://{cube_host}/api/mcp",
			Transport: registrydomain.MCPTransportStreamableHTTP,
			Auth:      &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeForwarded, Provider: "dev.cube/mcp", Registration: registrydomain.RegistrationAuto},
		},
	}
	saver := &countingSaver{}
	reapply := newTestReapply(t, catalog, saver, slog.New(slog.DiscardHandler))
	withClearProbes(reapply)
	reapply.Reapply(context.Background(), gatewayID, []*registrydomain.Registry{reg})
	if saver.calls != 0 || reg.MCPTarget.URL != "https://{cube_host}/api/mcp" {
		t.Fatalf("cube template changed: saves=%d url=%s", saver.calls, reg.MCPTarget.URL)
	}
}

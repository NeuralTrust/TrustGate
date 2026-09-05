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

package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type fakeRegistryLister struct{ items []*registrydomain.Registry }

func (f fakeRegistryLister) List(context.Context, registrydomain.ListFilter) ([]*registrydomain.Registry, int, error) {
	return f.items, len(f.items), nil
}

func shelfReg(code string, store *registrydomain.MCPStoreConfig) *registrydomain.Registry {
	return &registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		MCPTarget: &registrydomain.MCPTarget{Code: code, Store: store},
	}
}

type fakeCatalog struct{ servers []catalogdomain.MCPServer }

func (f fakeCatalog) ListMCPServers() []catalogdomain.MCPServer { return f.servers }

func sampleCatalog() fakeCatalog {
	return fakeCatalog{servers: []catalogdomain.MCPServer{
		{Code: "github", DisplayName: "GitHub", Vendor: "GitHub", Category: "dev", Description: "code hosting", RequiresAuth: true, Tools: []catalogdomain.MCPTool{{Name: "create_issue"}, {Name: "list_repos"}}},
		{Code: "gitlab", DisplayName: "GitLab", Vendor: "GitLab", Category: "dev", Description: "git and CI"},
		{Code: "salesforce", DisplayName: "Salesforce", Vendor: "Salesforce", Category: "crm", Description: "sales cloud"},
	}}
}

func storeRC() *appconsumer.RoutableConsumer {
	return &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(ids.New[ids.GatewayKind]())}
}

func decodeStructured(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var out struct {
		StructuredContent map[string]any `json:"structuredContent"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	return out.StructuredContent
}

func decodeText(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var out struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if len(out.Content) == 0 {
		return ""
	}
	return out.Content[0].Text
}

func newStoreToolForTest(t *testing.T) StoreTool {
	t.Helper()
	tool, err := NewStoreTool(sampleCatalog())
	if err != nil {
		t.Fatalf("NewStoreTool: %v", err)
	}
	return tool
}

func TestNewStoreToolRejectsNilCatalog(t *testing.T) {
	if _, err := NewStoreTool(nil); err == nil {
		t.Fatal("NewStoreTool(nil) must error")
	}
}

func TestStoreToolHandles(t *testing.T) {
	tool := newStoreToolForTest(t)
	if !tool.Handles(StoreSearchToolName) {
		t.Fatalf("must handle %q", StoreSearchToolName)
	}
	if tool.Handles("github_create_issue") || tool.Handles("trustgate_connect_github") {
		t.Fatal("must not handle upstream or connection tools")
	}
}

func TestStoreToolDefinitionsExposeSearch(t *testing.T) {
	tool := newStoreToolForTest(t)
	defs := tool.Definitions(context.Background(), storeRC())
	if len(defs) != 1 || defs[0].Name != StoreSearchToolName {
		t.Fatalf("expected the search tool, got %+v", defs)
	}
}

func TestStoreSearchByQuery(t *testing.T) {
	tool := newStoreToolForTest(t)
	raw, err := tool.Call(context.Background(), storeRC(), "", StoreSearchToolName, json.RawMessage(`{"query":"git"}`))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	sc := decodeStructured(t, raw)
	if sc["total"].(float64) != 2 {
		t.Fatalf("query 'git' should match github and gitlab, got total=%v", sc["total"])
	}
	results := sc["results"].([]any)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	first := results[0].(map[string]any)
	if first["code"] != "github" || first["tool_count"].(float64) != 2 || first["requires_auth"] != true {
		t.Fatalf("unexpected first result: %+v", first)
	}
	// The exact install code must also appear in the text body, so clients that
	// surface only the text (not structuredContent) still pass the right code.
	if text := decodeText(t, raw); !strings.Contains(text, `code "github"`) {
		t.Fatalf("search text must carry the exact code; got: %q", text)
	}
}

func TestStoreSearchByCategory(t *testing.T) {
	tool := newStoreToolForTest(t)
	raw, err := tool.Call(context.Background(), storeRC(), "", StoreSearchToolName, json.RawMessage(`{"category":"crm"}`))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	sc := decodeStructured(t, raw)
	if sc["total"].(float64) != 1 {
		t.Fatalf("category crm should match only salesforce, got %v", sc["total"])
	}
}

func TestStoreSearchEmptyBrowsesAll(t *testing.T) {
	tool := newStoreToolForTest(t)
	raw, err := tool.Call(context.Background(), storeRC(), "", StoreSearchToolName, nil)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	sc := decodeStructured(t, raw)
	if sc["total"].(float64) != 3 {
		t.Fatalf("empty query should browse the whole catalog (3), got %v", sc["total"])
	}
}

func TestStoreSearchRespectsLimitAndReportsTruncation(t *testing.T) {
	tool := newStoreToolForTest(t)
	raw, err := tool.Call(context.Background(), storeRC(), "", StoreSearchToolName, json.RawMessage(`{"limit":1}`))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	sc := decodeStructured(t, raw)
	if sc["total"].(float64) != 3 || sc["returned"].(float64) != 1 || sc["truncated"] != true {
		t.Fatalf("limit=1 over 3 must truncate: %+v", sc)
	}
}

func TestStoreToolCallRejectsUnknownTool(t *testing.T) {
	tool := newStoreToolForTest(t)
	if _, err := tool.Call(context.Background(), storeRC(), "", "trustgate_store_bogus", nil); err == nil {
		t.Fatal("unknown store tool must error")
	}
}

func storeToolWithShelf(t *testing.T, items ...*registrydomain.Registry) StoreTool {
	t.Helper()
	tool, err := NewStoreToolWithInstaller(sampleCatalog(), nil, fakeRegistryLister{items: items}, nil, nil)
	if err != nil {
		t.Fatalf("NewStoreToolWithInstaller: %v", err)
	}
	return tool
}

func resultsByCode(t *testing.T, raw json.RawMessage) map[string]map[string]any {
	t.Helper()
	sc := decodeStructured(t, raw)
	out := map[string]map[string]any{}
	for _, r := range sc["results"].([]any) {
		m := r.(map[string]any)
		out[m["code"].(string)] = m
	}
	return out
}

func TestStoreSearchTagsShelfState(t *testing.T) {
	tool := storeToolWithShelf(t,
		shelfReg("github", &registrydomain.MCPStoreConfig{Available: true}),
		shelfReg("gitlab", &registrydomain.MCPStoreConfig{Available: true, RequiresApproval: true}),
		// salesforce not on the shelf
	)
	raw, err := tool.Call(context.Background(), storeRC(), "", StoreSearchToolName, nil)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	got := resultsByCode(t, raw)
	if got["github"]["store_state"] != storeStateAvailable {
		t.Fatalf("github should be available, got %v", got["github"]["store_state"])
	}
	if got["gitlab"]["store_state"] != storeStateApproval {
		t.Fatalf("gitlab should be approval, got %v", got["gitlab"]["store_state"])
	}
	if got["salesforce"]["store_state"] != storeStateRequest {
		t.Fatalf("salesforce should be request, got %v", got["salesforce"]["store_state"])
	}
}

// ctxWithStoreAccess builds a context carrying a principal whose token declares
// a per-principal MCP Store access level ("open" | "curated" | "none").
func ctxWithStoreAccess(base context.Context, sub, mode string) context.Context {
	claims := map[string]any{}
	if mode != "" {
		claims[identity.ClaimStoreAccess] = mode
	}
	return identity.WithPrincipal(base, &identity.Principal{Subject: sub, Claims: claims})
}

func TestStoreSearchPrincipalOpenOverridesCuratedGateway(t *testing.T) {
	tool := storeToolWithShelf(t, shelfReg("github", &registrydomain.MCPStoreConfig{Available: true}))
	// Gateway default is curated (only shelf servers), but this principal's token
	// carries store_access=open, so the whole catalog is browsable for them.
	gw := &gatewaydomain.Gateway{Metadata: gatewaydomain.WithStoreMode(nil, gatewaydomain.StoreModeCurated)}
	ctx := appgateway.WithGateway(
		ctxWithStoreAccess(context.Background(), "ana", gatewaydomain.StoreModeOpen),
		gw,
	)
	raw, err := tool.Call(ctx, storeRC(), "", StoreSearchToolName, nil)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	got := resultsByCode(t, raw)
	if _, ok := got["salesforce"]; !ok {
		t.Fatal("principal store_access=open must reveal non-shelf servers despite a curated gateway")
	}
}

func TestStoreSearchPrincipalNoneClosesStore(t *testing.T) {
	// Gateway default is open, but this principal's token carries
	// store_access=none, so the Store is closed for them.
	tool := storeToolWithShelf(t, shelfReg("github", &registrydomain.MCPStoreConfig{Available: true}))
	ctx := ctxWithStoreAccess(context.Background(), "ana", gatewaydomain.StoreModeNone)
	raw, err := tool.Call(ctx, storeRC(), "", StoreSearchToolName, nil)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	sc := decodeStructured(t, raw)
	if total, _ := sc["total"].(float64); total != 0 {
		t.Fatalf("principal store_access=none must return an empty catalog, got total %v", sc["total"])
	}
}

func TestStoreInstallPrincipalNoneRefused(t *testing.T) {
	inst := &fakeInstaller{}
	tool := storeToolWithInstaller(t, inst)
	ctx := ctxWithStoreAccess(context.Background(), "ana", gatewaydomain.StoreModeNone)
	if _, err := tool.Call(ctx, storeRC(), "", StoreInstallToolName, json.RawMessage(`{"code":"github"}`)); err == nil {
		t.Fatal("install must be refused when the principal's store_access is none")
	}
	if len(inst.installed) != 0 {
		t.Fatalf("installer must not run when store access is none, got %v", inst.installed)
	}
}

func TestStoreSearchCuratedModeHidesNonShelf(t *testing.T) {
	tool := storeToolWithShelf(t, shelfReg("github", &registrydomain.MCPStoreConfig{Available: true}))
	// A gateway in curated mode.
	gw := &gatewaydomain.Gateway{Metadata: gatewaydomain.WithStoreMode(nil, gatewaydomain.StoreModeCurated)}
	ctx := appgateway.WithGateway(context.Background(), gw)

	raw, err := tool.Call(ctx, storeRC(), "", StoreSearchToolName, nil)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	got := resultsByCode(t, raw)
	if _, ok := got["github"]; !ok {
		t.Fatal("curated mode must still show the shelf server github")
	}
	if _, ok := got["salesforce"]; ok {
		t.Fatal("curated mode must hide non-shelf servers")
	}
}

type fakeInstaller struct {
	installed   []string
	lastGroups  []string
	uninstalled []string
	result      *appstore.InstallResult
}

func (f *fakeInstaller) Install(_ context.Context, in appstore.InstallRequest) (*appstore.InstallResult, error) {
	f.installed = append(f.installed, in.Code)
	f.lastGroups = in.Groups
	if f.result != nil {
		return f.result, nil
	}
	return &appstore.InstallResult{Code: in.Code, Name: in.Code}, nil
}

func (f *fakeInstaller) Uninstall(_ context.Context, _ ids.GatewayID, _, code string) error {
	f.uninstalled = append(f.uninstalled, code)
	return nil
}

func storeToolWithInstaller(t *testing.T, installer appstore.Installer) StoreTool {
	t.Helper()
	tool, err := NewStoreToolWithInstaller(sampleCatalog(), installer, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewStoreToolWithInstaller: %v", err)
	}
	return tool
}

func ctxWithPrincipal() context.Context {
	return identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "ana"})
}

func TestStoreDefinitionsIncludeInstallOnlyWithInstaller(t *testing.T) {
	searchOnly := newStoreToolForTest(t)
	if got := len(searchOnly.Definitions(context.Background(), storeRC())); got != 1 {
		t.Fatalf("without an installer only SEARCH is offered, got %d tools", got)
	}
	withInstaller := storeToolWithInstaller(t, &fakeInstaller{})
	names := map[string]bool{}
	for _, d := range withInstaller.Definitions(context.Background(), storeRC()) {
		names[d.Name] = true
	}
	if !names[StoreSearchToolName] || !names[StoreInstallToolName] || !names[StoreUninstallToolName] {
		t.Fatalf("expected search+install+uninstall, got %v", names)
	}
}

func TestStoreInstallCall(t *testing.T) {
	installer := &fakeInstaller{result: &appstore.InstallResult{Code: "github", Name: "GitHub", RequiresAuth: true}}
	tool := storeToolWithInstaller(t, installer)
	raw, err := tool.Call(ctxWithPrincipal(), storeRC(), "", StoreInstallToolName, json.RawMessage(`{"code":"github"}`))
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if len(installer.installed) != 1 || installer.installed[0] != "github" {
		t.Fatalf("installer must be called with the code, got %v", installer.installed)
	}
	sc := decodeStructured(t, raw)
	if sc["code"] != "github" || sc["requires_auth"] != true {
		t.Fatalf("unexpected install result: %+v", sc)
	}
}

func TestStoreInstallRequiresPrincipal(t *testing.T) {
	tool := storeToolWithInstaller(t, &fakeInstaller{})
	if _, err := tool.Call(context.Background(), storeRC(), "", StoreInstallToolName, json.RawMessage(`{"code":"github"}`)); err == nil {
		t.Fatal("install without an authenticated principal must error")
	}
}

func TestStoreInstallUnavailableWithoutInstaller(t *testing.T) {
	tool := newStoreToolForTest(t)
	if _, err := tool.Call(ctxWithPrincipal(), storeRC(), "", StoreInstallToolName, json.RawMessage(`{"code":"github"}`)); err == nil {
		t.Fatal("install must be unavailable when no installer is wired")
	}
}

func TestStoreUninstallCall(t *testing.T) {
	installer := &fakeInstaller{}
	tool := storeToolWithInstaller(t, installer)
	if _, err := tool.Call(ctxWithPrincipal(), storeRC(), "", StoreUninstallToolName, json.RawMessage(`{"code":"github"}`)); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if len(installer.uninstalled) != 1 || installer.uninstalled[0] != "github" {
		t.Fatalf("uninstall must call the installer, got %v", installer.uninstalled)
	}
}

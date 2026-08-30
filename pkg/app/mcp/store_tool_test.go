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
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

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
	raw, err := tool.Call(context.Background(), storeRC(), StoreSearchToolName, json.RawMessage(`{"query":"git"}`))
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
}

func TestStoreSearchByCategory(t *testing.T) {
	tool := newStoreToolForTest(t)
	raw, err := tool.Call(context.Background(), storeRC(), StoreSearchToolName, json.RawMessage(`{"category":"crm"}`))
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
	raw, err := tool.Call(context.Background(), storeRC(), StoreSearchToolName, nil)
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
	raw, err := tool.Call(context.Background(), storeRC(), StoreSearchToolName, json.RawMessage(`{"limit":1}`))
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
	if _, err := tool.Call(context.Background(), storeRC(), "trustgate_store_bogus", nil); err == nil {
		t.Fatal("unknown store tool must error")
	}
}

type fakeInstaller struct {
	installed   []string
	uninstalled []string
	result      *appstore.InstallResult
}

func (f *fakeInstaller) Install(_ context.Context, _ ids.GatewayID, _, code, _ string) (*appstore.InstallResult, error) {
	f.installed = append(f.installed, code)
	if f.result != nil {
		return f.result, nil
	}
	return &appstore.InstallResult{Code: code, Name: code}, nil
}

func (f *fakeInstaller) Uninstall(_ context.Context, _ ids.GatewayID, _, code string) error {
	f.uninstalled = append(f.uninstalled, code)
	return nil
}

func storeToolWithInstaller(t *testing.T, installer appstore.Installer) StoreTool {
	t.Helper()
	tool, err := NewStoreToolWithInstaller(sampleCatalog(), installer)
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
	raw, err := tool.Call(ctxWithPrincipal(), storeRC(), StoreInstallToolName, json.RawMessage(`{"code":"github"}`))
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
	if _, err := tool.Call(context.Background(), storeRC(), StoreInstallToolName, json.RawMessage(`{"code":"github"}`)); err == nil {
		t.Fatal("install without an authenticated principal must error")
	}
}

func TestStoreInstallUnavailableWithoutInstaller(t *testing.T) {
	tool := newStoreToolForTest(t)
	if _, err := tool.Call(ctxWithPrincipal(), storeRC(), StoreInstallToolName, json.RawMessage(`{"code":"github"}`)); err == nil {
		t.Fatal("install must be unavailable when no installer is wired")
	}
}

func TestStoreUninstallCall(t *testing.T) {
	installer := &fakeInstaller{}
	tool := storeToolWithInstaller(t, installer)
	if _, err := tool.Call(ctxWithPrincipal(), storeRC(), StoreUninstallToolName, json.RawMessage(`{"code":"github"}`)); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if len(installer.uninstalled) != 1 || installer.uninstalled[0] != "github" {
		t.Fatalf("uninstall must call the installer, got %v", installer.uninstalled)
	}
}

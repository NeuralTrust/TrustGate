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
	"errors"
	"strings"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
)

type fakeRegistryLister struct{ items []*registrydomain.Registry }

func (f fakeRegistryLister) List(context.Context, registrydomain.ListFilter) ([]*registrydomain.Registry, int, error) {
	return f.items, len(f.items), nil
}

type panicRegistryLister struct{}

func (panicRegistryLister) List(context.Context, registrydomain.ListFilter) ([]*registrydomain.Registry, int, error) {
	panic("registry list must not be called by Store search")
}

type fakeGrantReader struct {
	items []*storeaccessdomain.Grant
	err   error
}

func (f fakeGrantReader) ListByGateway(context.Context, ids.GatewayID) ([]*storeaccessdomain.Grant, error) {
	return f.items, f.err
}

func shelfReg(code string) *registrydomain.Registry {
	return &registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		MCPTarget: &registrydomain.MCPTarget{Code: code},
	}
}

// grantFor grants a catalog code (every instance) to groups/users; a non-nil
// registry id narrows it to that instance.
func grantFor(code string, registryID ids.RegistryID, groups, users []string) *storeaccessdomain.Grant {
	g, err := storeaccessdomain.New(ids.New[ids.GatewayKind](), code, registryID, groups, users)
	if err != nil {
		panic(err)
	}
	return g
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

// selfServiceCtx carries a self-service (free tier) gateway with nothing
// stamped: the zero-friction default, where the Store is open.
func selfServiceCtx() context.Context {
	return appgateway.WithGateway(context.Background(), &gatewaydomain.Gateway{
		Entitlements: gatewaydomain.Entitlements{Tier: "free"},
	})
}

// enterpriseGateway is a governed gateway with the given configured Store mode.
func enterpriseGateway(mode string) *gatewaydomain.Gateway {
	return &gatewaydomain.Gateway{
		Entitlements: gatewaydomain.Entitlements{Tier: "enterprise"},
		Metadata:     gatewaydomain.WithStoreMode(nil, mode),
	}
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
	raw, err := tool.Call(selfServiceCtx(), storeRC(), "", StoreSearchToolName, json.RawMessage(`{"query":"git"}`))
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
	raw, err := tool.Call(selfServiceCtx(), storeRC(), "", StoreSearchToolName, json.RawMessage(`{"category":"crm"}`))
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
	raw, err := tool.Call(selfServiceCtx(), storeRC(), "", StoreSearchToolName, nil)
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
	raw, err := tool.Call(selfServiceCtx(), storeRC(), "", StoreSearchToolName, json.RawMessage(`{"limit":1}`))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	sc := decodeStructured(t, raw)
	if sc["total"].(float64) != 3 || sc["returned"].(float64) != 1 || sc["truncated"] != true {
		t.Fatalf("limit=1 over 3 must truncate: %+v", sc)
	}
}

func TestStoreSearchRejectsMalformedArguments(t *testing.T) {
	t.Parallel()
	tool := newStoreToolForTest(t)
	if _, err := tool.Call(selfServiceCtx(), storeRC(), "", StoreSearchToolName, json.RawMessage(`{"limit":`)); !errors.Is(err, ErrStoreToolUnavailable) {
		t.Fatalf("malformed search error = %v", err)
	}
}

func TestStoreSearchUsesGrantIndexWithoutRegistryRead(t *testing.T) {
	t.Parallel()
	grant := grantFor("gitlab", ids.New[ids.RegistryKind](), []string{"sre"}, nil)
	tool, err := NewStoreToolWithInstaller(sampleCatalog(), nil, panicRegistryLister{}, fakeGrantReader{items: []*storeaccessdomain.Grant{grant}}, nil, nil)
	if err != nil {
		t.Fatalf("new Store tool: %v", err)
	}
	ctx := appgateway.WithGateway(
		identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "ana", Claims: map[string]any{identity.ClaimGroups: "sre"}}),
		enterpriseGateway(gatewaydomain.StoreModeCurated),
	)
	raw, err := tool.Call(ctx, storeRC(), "", StoreSearchToolName, nil)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if got := resultsByCode(t, raw)["gitlab"]["store_state"]; got != storeStateAvailable {
		t.Fatalf("instance grant state = %v", got)
	}
}

func TestStoreSearchSurfacesGrantReadError(t *testing.T) {
	t.Parallel()
	readErr := errors.New("grants unavailable")
	tool, err := NewStoreToolWithInstaller(sampleCatalog(), nil, nil, fakeGrantReader{err: readErr}, nil, nil)
	if err != nil {
		t.Fatalf("new Store tool: %v", err)
	}
	ctx := appgateway.WithGateway(context.Background(), enterpriseGateway(gatewaydomain.StoreModeCurated))
	if _, err = tool.Call(ctx, storeRC(), "", StoreSearchToolName, nil); !errors.Is(err, readErr) {
		t.Fatalf("search error = %v", err)
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
	return storeToolWithGrants(t, nil, items...)
}

func storeToolWithGrants(t *testing.T, grants []*storeaccessdomain.Grant, items ...*registrydomain.Registry) StoreTool {
	t.Helper()
	tool, err := NewStoreToolWithInstaller(sampleCatalog(), nil, fakeRegistryLister{items: items}, fakeGrantReader{items: grants}, nil, nil)
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

// TestStoreSearchTagsShelfState: under Selected the whole catalog is browsable
// and each server's state is the caller's own outcome — "available" when a
// grant names them for the code (or one of its instances), "request" otherwise.
func TestStoreSearchTagsShelfState(t *testing.T) {
	gitlab := shelfReg("gitlab")
	tool := storeToolWithGrants(t,
		[]*storeaccessdomain.Grant{
			grantFor("github", ids.RegistryID{}, nil, []string{"ana"}),
			grantFor("gitlab", gitlab.ID, []string{"sre"}, nil),
			// salesforce granted to nobody
		},
		shelfReg("github"), gitlab,
	)
	curated := appgateway.WithGateway(
		identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "ana", Claims: map[string]any{identity.ClaimGroups: []string{"eng"}}}),
		enterpriseGateway(gatewaydomain.StoreModeCurated))
	raw, err := tool.Call(curated, storeRC(), "", StoreSearchToolName, nil)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	got := resultsByCode(t, raw)
	if len(got) != 3 {
		t.Fatalf("Selected must browse the whole catalog, got %d results", len(got))
	}
	if got["github"]["store_state"] != storeStateAvailable {
		t.Fatalf("github (granted to ana) should be available, got %v", got["github"]["store_state"])
	}
	if got["gitlab"]["store_state"] != storeStateRequest {
		t.Fatalf("gitlab (granted to sre, caller is eng) should be request, got %v", got["gitlab"]["store_state"])
	}
	if got["salesforce"]["store_state"] != storeStateRequest {
		t.Fatalf("salesforce (granted to nobody) should be request, got %v", got["salesforce"]["store_state"])
	}

	// The same caller in the granted group sees gitlab as available.
	sre := appgateway.WithGateway(
		identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "ana", Claims: map[string]any{identity.ClaimGroups: []string{"sre"}}}),
		enterpriseGateway(gatewaydomain.StoreModeCurated))
	raw, err = tool.Call(sre, storeRC(), "", StoreSearchToolName, nil)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if got := resultsByCode(t, raw); got["gitlab"]["store_state"] != storeStateAvailable {
		t.Fatalf("gitlab should be available for sre, got %v", got["gitlab"]["store_state"])
	}

	// Under All everything is available, shelved or not.
	raw, err = tool.Call(selfServiceCtx(), storeRC(), "", StoreSearchToolName, nil)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	for code, r := range resultsByCode(t, raw) {
		if r["store_state"] != storeStateAvailable {
			t.Fatalf("All: %s should be available, got %v", code, r["store_state"])
		}
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
	tool := storeToolWithShelf(t, shelfReg("github"))
	// Gateway default is curated (only shelf servers), but this principal's token
	// carries store_access=open, so the whole catalog is browsable for them.
	gw := enterpriseGateway(gatewaydomain.StoreModeCurated)
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
	if mode := decodeStructured(t, raw)["mode"]; mode != gatewaydomain.StoreModeOpen {
		t.Fatalf("reported mode = %v, want %s", mode, gatewaydomain.StoreModeOpen)
	}
}

func TestStoreSearchPrincipalNoneClosesStore(t *testing.T) {
	// Gateway default is open, but this principal's token carries
	// store_access=none, so the Store is closed for them.
	tool := storeToolWithShelf(t, shelfReg("github"))
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

// TestStoreSearchCuratedModeShowsNonShelfAsRequest: Selected browses the whole
// catalog so a user can discover what to ask for; a non-shelf server is tagged
// "request" (installing it files an approval request) while a granted shelf
// server is "available" (instant).
func TestStoreSearchCuratedModeShowsNonShelfAsRequest(t *testing.T) {
	tool := storeToolWithGrants(t,
		[]*storeaccessdomain.Grant{grantFor("github", ids.RegistryID{}, nil, []string{"ana"})},
		shelfReg("github"),
	)
	gw := enterpriseGateway(gatewaydomain.StoreModeCurated)
	ctx := appgateway.WithGateway(identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "ana"}), gw)

	raw, err := tool.Call(ctx, storeRC(), "", StoreSearchToolName, nil)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	got := resultsByCode(t, raw)
	if got["github"]["store_state"] != storeStateAvailable {
		t.Fatalf("granted server github must be available, got %v", got["github"]["store_state"])
	}
	if got["salesforce"]["store_state"] != storeStateRequest {
		t.Fatalf("non-shelf server must be browsable as a request, got %v", got["salesforce"]["store_state"])
	}
}

type fakeInstaller struct {
	installed    []string
	lastGroups   []string
	lastRegistry ids.RegistryID
	uninstalled  []string
	lastInstance string
	instances    []*installationdomain.Installation
	uninstallErr error
	result       *appstore.InstallResult
}

type failingConnect struct{ err error }

func (f failingConnect) CreateServerTicket(context.Context, ids.GatewayID, string, string, string, string) (string, error) {
	return "", f.err
}

type failingConfigure struct{ err error }

func (f failingConfigure) CreateTicket(context.Context, appoauth.ConfigureTicketRequest) (string, error) {
	return "", f.err
}

func (f *fakeInstaller) Install(_ context.Context, in appstore.InstallRequest) (*appstore.InstallResult, error) {
	f.installed = append(f.installed, in.Code)
	f.lastGroups = in.Groups
	f.lastRegistry = in.RegistryID
	if f.result != nil {
		return f.result, nil
	}
	return &appstore.InstallResult{Code: in.Code, Name: in.Code}, nil
}

func (f *fakeInstaller) Instances(_ context.Context, _ ids.GatewayID, _, _ string) ([]*installationdomain.Installation, error) {
	return f.instances, nil
}

func (f *fakeInstaller) Uninstall(_ context.Context, _ ids.GatewayID, _, code, instance string) error {
	if f.uninstallErr != nil {
		return f.uninstallErr
	}
	f.uninstalled = append(f.uninstalled, code)
	f.lastInstance = instance
	return nil
}

func storeToolWithInstaller(t *testing.T, installer appstore.Installer) StoreTool {
	t.Helper()
	tool, err := NewStoreToolWithInstaller(sampleCatalog(), installer, nil, nil, nil, nil)
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

// toolDescription reads a definition's description back off the wire, which is
// where a client sees it.
func toolDescription(t *testing.T, tool Tool) string {
	t.Helper()
	raw, err := json.Marshal(tool)
	if err != nil {
		t.Fatalf("marshal %s: %v", tool.Name, err)
	}
	var decoded struct {
		Description string `json:"description"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode %s: %v", tool.Name, err)
	}
	return decoded.Description
}

// The Store's tools have to be listed for a client to call them, so a client
// asked "what tools do I have?" reads them next to the user's own. Every one of
// them says it is not part of that answer.
func TestStoreDefinitionsSayTheyAreNotTheUsersTools(t *testing.T) {
	tool := storeToolWithInstaller(t, &fakeInstaller{})
	defs := tool.Definitions(context.Background(), storeRC())
	if len(defs) != 3 {
		t.Fatalf("expected search+install+uninstall, got %d", len(defs))
	}
	for _, def := range defs {
		description := toolDescription(t, def)
		if !strings.Contains(description, GatewayToolDisclaimer) {
			t.Fatalf("%s does not say it is a gateway tool: %q", def.Name, description)
		}
		if !strings.Contains(description, InventoryToolName) {
			t.Fatalf("%s should point at %s for what the user actually has", def.Name, InventoryToolName)
		}
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

func TestStoreInstallSurfacesLinkErrors(t *testing.T) {
	t.Parallel()
	ticketErr := errors.New("ticket unavailable")
	tests := []struct {
		name      string
		result    *appstore.InstallResult
		configure ConfigureGateway
		connect   ServerConnectGateway
	}{
		{
			name:      "configure ticket",
			result:    &appstore.InstallResult{Code: "github", Name: "GitHub", RequiresConfig: true},
			configure: failingConfigure{err: ticketErr},
		},
		{
			name:    "connect ticket",
			result:  &appstore.InstallResult{Code: "github", Name: "GitHub", RequiresAuth: true},
			connect: failingConnect{err: ticketErr},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			tool, err := NewStoreToolWithInstaller(sampleCatalog(), &fakeInstaller{result: test.result}, nil, nil, test.configure, test.connect)
			if err != nil {
				t.Fatalf("new Store tool: %v", err)
			}
			_, err = tool.Call(ctxWithPrincipal(), storeRC(), "https://gateway.example", StoreInstallToolName, json.RawMessage(`{"code":"github"}`))
			if !errors.Is(err, ticketErr) || !errors.Is(err, ErrStoreToolUnavailable) {
				t.Fatalf("install link error = %v", err)
			}
		})
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

func TestStoreUninstallPassesInstanceID(t *testing.T) {
	installer := &fakeInstaller{}
	tool := storeToolWithInstaller(t, installer)
	if _, err := tool.Call(ctxWithPrincipal(), storeRC(), "", StoreUninstallToolName,
		json.RawMessage(`{"code":"snowflake","instance":"018f-abc"}`)); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if installer.lastInstance != "018f-abc" {
		t.Fatalf("uninstall must pass the instance id through, got %q", installer.lastInstance)
	}
}

func TestStoreUninstallAmbiguousReturnsInstancePicker(t *testing.T) {
	a, _ := installationdomain.New(ids.New[ids.GatewayKind](), "ana", "snowflake", "ana", map[string]string{"database": "analytics"})
	f, _ := installationdomain.New(ids.New[ids.GatewayKind](), "ana", "snowflake", "ana", map[string]string{"database": "finance"})
	installer := &fakeInstaller{
		uninstallErr: appstore.ErrAmbiguousInstance,
		instances:    []*installationdomain.Installation{a, f},
	}
	tool := storeToolWithInstaller(t, installer)
	raw, err := tool.Call(ctxWithPrincipal(), storeRC(), "", StoreUninstallToolName, json.RawMessage(`{"code":"snowflake"}`))
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	var out struct {
		StructuredContent struct {
			Ambiguous bool `json:"ambiguous"`
			Instances []struct {
				Instance string `json:"instance"`
				Label    string `json:"label"`
			} `json:"instances"`
		} `json:"structuredContent"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.StructuredContent.Ambiguous || len(out.StructuredContent.Instances) != 2 {
		t.Fatalf("expected an ambiguous picker with two instances, got %+v", out.StructuredContent)
	}
	if out.StructuredContent.Instances[0].Instance != a.ID.String() {
		t.Fatalf("picker must carry the instance ids, got %+v", out.StructuredContent.Instances)
	}
	if len(installer.uninstalled) != 0 {
		t.Fatal("an ambiguous uninstall must not remove anything")
	}
}

// TestStoreInstallInstanceChoiceRoundTrip: when the installer reports several
// usable configured instances the tool returns the list (no install recorded)
// and a follow-up call with `instance` reaches the installer as a registry id.
func TestStoreInstallInstanceChoiceRoundTrip(t *testing.T) {
	finance := ids.New[ids.RegistryKind]()
	analytics := ids.New[ids.RegistryKind]()
	inst := &fakeInstaller{result: &appstore.InstallResult{
		Code: "github", Name: "GitHub", RequiresInstanceChoice: true,
		InstanceChoices: []appstore.InstanceChoice{{RegistryID: finance, Name: "GitHub (finance)"}, {RegistryID: analytics, Name: "GitHub (analytics)"}},
	}}
	tool := storeToolWithInstaller(t, inst)
	raw, err := tool.Call(ctxWithPrincipal(), storeRC(), "https://gw.example", StoreInstallToolName, json.RawMessage(`{"code":"github"}`))
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	sc := decodeStructured(t, raw)
	if sc["requires_instance_choice"] != true {
		t.Fatalf("expected requires_instance_choice, got %+v", sc)
	}
	choices, _ := sc["instances"].([]any)
	if len(choices) != 2 || choices[0].(map[string]any)["instance"] != finance.String() || choices[0].(map[string]any)["name"] != "GitHub (finance)" {
		t.Fatalf("choices must carry registry id and name, got %+v", sc["instances"])
	}

	inst.result = nil
	if _, err := tool.Call(ctxWithPrincipal(), storeRC(), "https://gw.example", StoreInstallToolName,
		json.RawMessage(`{"code":"github","instance":"`+analytics.String()+`"}`)); err != nil {
		t.Fatalf("install with instance: %v", err)
	}
	if inst.lastRegistry != analytics {
		t.Fatalf("the chosen instance must reach the installer as RegistryID, got %s", inst.lastRegistry)
	}
	if _, err := tool.Call(ctxWithPrincipal(), storeRC(), "https://gw.example", StoreInstallToolName,
		json.RawMessage(`{"code":"github","instance":"not-a-uuid"}`)); err == nil {
		t.Fatal("a malformed instance id must be refused")
	}
}

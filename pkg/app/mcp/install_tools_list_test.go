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
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// lagEnsurer is the data-plane view of EnsureRegistry: the control plane
// accepts the registry, and this replica's snapshot does not have it yet.
type lagEnsurer struct{}

func (lagEnsurer) Ensure(context.Context, ids.GatewayID, string) error { return nil }

func deepWiki() catalogdomain.MCPServer {
	return catalogdomain.MCPServer{
		Code:        "com.deepwiki/mcp",
		DisplayName: "DeepWiki",
		URL:         "https://mcp.deepwiki.com/mcp",
		Transport:   "streamable-http",
		SelfService: true,
		Tools: []catalogdomain.MCPTool{
			{Name: "ask_wiki_question"},
			{Name: "read_wiki_contents"},
			{Name: "read_wiki_structure"},
		},
	}
}

func toolNamesOf(t *testing.T, listed any) []string {
	t.Helper()
	body, ok := listed.(map[string]any)
	if !ok {
		t.Fatalf("tools/list result = %T", listed)
	}
	tools, ok := body["tools"].([]Tool)
	if !ok {
		t.Fatalf("tools = %T", body["tools"])
	}
	return toolNames(tools)
}

// TestToolsListIncludesServerRightAfterInstall is the data-plane install: the
// installation is recorded and Ensure succeeds, but the config snapshot has
// not been pushed yet. The next tools/list for that principal must already
// carry the new server's tools. Uninstall drops them at once, because the
// installation row is what the surface reads.
func TestToolsListIncludesServerRightAfterInstall(t *testing.T) {
	entry := deepWiki()
	catalog := e2eCatalog{servers: []catalogdomain.MCPServer{entry}}
	regs := &e2eRegistries{}
	installs := &e2eInstalls{}
	installer, err := appstore.NewInstaller(catalog, regs, installs, nil, lagEnsurer{})
	if err != nil {
		t.Fatalf("NewInstaller: %v", err)
	}
	gw := ids.New[ids.GatewayKind]()
	ctx := selfServiceDefaultCtx("ana")
	res, err := installer.Install(ctx, appstore.InstallRequest{
		GatewayID:    gw,
		PrincipalSub: "ana",
		Code:         entry.Code,
		InstalledBy:  "ana",
		OpenMode:     true,
	})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.Status != installationdomain.StatusInstalled || !res.RegistryID.IsNil() {
		t.Fatalf("install result = %+v", res)
	}
	if len(regs.items) != 0 {
		t.Fatal("the snapshot must still be empty when tools/list runs")
	}

	scoper, err := appstore.NewScoper(installs, regs, nil, appstore.WithScoperCatalog(catalog))
	if err != nil {
		t.Fatalf("NewScoper: %v", err)
	}
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		entry.URL: {tools: tools("ask_wiki_question", "read_wiki_contents", "read_wiki_structure")},
	}}
	dispatcher := NewRPCDispatcher(newTestComposer(dialer), NewPluginRunner(nil, nil), nil, nil, nil).
		WithStoreScoper(scoper)
	rc := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}

	listed, err := dispatcher.Dispatch(ctx, rc, "", "tools/list", nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	want := []string{"deepwiki_ask_wiki_question", "deepwiki_read_wiki_contents", "deepwiki_read_wiki_structure"}
	if got := toolNamesOf(t, listed); len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("tools/list = %v, want %v", got, want)
	}

	// The snapshot landing replaces the stand-in. Names stay put, and the
	// server is not listed twice.
	regs.items = append(regs.items, &registrydomain.Registry{
		ID:      ids.New[ids.RegistryKind](),
		Name:    "DeepWiki",
		Type:    registrydomain.TypeMCP,
		Enabled: true,
		MCPTarget: &registrydomain.MCPTarget{
			Code: entry.Code, URL: entry.URL, Transport: registrydomain.MCPTransportStreamableHTTP,
		},
	})
	listed, err = dispatcher.Dispatch(ctx, rc, "", "tools/list", nil)
	if err != nil {
		t.Fatalf("tools/list after snapshot: %v", err)
	}
	if got := toolNamesOf(t, listed); len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("tools/list after snapshot = %v, want %v", got, want)
	}

	installs.rows[0].Status = installationdomain.StatusRevoked
	listed, err = dispatcher.Dispatch(ctx, rc, "", "tools/list", nil)
	if err != nil {
		t.Fatalf("tools/list after uninstall: %v", err)
	}
	if got := toolNamesOf(t, listed); len(got) != 0 {
		t.Fatalf("uninstall must drop the server's tools immediately, got %v", got)
	}
}

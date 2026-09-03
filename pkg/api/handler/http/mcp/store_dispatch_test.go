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

package mcp_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/app/mcp/mocks"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// stubScoper adds a fixed set of registries to the Store consumer, standing in
// for the real CatalogScoper.
type stubScoper struct{ regs []*registrydomain.Registry }

func (s stubScoper) Scope(_ context.Context, rc *appconsumer.RoutableConsumer) (*appconsumer.RoutableConsumer, error) {
	if rc == nil || rc.Consumer == nil || !consumerdomain.IsStoreConsumer(rc.Consumer) {
		return rc, nil
	}
	scoped := *rc
	scoped.Registries = s.regs
	return &scoped, nil
}

type stubCatalog struct{ servers []catalogdomain.MCPServer }

func (s stubCatalog) ListMCPServers() []catalogdomain.MCPServer { return s.servers }

func storeToolForDispatch(t *testing.T) appmcp.StoreTool {
	t.Helper()
	tool, err := appmcp.NewStoreTool(stubCatalog{servers: []catalogdomain.MCPServer{
		{Code: "github", DisplayName: "GitHub", Category: "dev", Description: "code hosting"},
		{Code: "salesforce", DisplayName: "Salesforce", Category: "crm"},
	}})
	require.NoError(t, err)
	return tool
}

func toolNames(tools []appmcp.Tool) []string {
	names := make([]string, len(tools))
	for i, tool := range tools {
		names[i] = tool.Name
	}
	return names
}

func TestRPCGateway_Store_ListsAndCallsSearch(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).Return(nil, nil).Once()
	g := mcphttp.NewRPCGatewayWithMetaTools(composer, noopRunner(), nil, nil, storeToolForDispatch(t))

	rc := &appconsumer.RoutableConsumer{
		Consumer: consumerdomain.BuildStoreConsumer(ids.New[ids.GatewayKind]()),
	}

	listed, err := g.Dispatch(context.Background(), rc, "tools/list", nil)
	require.NoError(t, err)
	tools := listed.(map[string]any)["tools"].([]appmcp.Tool)
	require.Contains(t, toolNames(tools), appmcp.StoreSearchToolName)

	called, err := g.Dispatch(
		context.Background(),
		rc,
		"tools/call",
		json.RawMessage(`{"name":"`+appmcp.StoreSearchToolName+`","arguments":{"query":"git"}}`),
	)
	require.NoError(t, err)
	require.Contains(t, string(called.(json.RawMessage)), `"github"`)
}

func TestRPCGateway_Store_ScoperSurfacesInstalledTools(t *testing.T) {
	t.Parallel()
	installedReg := &registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		MCPTarget: &registrydomain.MCPTarget{Code: "github"},
	}
	composer := mocks.NewComposer(t)
	// ListTools must be called with the SCOPED consumer: the Store consumer now
	// carries the installed registry.
	composer.EXPECT().
		ListTools(mock.Anything, mock.MatchedBy(func(rc *appconsumer.RoutableConsumer) bool {
			return rc != nil && len(rc.Registries) == 1 && rc.Registries[0].ID == installedReg.ID
		})).
		Return([]appmcp.Tool{{Name: "github_create_issue"}}, nil).Once()

	g := mcphttp.NewRPCGatewayWithMetaTools(composer, noopRunner(), nil, nil, storeToolForDispatch(t)).
		WithStoreScoper(stubScoper{regs: []*registrydomain.Registry{installedReg}})

	rc := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(ids.New[ids.GatewayKind]())}

	listed, err := g.Dispatch(context.Background(), rc, "tools/list", nil)
	require.NoError(t, err)
	names := toolNames(listed.(map[string]any)["tools"].([]appmcp.Tool))
	require.Contains(t, names, "github_create_issue")      // an installed upstream tool
	require.Contains(t, names, appmcp.StoreSearchToolName) // and the Store meta-tools alongside
}

func TestRPCGateway_Store_NotOfferedOnRegularConsumer(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).
		Return([]appmcp.Tool{{Name: "upstream_tool"}}, nil).Once()
	g := mcphttp.NewRPCGatewayWithMetaTools(composer, noopRunner(), nil, nil, storeToolForDispatch(t))

	rc := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{
		ID:   ids.New[ids.ConsumerKind](),
		Slug: "regular",
		Type: consumerdomain.TypeMCP,
	}}

	listed, err := g.Dispatch(context.Background(), rc, "tools/list", nil)
	require.NoError(t, err)
	tools := listed.(map[string]any)["tools"].([]appmcp.Tool)
	require.NotContains(t, toolNames(tools), appmcp.StoreSearchToolName)

	// A regular consumer cannot invoke the Store meta-tools.
	_, err = g.Dispatch(
		context.Background(),
		rc,
		"tools/call",
		json.RawMessage(`{"name":"`+appmcp.StoreSearchToolName+`","arguments":{}}`),
	)
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "not permitted") || strings.Contains(err.Error(), appmcp.StoreSearchToolName))
}

// The synthetic Store consumer has no registries of its own, so the composer
// rejects tools/list with ErrNoMCPRegistries. That must not fail the listing:
// the Store's tools are the gateway meta-tools, so an empty upstream listing is
// tolerated and the meta-tools are still advertised. (Regression: the Store
// connected but surfaced 0 tools because this error propagated to the client.)
func TestRPCGateway_Store_ToleratesNoRegistries(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).
		Return(nil, appmcp.ErrNoMCPRegistries).Once()
	g := mcphttp.NewRPCGatewayWithMetaTools(composer, noopRunner(), nil, nil, storeToolForDispatch(t))

	rc := &appconsumer.RoutableConsumer{
		Consumer: consumerdomain.BuildStoreConsumer(ids.New[ids.GatewayKind]()),
	}

	listed, err := g.Dispatch(context.Background(), rc, "tools/list", nil)
	require.NoError(t, err)
	tools := listed.(map[string]any)["tools"].([]appmcp.Tool)
	require.Contains(t, toolNames(tools), appmcp.StoreSearchToolName)
}

// The no-registries tolerance is Store-only: a regular MCP consumer that has no
// registries still gets the validation error (there is nothing else to serve).
func TestRPCGateway_RegularConsumer_NoRegistriesStillErrors(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).
		Return(nil, appmcp.ErrNoMCPRegistries).Once()
	g := mcphttp.NewRPCGatewayWithMetaTools(composer, noopRunner(), nil, nil, storeToolForDispatch(t))

	rc := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{
		ID:   ids.New[ids.ConsumerKind](),
		Slug: "regular",
		Type: consumerdomain.TypeMCP,
	}}

	_, err := g.Dispatch(context.Background(), rc, "tools/list", nil)
	require.ErrorIs(t, err, appmcp.ErrNoMCPRegistries)
}

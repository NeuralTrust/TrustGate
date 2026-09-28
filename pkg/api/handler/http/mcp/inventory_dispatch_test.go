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
	"testing"

	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/app/mcp/mocks"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func inventoryConsumer(t *testing.T) *appconsumer.RoutableConsumer {
	t.Helper()
	gatewayID := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gatewayID, "notion", "",
		&registrydomain.MCPTarget{URL: "https://notion.example.com/mcp", Code: "com.notion/mcp"})
	require.NoError(t, err)
	return &appconsumer.RoutableConsumer{
		Consumer:   &consumerdomain.Consumer{Type: consumerdomain.TypeMCP, GatewayID: gatewayID},
		Registries: []*registrydomain.Registry{reg},
	}
}

func TestRPCGateway_ListsAndCallsTheInventoryMetaTool(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).Return(nil, nil).Once()
	composer.EXPECT().ToolInventory(mock.Anything, mock.Anything).Return(&appmcp.ToolInventory{
		Servers: []appmcp.InventoryServer{{
			Name:     "notion",
			Code:     "com.notion/mcp",
			State:    appmcp.InventoryStateNeedsConnect,
			Provider: "com.notion/mcp",
		}},
	}, nil).Once()
	inventory, err := appmcp.NewInventoryTool(composer, nil)
	require.NoError(t, err)
	g := mcphttp.NewRPCGateway(composer, noopRunner(), nil).WithInventoryTool(inventory)

	rc := inventoryConsumer(t)
	listed, err := g.Dispatch(context.Background(), rc, "tools/list", nil)
	require.NoError(t, err)
	require.Contains(t, toolNames(listed.(map[string]any)["tools"].([]appmcp.Tool)), appmcp.InventoryToolName)

	called, err := g.Dispatch(context.Background(), rc, "tools/call",
		json.RawMessage(`{"name":"`+appmcp.InventoryToolName+`"}`))
	require.NoError(t, err)
	require.Contains(t, string(called.(json.RawMessage)), appmcp.InventoryStateNeedsConnect)
}

// The inventory exists for exactly this case, so a surface that cannot be
// composed — every server awaiting the user's consent — must not take it down
// with it: the tool is what tells the user which server to connect.
func TestRPCGateway_ConsentPendingStillListsTheInventoryMetaTool(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).
		Return(nil, &appmcp.ConsentRequiredError{Provider: "com.notion/mcp", Ticket: "tk", Path: "/c/mcp"}).Once()
	inventory, err := appmcp.NewInventoryTool(composer, nil)
	require.NoError(t, err)
	g := mcphttp.NewRPCGateway(composer, noopRunner(), nil).WithInventoryTool(inventory)

	listed, err := g.Dispatch(context.Background(), inventoryConsumer(t), "tools/list", nil)
	require.NoError(t, err)
	require.Contains(t, toolNames(listed.(map[string]any)["tools"].([]appmcp.Tool)), appmcp.InventoryToolName)
}

// A consumer whose toolkit names no tool is meant to expose nothing. Handing it
// an inventory would name every server behind that empty surface, so the
// gateway withholds its own tools there too.
func TestRPCGateway_DenyAllToolkitGetsNoInventory(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).Return(nil, nil).Once()
	inventory, err := appmcp.NewInventoryTool(composer, nil)
	require.NoError(t, err)
	g := mcphttp.NewRPCGateway(composer, noopRunner(), nil).WithInventoryTool(inventory)

	rc := inventoryConsumer(t)
	rc.Consumer.MCP = &consumerdomain.MCPPolicy{Toolkit: consumerdomain.Toolkit{}}

	listed, err := g.Dispatch(context.Background(), rc, "tools/list", nil)
	require.NoError(t, err)
	require.NotContains(t, toolNames(listed.(map[string]any)["tools"].([]appmcp.Tool)), appmcp.InventoryToolName)

	_, err = g.Dispatch(context.Background(), rc, "tools/call",
		json.RawMessage(`{"name":"`+appmcp.InventoryToolName+`"}`))
	var notPermitted *appmcp.ToolNotPermittedError
	require.ErrorAs(t, err, &notPermitted)
}

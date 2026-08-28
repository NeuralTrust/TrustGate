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
	"errors"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/stretchr/testify/require"
)

type recordingGateway struct {
	gatewayID    ids.GatewayID
	principalSub string
	consumerPath string
	ticket       string
	createErr    error
	statuses     []appoauth.ProviderStatus
	statusErr    error
	createCalls  int
	statusCalls  int
}

func (c *recordingGateway) CreateTicket(
	_ context.Context,
	gatewayID ids.GatewayID,
	principalSub,
	consumerPath string,
) (string, error) {
	c.createCalls++
	c.gatewayID = gatewayID
	c.principalSub = principalSub
	c.consumerPath = consumerPath
	return c.ticket, c.createErr
}

func (c *recordingGateway) Statuses(
	_ context.Context,
	gatewayID ids.GatewayID,
	principalSub,
	consumerPath string,
) ([]appoauth.ProviderStatus, error) {
	c.statusCalls++
	c.gatewayID = gatewayID
	c.principalSub = principalSub
	c.consumerPath = consumerPath
	return c.statuses, c.statusErr
}

func TestConnectToolNameSanitizesProvider(t *testing.T) {
	t.Parallel()
	require.Equal(t, "trustgate_connect_linear", appmcp.ConnectToolName("Linear"))
	require.Equal(t, "trustgate_connect_com_google_workspace_gmail", appmcp.ConnectToolName("com.google.workspace/gmail"))
}

func TestConnectionToolDefinitionsListOnlyPendingProviders(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	gw := &recordingGateway{statuses: []appoauth.ProviderStatus{
		{Provider: "github", Registry: "github-mcp", Linked: true},
		{Provider: "linear", Registry: "linear-mcp"},
		{Provider: "notion", Registry: "notion-mcp", Linked: true, NeedsReconnect: true},
	}}
	tool, err := appmcp.NewConnectionTool(gw)
	require.NoError(t, err)
	rc := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{
		GatewayID: gatewayID,
		Slug:      "research",
	}}
	ctx := identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "alice"})

	defs := tool.Definitions(ctx, rc)
	require.Equal(t, 0, gw.createCalls)
	require.Equal(t, 1, gw.statusCalls)
	require.Equal(t, gatewayID, gw.gatewayID)
	require.Equal(t, "alice", gw.principalSub)
	require.Equal(t, "/research/mcp", gw.consumerPath)
	require.Len(t, defs, 2)

	linear := marshalTool(t, defs[0])
	require.Equal(t, "trustgate_connect_linear", linear["name"])
	require.Contains(t, linear["description"], "linear is not connected")
	require.Contains(t, linear["description"], "Call this tool when the user asks about linear")
	require.NotContains(t, linear["description"], "only when the user explicitly asks")

	notion := marshalTool(t, defs[1])
	require.Equal(t, "trustgate_connect_notion", notion["name"])
	require.Contains(t, notion["description"], "needs to be reconnected")
}

func TestConnectionToolDefinitionsFailOpen(t *testing.T) {
	t.Parallel()
	tool, err := appmcp.NewConnectionTool(&recordingGateway{statusErr: errors.New("vault down")})
	require.NoError(t, err)
	rc := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{
		GatewayID: ids.New[ids.GatewayKind](),
		Slug:      "research",
	}}
	ctx := identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "alice"})
	require.Empty(t, tool.Definitions(ctx, rc))
	require.Empty(t, tool.Definitions(context.Background(), rc))
}

func TestConnectionToolCallReturnsOptionalConnectLink(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	gw := &recordingGateway{ticket: "ticket+/?"}
	tool, err := appmcp.NewConnectionTool(gw)
	require.NoError(t, err)
	rc := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{
		ID:        ids.New[ids.ConsumerKind](),
		GatewayID: gatewayID,
		Slug:      "research",
	}}
	ctx := identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "alice"})

	raw, err := tool.Call(ctx, rc, "https://mcp.example.com", "trustgate_connect_linear")
	require.NoError(t, err)
	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		StructuredContent map[string]string `json:"structuredContent"`
	}
	require.NoError(t, json.Unmarshal(raw, &result))
	require.Equal(t, 0, gw.statusCalls)
	require.Equal(t, 1, gw.createCalls)
	require.Equal(t, gatewayID, gw.gatewayID)
	require.Equal(t, "alice", gw.principalSub)
	require.Equal(t, "/research/mcp", gw.consumerPath)
	require.Equal(
		t,
		"https://mcp.example.com/research/mcp/connect?ticket=ticket%2B%2F%3F",
		result.StructuredContent["connect_url"],
	)
	require.Equal(t, "user_confirmation_required", result.StructuredContent["action"])
	require.Contains(t, result.Content[0].Text, "let them decide whether to open it")
	require.True(t, tool.Handles("trustgate_connect_linear"))
	require.False(t, tool.Handles("echo"))
}

func TestConnectionToolCallRequiresPrincipalAndValidOrigin(t *testing.T) {
	t.Parallel()
	tool, err := appmcp.NewConnectionTool(&recordingGateway{ticket: "ticket"})
	require.NoError(t, err)
	rc := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{
		GatewayID: ids.New[ids.GatewayKind](),
		Slug:      "research",
	}}

	_, err = tool.Call(context.Background(), rc, "https://mcp.example.com", "trustgate_connect_linear")
	require.ErrorIs(t, err, appmcp.ErrNoPrincipal)

	ctx := identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "alice"})
	_, err = tool.Call(ctx, rc, "javascript:alert(1)", "trustgate_connect_linear")
	require.ErrorIs(t, err, appmcp.ErrConnectionToolUnavailable)
}

func TestConnectionToolCallWrapsTicketFailure(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("store unavailable")
	tool, err := appmcp.NewConnectionTool(&recordingGateway{createErr: sentinel})
	require.NoError(t, err)
	rc := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{
		GatewayID: ids.New[ids.GatewayKind](),
		Slug:      "research",
	}}
	ctx := identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "alice"})

	_, err = tool.Call(ctx, rc, "https://mcp.example.com", "trustgate_connect_linear")
	require.ErrorIs(t, err, sentinel)
	require.ErrorIs(t, err, appmcp.ErrConnectionToolUnavailable)
}

func marshalTool(t *testing.T, tool appmcp.Tool) map[string]any {
	t.Helper()
	raw, err := json.Marshal(tool)
	require.NoError(t, err)
	var definition map[string]any
	require.NoError(t, json.Unmarshal(raw, &definition))
	return definition
}

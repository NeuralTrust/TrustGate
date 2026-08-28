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
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/stretchr/testify/require"
)

type recordingTicketCreator struct {
	gatewayID    ids.GatewayID
	principalSub string
	consumerPath string
	ticket       string
	err          error
}

func (c *recordingTicketCreator) CreateTicket(
	_ context.Context,
	gatewayID ids.GatewayID,
	principalSub,
	consumerPath string,
) (string, error) {
	c.gatewayID = gatewayID
	c.principalSub = principalSub
	c.consumerPath = consumerPath
	return c.ticket, c.err
}

func TestConnectionToolDefinitionRequiresExplicitUserIntent(t *testing.T) {
	t.Parallel()
	tool, err := appmcp.NewConnectionTool(&recordingTicketCreator{})
	require.NoError(t, err)

	raw, err := json.Marshal(tool.Definition())
	require.NoError(t, err)
	var definition map[string]any
	require.NoError(t, json.Unmarshal(raw, &definition))
	require.Equal(t, appmcp.ManageConnectionsToolName, definition["name"])
	require.Contains(t, definition["description"], "only when the user explicitly asks")
	require.Contains(t, definition["description"], "Never call this tool automatically")
	require.Equal(t, false, definition["annotations"].(map[string]any)["openWorldHint"])
}

func TestConnectionToolCallReturnsOptionalConnectLink(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	creator := &recordingTicketCreator{ticket: "ticket+/?"}
	tool, err := appmcp.NewConnectionTool(creator)
	require.NoError(t, err)
	rc := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{
		ID:        ids.New[ids.ConsumerKind](),
		GatewayID: gatewayID,
		Slug:      "research",
	}}
	ctx := identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "alice"})

	raw, err := tool.Call(ctx, rc, "https://mcp.example.com")
	require.NoError(t, err)
	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		StructuredContent map[string]string `json:"structuredContent"`
	}
	require.NoError(t, json.Unmarshal(raw, &result))
	require.Equal(t, gatewayID, creator.gatewayID)
	require.Equal(t, "alice", creator.principalSub)
	require.Equal(t, "/research/mcp", creator.consumerPath)
	require.Equal(
		t,
		"https://mcp.example.com/research/mcp/connect?ticket=ticket%2B%2F%3F",
		result.StructuredContent["connect_url"],
	)
	require.Equal(t, "user_confirmation_required", result.StructuredContent["action"])
	require.Contains(t, result.Content[0].Text, "let them decide whether to open it")
}

func TestConnectionToolCallRequiresPrincipalAndValidOrigin(t *testing.T) {
	t.Parallel()
	tool, err := appmcp.NewConnectionTool(&recordingTicketCreator{ticket: "ticket"})
	require.NoError(t, err)
	rc := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{
		GatewayID: ids.New[ids.GatewayKind](),
		Slug:      "research",
	}}

	_, err = tool.Call(context.Background(), rc, "https://mcp.example.com")
	require.ErrorIs(t, err, appmcp.ErrNoPrincipal)

	ctx := identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "alice"})
	_, err = tool.Call(ctx, rc, "javascript:alert(1)")
	require.ErrorIs(t, err, appmcp.ErrConnectionToolUnavailable)
}

func TestConnectionToolCallWrapsTicketFailure(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("store unavailable")
	tool, err := appmcp.NewConnectionTool(&recordingTicketCreator{err: sentinel})
	require.NoError(t, err)
	rc := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{
		GatewayID: ids.New[ids.GatewayKind](),
		Slug:      "research",
	}}
	ctx := identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "alice"})

	_, err = tool.Call(ctx, rc, "https://mcp.example.com")
	require.ErrorIs(t, err, sentinel)
	require.ErrorIs(t, err, appmcp.ErrConnectionToolUnavailable)
}

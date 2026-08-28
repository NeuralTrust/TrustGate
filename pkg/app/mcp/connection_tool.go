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
	"fmt"
	"net/url"
	"strings"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// ManageConnectionsToolName is the reserved name of TrustGate's connection-management tool.
const ManageConnectionsToolName = "trustgate_manage_connections"

// ErrConnectionToolUnavailable reports that TrustGate could not create a connection-management link.
var ErrConnectionToolUnavailable = errors.New("mcp: connection management unavailable")

// ConnectTicketCreator creates a short-lived ticket for the existing connection screen.
type ConnectTicketCreator interface {
	CreateTicket(ctx context.Context, gatewayID ids.GatewayID, principalSub, consumerPath string) (string, error)
}

// ConnectionTool exposes the connection screen as an explicitly invoked MCP tool.
type ConnectionTool interface {
	Name() string
	Definition() Tool
	Call(ctx context.Context, rc *appconsumer.RoutableConsumer, baseURL string) (json.RawMessage, error)
}

type connectionTool struct {
	connect    ConnectTicketCreator
	definition Tool
}

// NewConnectionTool builds TrustGate's connection-management tool.
func NewConnectionTool(connect ConnectTicketCreator) (ConnectionTool, error) {
	var definition Tool
	if err := json.Unmarshal([]byte(`{
		"name": "trustgate_manage_connections",
		"title": "Manage MCP connections",
		"description": "Use only when the user explicitly asks to view, connect, reconnect, or disconnect external MCP accounts. Never call this tool automatically after an unrelated request or merely because available integrations changed. It returns a secure link that the user may choose to open; it does not open the connection screen.",
		"inputSchema": {
			"type": "object",
			"properties": {},
			"additionalProperties": false
		},
		"outputSchema": {
			"type": "object",
			"properties": {
				"connect_url": {"type": "string", "format": "uri"},
				"action": {"type": "string", "const": "user_confirmation_required"}
			},
			"required": ["connect_url", "action"],
			"additionalProperties": false
		},
		"annotations": {
			"readOnlyHint": true,
			"destructiveHint": false,
			"idempotentHint": false,
			"openWorldHint": false
		}
	}`), &definition); err != nil {
		return nil, fmt.Errorf("%w: build tool definition: %w", ErrConnectionToolUnavailable, err)
	}
	return &connectionTool{connect: connect, definition: definition}, nil
}

func (t *connectionTool) Name() string {
	return ManageConnectionsToolName
}

func (t *connectionTool) Definition() Tool {
	return t.definition
}

func (t *connectionTool) Call(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	baseURL string,
) (json.RawMessage, error) {
	if t == nil || t.connect == nil || rc == nil || rc.Consumer == nil {
		return nil, ErrConnectionToolUnavailable
	}
	principal := identity.PrincipalFromContext(ctx)
	if principal == nil || strings.TrimSpace(principal.Subject) == "" {
		return nil, ErrNoPrincipal
	}
	consumerPath := appconsumer.MCPPath(rc.Consumer.Slug)
	ticket, err := t.connect.CreateTicket(ctx, rc.Consumer.GatewayID, principal.Subject, consumerPath)
	if err != nil {
		return nil, fmt.Errorf("%w: create ticket: %w", ErrConnectionToolUnavailable, err)
	}
	connectURL, err := buildConnectionURL(baseURL, consumerPath, ticket)
	if err != nil {
		return nil, err
	}
	result := map[string]any{
		"content": []map[string]string{{
			"type": "text",
			"text": "The connection screen is available at " + connectURL +
				". Present this link to the user and let them decide whether to open it. Do not claim that it opened automatically.",
		}},
		"structuredContent": map[string]string{
			"connect_url": connectURL,
			"action":      "user_confirmation_required",
		},
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("%w: encode result: %w", ErrConnectionToolUnavailable, err)
	}
	return raw, nil
}

func buildConnectionURL(baseURL, consumerPath, ticket string) (string, error) {
	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || base.Scheme == "" || base.Host == "" ||
		(base.Scheme != "http" && base.Scheme != "https") {
		return "", fmt.Errorf("%w: invalid public MCP base URL", ErrConnectionToolUnavailable)
	}
	base.Path = strings.TrimRight(base.Path, "/") + consumerPath + "/connect"
	base.RawPath = ""
	base.RawQuery = url.Values{"ticket": {ticket}}.Encode()
	base.Fragment = ""
	return base.String(), nil
}

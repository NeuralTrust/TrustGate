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
	"unicode"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

const (
	ConnectToolNamePrefix = "trustgate_connect_"
	maxConnectToolName    = 64
)

var ErrConnectionToolUnavailable = errors.New("mcp: connection management unavailable")

type ConnectionGateway interface {
	CreateTicket(ctx context.Context, gatewayID ids.GatewayID, principalSub, consumerPath string) (string, error)
	Statuses(ctx context.Context, gatewayID ids.GatewayID, principalSub, consumerPath string) ([]appoauth.ProviderStatus, error)
}

type ConnectionTool interface {
	Definitions(ctx context.Context, rc *appconsumer.RoutableConsumer) []Tool
	Handles(name string) bool
	Call(ctx context.Context, rc *appconsumer.RoutableConsumer, baseURL, name string) (json.RawMessage, error)
}

type connectionTool struct {
	connect ConnectionGateway
}

func NewConnectionTool(connect ConnectionGateway) (ConnectionTool, error) {
	if connect == nil {
		return nil, ErrConnectionToolUnavailable
	}
	return &connectionTool{connect: connect}, nil
}

func ConnectToolName(provider string) string {
	slug := sanitizeConnectToolSlug(provider)
	if slug == "" {
		slug = "provider"
	}
	name := ConnectToolNamePrefix + slug
	if len(name) > maxConnectToolName {
		return name[:maxConnectToolName]
	}
	return name
}

func (t *connectionTool) Handles(name string) bool {
	return strings.HasPrefix(name, ConnectToolNamePrefix)
}

func (t *connectionTool) Definitions(ctx context.Context, rc *appconsumer.RoutableConsumer) []Tool {
	if t == nil || t.connect == nil || rc == nil || rc.Consumer == nil {
		return nil
	}
	principal := identity.PrincipalFromContext(ctx)
	if principal == nil || strings.TrimSpace(principal.Subject) == "" {
		return nil
	}
	statuses, err := t.connect.Statuses(
		ctx,
		rc.Consumer.GatewayID,
		principal.Subject,
		appconsumer.MCPPath(rc.Consumer.Slug),
	)
	if err != nil {
		return nil
	}
	usedNames := make(map[string]struct{})
	seenProviders := make(map[string]struct{})
	var tools []Tool
	for _, status := range statuses {
		if !connectionPending(status) {
			continue
		}
		provider := strings.TrimSpace(status.Provider)
		if provider == "" {
			continue
		}
		if _, dup := seenProviders[provider]; dup {
			continue
		}
		seenProviders[provider] = struct{}{}
		name := uniqueConnectToolName(ConnectToolName(provider), usedNames)
		def, err := pendingConnectionDefinition(name, status)
		if err != nil {
			continue
		}
		tools = append(tools, def)
	}
	return tools
}

func (t *connectionTool) Call(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	baseURL,
	name string,
) (json.RawMessage, error) {
	if t == nil || t.connect == nil || rc == nil || rc.Consumer == nil {
		return nil, ErrConnectionToolUnavailable
	}
	if !t.Handles(name) {
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
	label := connectionToolLabel(name)
	result := map[string]any{
		"content": []map[string]string{{
			"type": "text",
			"text": label + " can be connected at " + connectURL +
				". Present this link to the user and let them decide whether to open it. Do not claim that it opened automatically.",
		}},
		"structuredContent": map[string]string{
			"connect_url": connectURL,
			"action":      "user_confirmation_required",
			"tool":        name,
		},
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("%w: encode result: %w", ErrConnectionToolUnavailable, err)
	}
	return raw, nil
}

func connectionPending(status appoauth.ProviderStatus) bool {
	return !status.Linked || status.NeedsReconnect
}

func pendingConnectionDefinition(name string, status appoauth.ProviderStatus) (Tool, error) {
	display := connectionDisplayName(status)
	description := display + " is not connected for this TrustGate MCP user. Call this tool when the user asks about " +
		display + " (its issues, projects, or data) or wants to connect that account. It returns a link the user may open; it does not start OAuth or open the connection screen by itself."
	if status.NeedsReconnect {
		description = display + " is connected but needs to be reconnected for this TrustGate MCP user. Call this tool when the user asks about " +
			display + " or wants to reconnect that account. It returns a link the user may open; it does not start OAuth or open the connection screen by itself."
	}
	raw, err := json.Marshal(map[string]any{
		"name":        name,
		"title":       "Connect " + display,
		"description": description,
		"inputSchema": map[string]any{
			"type":                 "object",
			"properties":           map[string]any{},
			"additionalProperties": false,
		},
		"outputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"connect_url": map[string]any{"type": "string", "format": "uri"},
				"action":      map[string]any{"type": "string", "const": "user_confirmation_required"},
				"tool":        map[string]any{"type": "string"},
			},
			"required":             []string{"connect_url", "action"},
			"additionalProperties": false,
		},
		"annotations": map[string]any{
			"readOnlyHint":    true,
			"destructiveHint": false,
			"idempotentHint":  false,
			"openWorldHint":   false,
		},
	})
	if err != nil {
		return Tool{}, err
	}
	var definition Tool
	if err := json.Unmarshal(raw, &definition); err != nil {
		return Tool{}, err
	}
	return definition, nil
}

func connectionDisplayName(status appoauth.ProviderStatus) string {
	if name := strings.TrimSpace(status.Provider); name != "" {
		return name
	}
	if name := strings.TrimSpace(status.Registry); name != "" {
		return name
	}
	return "this MCP provider"
}

func connectionToolLabel(name string) string {
	slug := strings.TrimPrefix(name, ConnectToolNamePrefix)
	slug = strings.ReplaceAll(slug, "_", " ")
	slug = strings.TrimSpace(slug)
	if slug == "" {
		return "This MCP provider"
	}
	return slug
}

func uniqueConnectToolName(name string, used map[string]struct{}) string {
	if _, exists := used[name]; !exists {
		used[name] = struct{}{}
		return name
	}
	base := name
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s_%d", base, i)
		if len(candidate) > maxConnectToolName {
			candidate = candidate[:maxConnectToolName]
		}
		if _, exists := used[candidate]; !exists {
			used[candidate] = struct{}{}
			return candidate
		}
	}
}

func sanitizeConnectToolSlug(provider string) string {
	var b strings.Builder
	lastUnderscore := false
	for _, r := range strings.ToLower(strings.TrimSpace(provider)) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if b.Len() == 0 || lastUnderscore {
			continue
		}
		b.WriteByte('_')
		lastUnderscore = true
	}
	return strings.Trim(b.String(), "_")
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

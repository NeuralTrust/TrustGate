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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
)

// trustgate_call and trustgate_access.
//
// Both are thin: each call lands on the implementation the earlier tools
// already had — the call-through, the agent tools, the Store tool, the
// connection tool — so a state those tools answer is answered the same way
// here. What changes is the shape around them: one name per verb, arguments
// named for what they are, the earlier tools' names rewritten in the text,
// and a fault the caller can act on returned as a tool error it can read
// rather than an opaque internal error.

// gatewayCallArgs is trustgate_call's input: a tool and its arguments, or an
// agent and a message (or a task to read).
type gatewayCallArgs struct {
	Tool string `json:"tool"`
	// Name is accepted for tool: a caller used to trustgate_call_tool writes
	// it, and refusing what it plainly means helps nobody.
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
	Agent     string          `json:"agent"`
	Message   string          `json:"message"`
	TaskID    string          `json:"task_id"`
	ContextID string          `json:"context_id"`
}

func decodeGatewayCallArgs(raw json.RawMessage) (gatewayCallArgs, error) {
	var args gatewayCallArgs
	if len(bytes.TrimSpace(raw)) == 0 {
		return args, nil
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return gatewayCallArgs{}, err
	}
	args.Tool = strings.TrimSpace(args.Tool)
	if args.Tool == "" {
		args.Tool = strings.TrimSpace(args.Name)
	}
	args.Agent = strings.TrimSpace(args.Agent)
	if args.Tool != "" {
		normalized, err := normalizeCallArguments(args.Arguments)
		if err != nil {
			return gatewayCallArgs{}, err
		}
		args.Arguments = normalized
	}
	return args, nil
}

// GatewayCallTarget reads which tool a tools/call of GatewayCallToolName calls
// and with what, the way CallThroughTarget does for CallToolName. ok is false
// for any other call, and for one that calls an agent.
func GatewayCallTarget(params json.RawMessage) (name string, arguments json.RawMessage, ok bool) {
	var call struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &call); err != nil || call.Name != GatewayCallToolName {
		return "", nil, false
	}
	args, err := decodeGatewayCallArgs(call.Arguments)
	if err != nil || args.Tool == "" || args.Agent != "" {
		return "", nil, false
	}
	return args.Tool, args.Arguments, true
}

// GatewayCallAgentTarget reads the agent and the message of a tools/call of
// GatewayCallToolName that calls an agent. ok is false for any other call.
func GatewayCallAgentTarget(params json.RawMessage) (agent, message string, ok bool) {
	var call struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &call); err != nil || call.Name != GatewayCallToolName {
		return "", "", false
	}
	args, err := decodeGatewayCallArgs(call.Arguments)
	if err != nil || args.Agent == "" || args.Tool != "" {
		return "", "", false
	}
	return args.Agent, args.Message, true
}

func (d *RPCDispatcher) gatewayCall(ctx context.Context, req dispatchRequest, arguments, meta json.RawMessage) (any, error) {
	if d.inventory == nil || !metaToolsPermitted(req.consumer) {
		markMetaTool(ctx)
		return nil, &ToolNotPermittedError{Tool: GatewayCallToolName}
	}
	args, err := decodeGatewayCallArgs(arguments)
	if err != nil {
		markMetaTool(ctx)
		return toolErrorResult(
			GatewayCallToolName+" takes {\"tool\": <tool name>, \"arguments\": {…}} or, for an agent, {\"agent\": <id>, \"message\": <text>}, and these arguments could not be read as that. Fix them and call again.",
			map[string]any{"error": "invalid_arguments"},
		)
	}
	switch {
	case args.Tool != "" && args.Agent != "":
		markMetaTool(ctx)
		return toolErrorResult(
			GatewayCallToolName+" calls either a tool or an agent: pass `tool` or `agent`, not both.",
			map[string]any{"error": "invalid_arguments"},
		)
	case args.Agent != "":
		return d.gatewayCallAgent(ctx, req, args)
	case args.Tool == "":
		markMetaTool(ctx)
		return toolErrorResult(
			GatewayCallToolName+" needs `tool`: the exact name of the tool to call, as "+SearchToolName+" gives it.",
			map[string]any{"error": "missing_tool"},
		)
	}
	if isGatewayToolName(args.Tool) {
		markMetaTool(ctx)
		return toolErrorResult(
			args.Tool+" is one of the gateway's own tools: call it directly, not through "+GatewayCallToolName+".",
			map[string]any{"error": "gateway_tool", "name": args.Tool},
		)
	}
	result, reached, err := d.invokeTool(ctx, req, args.Tool, args.Arguments, meta)
	return withSchemaOnFailureVia(GatewayCallToolName, args.Tool, reached, result, err)
}

func (d *RPCDispatcher) gatewayCallAgent(ctx context.Context, req dispatchRequest, args gatewayCallArgs) (any, error) {
	if d.agents == nil || !isStore(req.consumer) {
		markMetaTool(ctx)
		return toolErrorResult(
			"Agents are not available on this connection: only the MCP Store reaches the user's agents.",
			map[string]any{"error": "not_available"},
		)
	}
	raw, err := json.Marshal(map[string]string{
		"agent":      args.Agent,
		"message":    args.Message,
		"task_id":    strings.TrimSpace(args.TaskID),
		"context_id": strings.TrimSpace(args.ContextID),
	})
	if err != nil {
		return nil, err
	}
	// A call to an agent is real work the person asked for, counted like a
	// tool call, as through CallAgentToolName.
	result, err := d.agents.Call(ctx, CallAgentToolName, raw)
	if err != nil {
		return consolidatedToolError(err)
	}
	return withConsolidatedText(result), nil
}

// accessArgs is trustgate_access's input.
type accessArgs struct {
	Action         string            `json:"action"`
	Target         string            `json:"target"`
	Config         map[string]string `json:"config,omitempty"`
	RegistryID     string            `json:"registry_id,omitempty"`
	InstallationID string            `json:"installation_id,omitempty"`
}

// accessActions are the actions this consumer can take, in the order they are
// offered.
func (d *RPCDispatcher) accessActions(ctx context.Context, rc *appconsumer.RoutableConsumer) []string {
	if !isStore(rc) {
		if d.connections != nil {
			return []string{AccessActionConnect}
		}
		return nil
	}
	var actions []string
	installs := d.storeOffers(ctx, rc, StoreInstallToolName)
	if installs {
		actions = append(actions, AccessActionInstall, AccessActionUninstall)
	}
	if installs || d.storeOffers(ctx, rc, StorePersonalKeyToolName) {
		actions = append(actions, AccessActionConnect)
	}
	if d.storeOffers(ctx, rc, StoreRequestModelsToolName) {
		actions = append(actions, AccessActionRequest)
	}
	return actions
}

func (d *RPCDispatcher) access(ctx context.Context, req dispatchRequest, arguments json.RawMessage) (any, error) {
	markMetaTool(ctx)
	actions := d.accessActions(ctx, req.consumer)
	if len(actions) == 0 || !metaToolsPermitted(req.consumer) {
		return nil, &ToolNotPermittedError{Tool: AccessToolName}
	}
	var args accessArgs
	if len(bytes.TrimSpace(arguments)) > 0 {
		if err := json.Unmarshal(arguments, &args); err != nil {
			return toolErrorResult(
				AccessToolName+" takes {\"action\", \"target\"}, and these arguments could not be read as that. Fix them and call again.",
				map[string]any{"error": "invalid_arguments"},
			)
		}
	}
	args.Action = strings.ToLower(strings.TrimSpace(args.Action))
	args.Target = strings.TrimSpace(args.Target)
	if !containsString(actions, args.Action) {
		return toolErrorResult(
			fmt.Sprintf("%s cannot %q here. It can: %s.", AccessToolName, args.Action, strings.Join(actions, ", ")),
			map[string]any{"error": "invalid_arguments", "actions": actions},
		)
	}
	if args.Target == "" {
		return toolErrorResult(
			AccessToolName+" needs `target`: what the "+args.Action+" applies to.",
			map[string]any{"error": "missing_target"},
		)
	}

	var (
		result json.RawMessage
		err    error
	)
	switch args.Action {
	case AccessActionInstall:
		result, err = d.storeCall(ctx, req, StoreInstallToolName, map[string]any{
			"code": args.Target, "config": args.Config, "instance": args.RegistryID,
		})
	case AccessActionUninstall:
		result, err = d.storeCall(ctx, req, StoreUninstallToolName, map[string]any{
			"code": args.Target, "instance": args.InstallationID,
		})
	case AccessActionRequest:
		result, err = d.storeCall(ctx, req, StoreRequestModelsToolName, map[string]any{
			"provider": args.Target, "registry_id": args.RegistryID,
		})
	case AccessActionConnect:
		return d.accessConnect(ctx, req, args)
	}
	if err != nil {
		return consolidatedToolError(err)
	}
	return accessResult(args.Action, result), nil
}

func (d *RPCDispatcher) storeCall(ctx context.Context, req dispatchRequest, tool string, fields map[string]any) (json.RawMessage, error) {
	for key, value := range fields {
		switch v := value.(type) {
		case string:
			if v == "" {
				delete(fields, key)
			}
		case map[string]string:
			if len(v) == 0 {
				delete(fields, key)
			}
		}
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	return d.store.Call(ctx, req.consumer, req.baseURL, tool, raw)
}

// accessConnect gives the user the link that connects the account one of
// their servers waits on. On the Store that is the server's install link
// (installing an installed server again only answers its link); on an
// application it is the connection tool for the server's provider.
func (d *RPCDispatcher) accessConnect(ctx context.Context, req dispatchRequest, args accessArgs) (any, error) {
	if isStore(req.consumer) && strings.EqualFold(args.Target, AccessTargetPersonalKey) {
		result, err := d.storeCall(ctx, req, StorePersonalKeyToolName, map[string]any{})
		if err != nil {
			return consolidatedToolError(err)
		}
		return accessResult(args.Action, result), nil
	}
	var server *InventoryServer
	if d.inventoryImpl != nil {
		inventory, err := d.inventoryImpl.surface.ToolInventory(ctx, req.consumer)
		if err != nil {
			return nil, err
		}
		server = findInventoryServer(inventory, args.Target)
	}
	if server != nil {
		switch {
		case server.State == InventoryStateReady || server.State == InventoryStateNoTools:
			return marshalToolResult(
				fmt.Sprintf("%s is already connected: its tools can be called now.", server.Name),
				map[string]any{"status": "connected", "server": server.Name},
			)
		case server.State == InventoryStateUnavailable:
			return toolErrorResult(
				fmt.Sprintf("%s is not waiting on an account: the gateway cannot reach it right now (%s). Connecting would not change that.", server.Name, unavailablePhrase(server.Cause)),
				map[string]any{"error": "unavailable", "server": server.Name, "cause": server.Cause},
			)
		case callerCannotConnect(server.Cause):
			return toolErrorResult(
				fmt.Sprintf("%s cannot be connected from here: %s.", server.Name, strings.TrimPrefix(overviewStateText(map[string]any{"state": server.State, "cause": server.Cause}), "not connected: ")),
				map[string]any{"error": "not_available", "server": server.Name, "cause": server.Cause},
			)
		}
	}

	if isStore(req.consumer) {
		if server == nil || server.Code == "" {
			return toolErrorResult(
				fmt.Sprintf("%q is not one of the user's servers. Install it with %s {\"action\": \"install\", \"target\": <code>}, which also answers its connect link.", args.Target, AccessToolName),
				map[string]any{"error": "not_found", "target": args.Target},
			)
		}
		result, err := d.storeCall(ctx, req, StoreInstallToolName, map[string]any{"code": server.Code})
		if err != nil {
			return consolidatedToolError(err)
		}
		return accessResult(args.Action, result), nil
	}

	if d.connections == nil {
		return toolErrorResult("Connecting accounts is not available on this connection.", map[string]any{"error": "not_available"})
	}
	provider := args.Target
	if server != nil && server.Provider != "" {
		provider = server.Provider
	}
	name := pendingConnectTool(d.connections.Definitions(ctx, req.consumer), provider)
	if name == "" {
		return toolErrorResult(
			fmt.Sprintf("Nothing is waiting on an account for %q. %s with no arguments lists the user's servers and which need connecting.", args.Target, SearchToolName),
			map[string]any{"error": "not_found", "target": args.Target},
		)
	}
	result, err := d.connections.Call(ctx, req.consumer, req.baseURL, name)
	if err != nil {
		return consolidatedToolError(err)
	}
	return accessResult(args.Action, result), nil
}

// pendingConnectTool is the connection tool offered for a provider, or "".
func pendingConnectTool(definitions []Tool, provider string) string {
	want := ConnectToolName(provider)
	for _, def := range definitions {
		if def.Name == want {
			return def.Name
		}
	}
	return ""
}

// findInventoryServer finds the server a target names: by its name, its
// catalog code or the provider its account is with.
func findInventoryServer(inventory *ToolInventory, target string) *InventoryServer {
	if inventory == nil {
		return nil
	}
	for i := range inventory.Servers {
		server := &inventory.Servers[i]
		if strings.EqualFold(server.Name, target) || strings.EqualFold(server.Code, target) || strings.EqualFold(server.Provider, target) {
			return server
		}
	}
	return nil
}

// accessResult adds what an access call came to as `status`, and rewrites
// the earlier tools' names in its text. Every field the earlier tool answered
// with is kept as it was: a link's `action: "user_confirmation_required"` is
// how a client knows to put it in front of the person.
func accessResult(action string, result json.RawMessage) json.RawMessage {
	isError, structured, ok := structuredOf(result)
	if !ok {
		return withConsolidatedText(result)
	}
	add := map[string]any{"status": accessStatus(action, isError, structured)}
	return withConsolidatedText(withStructuredFields(result, add))
}

// accessStatus names what an access call came to, from the fields the
// earlier tools answer with.
func accessStatus(action string, isError bool, s map[string]any) string {
	if isError {
		return "error"
	}
	flag := func(key string) bool {
		v, _ := s[key].(bool)
		return v
	}
	has := func(key string) bool {
		v, _ := s[key].(string)
		return v != ""
	}
	switch {
	case flag("requires_admin_setup"):
		return "requires_admin_setup"
	case flag("requires_instance_choice"):
		return "choose_instance"
	case flag("requires_registry_choice"):
		return "choose_registry"
	case flag("ambiguous"):
		return "choose_installation"
	case flag("requires_reason"):
		return "requires_request"
	case flag("disabled"):
		return "disabled"
	case flag("has_access"):
		return "has_access"
	case flag("already_requested"):
		return "already_requested"
	case flag("unknown_provider"):
		return "unknown_provider"
	case flag("requires_config"):
		return "requires_config"
	}
	if v, exists := s["available"].(bool); exists && !v && action == AccessActionRequest {
		return "not_available"
	}
	switch action {
	case AccessActionUninstall:
		if flag("uninstalled") {
			return "uninstalled"
		}
		return "not_installed"
	case AccessActionConnect:
		if has("connect_url") || has("personal_key_url") {
			return "link"
		}
		if flag("already_installed") {
			return "connected"
		}
	case AccessActionInstall:
		if flag("already_installed") {
			return "already_installed"
		}
		return "installed"
	}
	return "done"
}

// consolidatedToolError turns a fault an earlier tool returns as a Go error —
// which reaches the client as an opaque internal error — into a tool error the
// caller can read and act on. A refusal by policy, a pending consent and the
// like stay protocol errors, exactly as on a direct call.
func consolidatedToolError(err error) (any, error) {
	var notPermitted *ToolNotPermittedError
	if errors.As(err, &notPermitted) {
		return nil, err
	}
	switch {
	case errors.Is(err, ErrStoreInstallDisabled):
		return toolErrorResult(
			"Installing from the Store is turned off for this user.",
			map[string]any{"error": "store_closed"},
		)
	case errors.Is(err, ErrNoPrincipal):
		return toolErrorResult(
			"This needs a signed-in person, and this connection is an application's own.",
			map[string]any{"error": "no_person"},
		)
	case errors.Is(err, ErrStoreToolUnavailable), errors.Is(err, ErrConnectionToolUnavailable), errors.Is(err, ErrAgentToolsUnavailable):
		return toolErrorResult(
			strings.TrimPrefix(err.Error(), "mcp: "),
			map[string]any{"error": "not_available"},
		)
	}
	return nil, err
}

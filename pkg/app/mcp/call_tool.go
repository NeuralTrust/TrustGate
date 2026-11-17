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
	"encoding/json"
	"errors"
	"strings"
)

// CallToolName is the gateway meta-tool that calls one of the caller's tools by
// its name.
//
// A server the user installs or connects mid-session reaches their client
// through notifications/tools/list_changed, and a client that honours it
// re-lists. Claude's hosted connectors do not: they keep the tool list they
// fetched when the connector was added, whatever the gateway announces, until
// the user disconnects and reconnects it. This tool is the way round that. It
// is in that first list, so it is always callable, and it reaches whatever is on
// the caller's surface now — the same tools/call path, the same policies,
// guards and audit, only the name travels as an argument.
const CallToolName = "trustgate_call_tool"

// callToolArgs is the meta-tool's input: the tool to call and its arguments.
type callToolArgs struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// CallThroughTarget reads which tool a tools/call of CallToolName is calling
// and with what. ok is false for any other call, and for a call-through that
// does not name a tool. It is what lets a span, an Activity preview, or a
// change detector see the tool that actually ran instead of the wrapper.
func CallThroughTarget(params json.RawMessage) (name string, arguments json.RawMessage, ok bool) {
	var call struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &call); err != nil || call.Name != CallToolName {
		return "", nil, false
	}
	args, err := decodeCallToolArgs(call.Arguments)
	if err != nil || args.Name == "" {
		return "", nil, false
	}
	return args.Name, args.Arguments, true
}

func decodeCallToolArgs(raw json.RawMessage) (callToolArgs, error) {
	var args callToolArgs
	if len(bytes.TrimSpace(raw)) == 0 {
		return args, nil
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return callToolArgs{}, err
	}
	args.Name = strings.TrimSpace(args.Name)
	inner := bytes.TrimSpace(args.Arguments)
	if len(inner) > 0 && inner[0] == '"' {
		// A model that writes the arguments as a JSON-encoded string means the
		// object inside it; the tool would refuse the string.
		var encoded string
		if err := json.Unmarshal(inner, &encoded); err != nil {
			return callToolArgs{}, err
		}
		inner = bytes.TrimSpace([]byte(encoded))
	}
	switch {
	case len(inner) == 0 || bytes.Equal(inner, []byte("null")):
		args.Arguments = nil
	case inner[0] == '{' && json.Valid(inner):
		args.Arguments = json.RawMessage(inner)
	default:
		return callToolArgs{}, errCallToolArgumentsNotObject
	}
	return args, nil
}

var errCallToolArgumentsNotObject = errors.New("mcp: call-through arguments are not an object")

// isGatewayToolName reports whether a name belongs to one of the gateway's own
// tools. Those are always in the client's list, so calling one through
// CallToolName adds nothing but a second way to reach it, and a call-through of
// the call-through is a loop with no end.
func isGatewayToolName(name string) bool {
	return name == CallToolName ||
		name == InventoryToolName ||
		strings.HasPrefix(name, StoreToolNamePrefix) ||
		strings.HasPrefix(name, ConnectToolNamePrefix)
}

func callToolDefinition() (Tool, error) {
	raw, err := json.Marshal(map[string]any{
		"name":  CallToolName,
		"title": "Call one of the user's tools by name",
		"description": "Call one of the user's tools through this gateway by its name, with its arguments. " +
			"Use it when a tool the user has is missing from your own tool list: a server the user installed or connected after this connector was added is reachable here even when your client is still showing the tool list from before. " +
			"Find the tool's exact name with " + InventoryToolName + ", and pass `tool` to " + InventoryToolName + " to read its input schema before the first call. " +
			"The call runs exactly as a direct call to that tool would — the same policies, approvals and audit — and returns that tool's result. " +
			"When the tool is already in your list, call it directly instead." + GatewayToolDisclaimer,
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name": map[string]any{
					"type":        "string",
					"description": "The tool's exact name, as " + InventoryToolName + " lists it (for example linear_save_issue).",
				},
				"arguments": map[string]any{
					"type":                 "object",
					"description":          "The tool's own arguments, matching the input schema " + InventoryToolName + " returns for it. Omit for a tool that takes none.",
					"additionalProperties": true,
				},
			},
			"required":             []string{"name"},
			"additionalProperties": false,
		},
		// It can reach any of the user's tools, writes included, so a client
		// that asks before a write must ask here too.
		"annotations": map[string]any{
			"readOnlyHint":    false,
			"destructiveHint": true,
			"idempotentHint":  false,
			"openWorldHint":   true,
		},
	})
	if err != nil {
		return Tool{}, err
	}
	var def Tool
	if err := json.Unmarshal(raw, &def); err != nil {
		return Tool{}, err
	}
	return def, nil
}

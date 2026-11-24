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
	"fmt"
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

// codeInvalidParams is the JSON-RPC code an upstream answers arguments it
// refuses with.
const codeInvalidParams = -32602

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
	normalized, err := normalizeCallArguments(args.Arguments)
	if err != nil {
		return callToolArgs{}, err
	}
	args.Arguments = normalized
	return args, nil
}

// normalizeCallArguments reads the arguments a caller passed for the tool it
// calls by name: an object, nothing, or an object written as a JSON string.
func normalizeCallArguments(raw json.RawMessage) (json.RawMessage, error) {
	inner := bytes.TrimSpace(raw)
	if len(inner) > 0 && inner[0] == '"' {
		// A model that writes the arguments as a JSON-encoded string means the
		// object inside it; the tool would refuse the string.
		var encoded string
		if err := json.Unmarshal(inner, &encoded); err != nil {
			return nil, err
		}
		inner = bytes.TrimSpace([]byte(encoded))
	}
	switch {
	case len(inner) == 0 || bytes.Equal(inner, []byte("null")):
		return nil, nil
	case inner[0] == '{' && json.Valid(inner):
		return json.RawMessage(inner), nil
	default:
		return nil, errCallToolArgumentsNotObject
	}
}

var errCallToolArgumentsNotObject = errors.New("mcp: call-through arguments are not an object")

// isGatewayToolName reports whether a name belongs to one of the gateway's own
// tools. Those are always in the client's list, so calling one through
// CallToolName adds nothing but a second way to reach it, and a call-through of
// the call-through is a loop with no end.
func isGatewayToolName(name string) bool {
	return IsConsolidatedToolName(name) ||
		name == CallToolName ||
		name == InventoryToolName ||
		name == ListAgentsToolName ||
		name == CallAgentToolName ||
		strings.HasPrefix(name, StoreToolNamePrefix) ||
		strings.HasPrefix(name, ConnectToolNamePrefix)
}

func callToolDefinition() (Tool, error) {
	raw, err := json.Marshal(map[string]any{
		"name":  CallToolName,
		"title": "Call one of the user's tools by name",
		"description": "Call one of the user's tools through this gateway by its name, with its arguments. " +
			"Use it when a tool the user has is missing from your own tool list: a server the user installed or connected after this connector was added is reachable here even when your client is still showing the tool list from before. " +
			"Find the tool's exact name with " + InventoryToolName + ". You can call it straight away with arguments inferred from its name and description: if the tool refuses them, the answer carries its input schema, so fix the arguments and call again. For a tool whose arguments are not obvious, read its schema first with " + InventoryToolName + " {\"tool\": <name>}. " +
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

// withSchemaOnFailure puts the called tool's input schema next to the
// upstream's refusal of a call-through.
//
// A caller going through CallToolName has never been handed the tool's
// definition: its client never listed the tool. It can read the schema from
// the inventory first, but that is a round trip on every first call, when most
// calls get their arguments right from the tool's name and description. So the
// first call goes straight out, and only a refusal pays for the schema — on the
// answer the caller is already reading.
//
// Only the upstream's own answer qualifies. A request or response stage that
// answered in its place said nothing about the arguments, and pointing at the
// schema there sends the caller to fix what was not broken.
func withSchemaOnFailure(name string, reached toolInvocation, result any, err error) (any, error) {
	return withSchemaOnFailureVia(CallToolName, name, reached, result, err)
}

// withSchemaOnFailureVia is withSchemaOnFailure for a call made through the
// named tool, which the refusal tells the caller to call again.
func withSchemaOnFailureVia(via, name string, reached toolInvocation, result any, err error) (any, error) {
	if !reached.upstream || reached.target == nil {
		return result, err
	}
	schema := toolInputSchema(reached.target.Tool)
	if schema == nil {
		return result, err
	}
	if err != nil {
		var rpcErr *RPCError
		if !errors.As(err, &rpcErr) || rpcErr.Code != codeInvalidParams {
			return result, err
		}
		// Kept a protocol error, so telemetry still records the refusal; the
		// message is what clients hand the model, so the schema rides in it.
		enriched := *rpcErr
		enriched.Message = fmt.Sprintf("%s The input schema of %s is %s — fix the arguments and call it again through %s.",
			strings.TrimSpace(rpcErr.Message), name, schema, via)
		return nil, &enriched
	}
	if !isToolErrorResult(result) {
		return result, nil
	}
	return appendResultText(result, fmt.Sprintf(
		"If the arguments were the problem, this is the input schema of %s: %s", name, schema)), nil
}

// toolInputSchema is the tool's advertised inputSchema, nil when it has none
// worth reading.
func toolInputSchema(tool Tool) json.RawMessage {
	raw := bytes.TrimSpace(tool.payload["inputSchema"])
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) || !json.Valid(raw) {
		return nil
	}
	return json.RawMessage(raw)
}

// isToolErrorResult reports whether a tools/call result says the call failed.
func isToolErrorResult(result any) bool {
	raw, ok := resultJSON(result)
	if !ok {
		return false
	}
	var envelope struct {
		IsError bool `json:"isError"`
	}
	return json.Unmarshal(raw, &envelope) == nil && envelope.IsError
}

// appendResultText adds one text block to a tool result, leaving everything
// else in it as it was. A result that cannot be read is returned untouched:
// the hint is worth less than the answer it would ride on.
func appendResultText(result any, text string) any {
	raw, ok := resultJSON(result)
	if !ok {
		return result
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return result
	}
	var content []json.RawMessage
	if existing, has := fields["content"]; has {
		if err := json.Unmarshal(existing, &content); err != nil {
			return result
		}
	}
	block, err := json.Marshal(map[string]string{"type": "text", "text": text})
	if err != nil {
		return result
	}
	encoded, err := json.Marshal(append(content, block))
	if err != nil {
		return result
	}
	fields["content"] = encoded
	out, err := json.Marshal(fields)
	if err != nil {
		return result
	}
	return json.RawMessage(out)
}

func resultJSON(result any) (json.RawMessage, bool) {
	switch typed := result.(type) {
	case nil:
		return nil, false
	case json.RawMessage:
		return typed, len(typed) > 0
	case []byte:
		return typed, len(typed) > 0
	default:
		raw, err := json.Marshal(typed)
		if err != nil {
			return nil, false
		}
		return raw, true
	}
}

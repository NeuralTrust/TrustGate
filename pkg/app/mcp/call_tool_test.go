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
	"strings"
	"testing"

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
)

func TestCallThroughTarget_ReadsTheCalledTool(t *testing.T) {
	t.Parallel()
	for label, tc := range map[string]struct {
		params   string
		wantName string
		wantArgs string
		wantOK   bool
	}{
		"call-through": {
			params:   `{"name":"trustgate_call_tool","arguments":{"name":"linear_save_issue","arguments":{"title":"x"}}}`,
			wantName: "linear_save_issue", wantArgs: `{"title":"x"}`, wantOK: true,
		},
		"string-encoded arguments": {
			params:   `{"name":"trustgate_call_tool","arguments":{"name":"linear_save_issue","arguments":"{\"title\":\"x\"}"}}`,
			wantName: "linear_save_issue", wantArgs: `{"title":"x"}`, wantOK: true,
		},
		"no arguments": {
			params:   `{"name":"trustgate_call_tool","arguments":{"name":" linear_whoami "}}`,
			wantName: "linear_whoami", wantOK: true,
		},
		"a direct call":                 {params: `{"name":"linear_save_issue","arguments":{"name":"x"}}`},
		"a call-through naming nothing": {params: `{"name":"trustgate_call_tool","arguments":{}}`},
		"arguments that are not an object": {
			params: `{"name":"trustgate_call_tool","arguments":{"name":"linear_save_issue","arguments":[1]}}`,
		},
		"not JSON": {params: `{`},
	} {
		got, args, ok := CallThroughTarget(json.RawMessage(tc.params))
		if ok != tc.wantOK || got != tc.wantName {
			t.Fatalf("%s: got (%q, %v), want (%q, %v)", label, got, ok, tc.wantName, tc.wantOK)
		}
		if tc.wantArgs == "" {
			if args != nil {
				t.Fatalf("%s: arguments = %s, want none", label, args)
			}
			continue
		}
		if string(args) != tc.wantArgs {
			t.Fatalf("%s: arguments = %s, want %s", label, args, tc.wantArgs)
		}
	}
}

// The call-through can reach every tool the user has, writes included, so a
// client that asks before a write must not read it as a safe one.
func TestCallToolDefinition_IsNotReadOnly(t *testing.T) {
	t.Parallel()
	def, err := callToolDefinition()
	if err != nil {
		t.Fatalf("definition: %v", err)
	}
	raw, err := json.Marshal(def)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var decoded struct {
		Name        string `json:"name"`
		InputSchema struct {
			Required []string `json:"required"`
		} `json:"inputSchema"`
		Annotations map[string]bool `json:"annotations"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Name != CallToolName {
		t.Fatalf("name = %q", decoded.Name)
	}
	if len(decoded.InputSchema.Required) != 1 || decoded.InputSchema.Required[0] != "name" {
		t.Fatalf("required = %v, want [name]", decoded.InputSchema.Required)
	}
	if decoded.Annotations["readOnlyHint"] || !decoded.Annotations["destructiveHint"] {
		t.Fatalf("annotations = %v, want a tool a client treats as a write", decoded.Annotations)
	}
}

func TestIsGatewayToolName(t *testing.T) {
	t.Parallel()
	for _, name := range []string{CallToolName, InventoryToolName, StoreInstallToolName, ConnectToolName("com.notion/mcp")} {
		if !isGatewayToolName(name) {
			t.Fatalf("%s is the gateway's own", name)
		}
	}
	for _, name := range []string{"linear_save_issue", "trustgate", "notion__trustgate_store_install"} {
		if isGatewayToolName(name) {
			t.Fatalf("%s is not the gateway's own", name)
		}
	}
}

// The listing leaves schemas out; asking for one tool is how a caller gets the
// schema a call-through needs.
func TestInventoryTool_DescribesOneToolWithItsSchema(t *testing.T) {
	t.Parallel()
	inventory := twoServerInventory()
	inventory.Servers[0].Tools[0].InputSchema = json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}`)
	tool, err := NewInventoryTool(&fakeSurfaceInventory{inventory: inventory}, nil)
	if err != nil {
		t.Fatalf("new inventory tool: %v", err)
	}

	result := callInventory(t, tool, `{"tool":"search_issues","server":"notion"}`)
	structured, _ := result["structuredContent"].(map[string]any)
	if structured["found"] != true || structured["tool"] != "search_issues" || structured["server"] != "linear" {
		t.Fatalf("structured = %v, want search_issues on linear (tool wins over server)", structured)
	}
	schema, _ := structured["input_schema"].(map[string]any)
	if schema["type"] != "object" || schema["required"] == nil {
		t.Fatalf("input_schema = %v, want the server's own", structured["input_schema"])
	}
	if structured["call_with"] != CallToolName {
		t.Fatalf("call_with = %v", structured["call_with"])
	}
	text := resultText(t, result)
	for _, want := range []string{"Search Linear issues", `"required":["query"]`, CallToolName} {
		if !strings.Contains(text, want) {
			t.Fatalf("text %q does not carry %q", text, want)
		}
	}
}

// A tool the server did not advertise a schema for is still callable: it gets
// the schema of a tool that takes an object.
func TestInventoryTool_DescribesAToolWithoutASchema(t *testing.T) {
	t.Parallel()
	tool, err := NewInventoryTool(&fakeSurfaceInventory{inventory: twoServerInventory()}, nil)
	if err != nil {
		t.Fatalf("new inventory tool: %v", err)
	}
	structured, _ := callInventory(t, tool, `{"tool":"create_issue"}`)["structuredContent"].(map[string]any)
	schema, _ := structured["input_schema"].(map[string]any)
	if schema["type"] != "object" {
		t.Fatalf("input_schema = %v, want an object schema", structured["input_schema"])
	}
}

func TestInventoryTool_DescribingAToolNobodyServesSaysSo(t *testing.T) {
	t.Parallel()
	tool, err := NewInventoryTool(&fakeSurfaceInventory{inventory: twoServerInventory()}, nil)
	if err != nil {
		t.Fatalf("new inventory tool: %v", err)
	}
	result := callInventory(t, tool, `{"tool":"query_database"}`)
	structured, _ := result["structuredContent"].(map[string]any)
	if structured["found"] != false {
		t.Fatalf("structured = %v, want found=false", structured)
	}
	if text := resultText(t, result); !strings.Contains(text, InventoryToolName) {
		t.Fatalf("text %q does not say how to find the right name", text)
	}
}

// The schema comes from the server itself, through the same discovery tools/list
// uses, so a call-through is written against what the server will accept.
func TestComposer_ToolInventory_CarriesTheToolsInputSchema(t *testing.T) {
	t.Parallel()
	reg := mcpRegistry(t, "linear", "https://linear.example.com/mcp")
	const schema = `{"type":"object","properties":{"q":{"type":"string"}},"required":["q"]}`
	var search Tool
	if err := json.Unmarshal([]byte(`{"name":"search","inputSchema":`+schema+`}`), &search); err != nil {
		t.Fatalf("decode tool: %v", err)
	}
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://linear.example.com/mcp": {tools: []Tool{search}},
	}}
	c := newTestComposer(dialer)
	inv, err := c.ToolInventory(context.Background(), routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, reg))
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	server := inventoryByName(inv, "linear")
	if server == nil || len(server.Tools) != 1 {
		t.Fatalf("linear = %+v, want its one tool", server)
	}
	if got := string(server.Tools[0].InputSchema); got != schema {
		t.Fatalf("input schema = %s, want %s", got, schema)
	}
}

func schemaTool(t *testing.T, schema string) Tool {
	t.Helper()
	var tool Tool
	raw := `{"name":"save_issue"}`
	if schema != "" {
		raw = `{"name":"save_issue","inputSchema":` + schema + `}`
	}
	if err := json.Unmarshal([]byte(raw), &tool); err != nil {
		t.Fatalf("decode tool: %v", err)
	}
	return tool
}

const issueSchema = `{"type":"object","properties":{"title":{"type":"string"}},"required":["title"]}`

// The upstream refusing the arguments is the one failure the schema fixes, so
// it rides on that refusal — still a protocol error, so telemetry records it.
func TestWithSchemaOnFailure_PutsTheSchemaOnARefusalOfTheArguments(t *testing.T) {
	t.Parallel()
	reached := toolInvocation{target: &ResolvedTool{Tool: schemaTool(t, issueSchema)}, upstream: true}
	refusal := &RPCError{Code: codeInvalidParams, Message: "title is required", Data: json.RawMessage(`{"field":"title"}`)}

	result, err := withSchemaOnFailure("linear_save_issue", reached, nil, refusal)
	if result != nil {
		t.Fatalf("result = %v, want the refusal alone", result)
	}
	var rpcErr *RPCError
	if !errors.As(err, &rpcErr) || rpcErr.Code != codeInvalidParams {
		t.Fatalf("err = %v, want the -32602 kept", err)
	}
	for _, want := range []string{"title is required", issueSchema, CallToolName} {
		if !strings.Contains(rpcErr.Message, want) {
			t.Fatalf("message %q does not carry %q", rpcErr.Message, want)
		}
	}
	if string(rpcErr.Data) != `{"field":"title"}` {
		t.Fatalf("data = %s, want the upstream's own", rpcErr.Data)
	}
	if refusal.Message != "title is required" {
		t.Fatalf("the upstream's error was changed in place: %q", refusal.Message)
	}
}

// A server on the newer SDK answers bad arguments as a tool error; the schema
// is added as one more text block and nothing else in the result moves.
func TestWithSchemaOnFailure_AddsTheSchemaToAToolError(t *testing.T) {
	t.Parallel()
	reached := toolInvocation{target: &ResolvedTool{Tool: schemaTool(t, issueSchema)}, upstream: true}
	failed := json.RawMessage(`{"content":[{"type":"text","text":"Invalid arguments"}],"isError":true,"_meta":{"k":"v"}}`)

	result, err := withSchemaOnFailure("linear_save_issue", reached, failed, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	var decoded struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool              `json:"isError"`
		Meta    map[string]string `json:"_meta"`
	}
	if err := json.Unmarshal(result.(json.RawMessage), &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !decoded.IsError || decoded.Meta["k"] != "v" || len(decoded.Content) != 2 {
		t.Fatalf("result = %s, want the original plus one block", result)
	}
	if decoded.Content[0].Text != "Invalid arguments" || !strings.Contains(decoded.Content[1].Text, issueSchema) {
		t.Fatalf("content = %+v", decoded.Content)
	}
}

func TestWithSchemaOnFailure_LeavesEverythingElseAlone(t *testing.T) {
	t.Parallel()
	withSchema := &ResolvedTool{Tool: schemaTool(t, issueSchema)}
	ok := json.RawMessage(`{"content":[{"type":"text","text":"done"}]}`)
	failed := json.RawMessage(`{"content":[{"type":"text","text":"no"}],"isError":true}`)
	denied := &RPCError{Code: CodePolicyBlocked, Message: "blocked"}
	refused := &RPCError{Code: codeInvalidParams, Message: "bad"}

	for name, tc := range map[string]struct {
		reached toolInvocation
		result  any
		err     error
	}{
		"a success":                     {reached: toolInvocation{target: withSchema, upstream: true}, result: ok},
		"another protocol error":        {reached: toolInvocation{target: withSchema, upstream: true}, err: denied},
		"a stage answered for the tool": {reached: toolInvocation{target: withSchema}, result: failed},
		"a stage refused the call":      {reached: toolInvocation{target: withSchema}, err: refused},
		"a tool with no schema":         {reached: toolInvocation{target: &ResolvedTool{Tool: schemaTool(t, "")}, upstream: true}, result: failed},
		"nothing was resolved":          {reached: toolInvocation{}, err: ErrToolNotFound},
	} {
		result, err := withSchemaOnFailure("linear_save_issue", tc.reached, tc.result, tc.err)
		if err != tc.err {
			t.Fatalf("%s: err = %v, want %v untouched", name, err, tc.err)
		}
		if tc.result == nil {
			if result != nil {
				t.Fatalf("%s: result = %v, want none", name, result)
			}
			continue
		}
		if string(result.(json.RawMessage)) != string(tc.result.(json.RawMessage)) {
			t.Fatalf("%s: result = %s, want it untouched", name, result)
		}
	}
}

// The call at the start of a conversation reads names, not every description
// on every server.
func TestInventoryTool_BriefListsNamesOnly(t *testing.T) {
	t.Parallel()
	tool, err := NewInventoryTool(&fakeSurfaceInventory{inventory: twoServerInventory()}, nil)
	if err != nil {
		t.Fatalf("new inventory tool: %v", err)
	}
	result := callInventory(t, tool, `{"brief":true}`)
	servers := structuredServers(t, result)
	if len(servers) != 2 {
		t.Fatalf("servers = %d, want both", len(servers))
	}
	if got := previewNames(t, servers[0]); len(got) != 2 || got[0] != "search_issues" {
		t.Fatalf("tools = %v, want the names", got)
	}
	for _, entry := range servers[0]["tools"].([]any) {
		listed := entry.(map[string]any)
		if _, has := listed["description"]; has {
			t.Fatalf("brief entry %v carries a description", listed)
		}
		if listed["callable"] != true {
			t.Fatalf("brief entry %v lost whether it can be called", listed)
		}
	}
	structured, _ := result["structuredContent"].(map[string]any)
	if structured["brief"] != true {
		t.Fatalf("structured = %v, want brief marked", structured)
	}
	text := resultText(t, result)
	if strings.Contains(text, "Search Linear issues") || !strings.Contains(text, "`tool`") {
		t.Fatalf("text %q, want names and where the descriptions are", text)
	}

	full := structuredServers(t, callInventory(t, tool, ""))
	if first := full[0]["tools"].([]any)[0].(map[string]any); first["description"] != "Search Linear issues" {
		t.Fatalf("the full listing lost its descriptions: %v", first)
	}
}

//go:build functional

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

package functional_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
)

// itemsUpstream serves list_items and get_item, annotated read-only,
// delete_item, annotated destructive, and audit_log, not annotated. It counts
// the deletes it was asked for.
func itemsUpstream(t *testing.T, deletes *atomic.Int32) string {
	t.Helper()
	destructive := true
	srv := startMCPUpstream(t, func(s *sdk.Server) {
		s.AddTool(&sdk.Tool{Name: "list_items", InputSchema: json.RawMessage(`{"type":"object"}`), Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
			func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
				return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: `{"items":[{"id":1},{"id":2},{"id":3}]}`}}}, nil
			})
		s.AddTool(&sdk.Tool{Name: "get_item", InputSchema: json.RawMessage(`{"type":"object","properties":{"id":{"type":"number"}}}`), Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
			func(_ context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
				var args struct {
					ID int `json:"id"`
				}
				_ = json.Unmarshal(req.Params.Arguments, &args)
				return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{
					Text: `{"id":` + strconv.Itoa(args.ID) + `,"done":` + strconv.FormatBool(args.ID%2 == 0) + `}`,
				}}}, nil
			})
		s.AddTool(&sdk.Tool{Name: "delete_item", InputSchema: json.RawMessage(`{"type":"object"}`), Annotations: &sdk.ToolAnnotations{DestructiveHint: &destructive}},
			func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
				deletes.Add(1)
				return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "deleted"}}}, nil
			})
		addTool(s, "audit_log")
	})
	return srv.URL
}

func listsTool(t *testing.T, gatewayID, consumerID, key, name string) bool {
	t.Helper()
	status, body := mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "tools/list", nil)
	for _, listed := range listedNames(t, rpcResult(t, status, body), "tools") {
		if listed == name {
			return true
		}
	}
	return false
}

func runProgram(t *testing.T, gatewayID, consumerID, key, code string) map[string]any {
	t.Helper()
	status, body := mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "tools/call",
		map[string]any{"name": appmcp.QueryToolName, "arguments": map[string]any{"code": code}})
	return rpcResult(t, status, body)
}

// An admin turns Code Mode on for a gateway; its MCP clients then get
// trustgate_query, whose programs call the user's read-only tools through the
// gateway, and only those.
func TestMCPCodeMode_QueryRunsProgramsOverReadOnlyTools(t *testing.T) {
	var deletes atomic.Int32
	url := itemsUpstream(t, &deletes)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-code")})
	registryID := CreateRegistry(t, gatewayID, mcpRegistryPayload(uniqueName("items"), url))
	consumerID, key := createMCPConsumer(t, gatewayID, []string{registryID}, nil, "")

	require.False(t, listsTool(t, gatewayID, consumerID, key, appmcp.QueryToolName), "Code Mode is off by default")
	off := runProgram(t, gatewayID, consumerID, key, `return 1;`)
	require.Equal(t, true, off["isError"])
	require.Equal(t, "not_enabled", off["structuredContent"].(map[string]any)["error"])

	status, gw := sendRequest(t, http.MethodPut, fmt.Sprintf("%s/v1/gateways/%s", AdminURL, gatewayID), nil,
		map[string]any{"mcp_code_mode": "read_only"})
	require.Equal(t, http.StatusOK, status, "update: %v", gw)
	require.Equal(t, "read_only", gw["mcp_code_mode"])
	status, gw = sendRequest(t, http.MethodPut, fmt.Sprintf("%s/v1/gateways/%s", AdminURL, gatewayID), nil,
		map[string]any{"mcp_code_mode": "everything"})
	require.Equal(t, http.StatusUnprocessableEntity, status, "an unknown mode is refused: %v", gw)

	require.Eventually(t, func() bool { return listsTool(t, gatewayID, consumerID, key, appmcp.QueryToolName) },
		15*time.Second, 200*time.Millisecond, "the gateway's MCP plane sees the change")
	require.False(t, listsTool(t, gatewayID, consumerID, key, appmcp.ExecuteToolName), "read_only does not offer trustgate_execute")

	list, get, del, audit := exposedToolName(registryID, "list_items"), exposedToolName(registryID, "get_item"),
		exposedToolName(registryID, "delete_item"), exposedToolName(registryID, "audit_log")
	result := runProgram(t, gatewayID, consumerID, key, `
		const { items } = await tools.`+list+`({});
		const details = await Promise.all(items.map(i => tools.`+get+`({ id: i.id })));
		const refused = {};
		for (const name of ["`+del+`", "`+audit+`"]) {
			try { await tools[name]({}); refused[name] = "called"; } catch (e) { refused[name] = e.name; }
		}
		return { done: details.filter(d => d.done).map(d => d.id), refused };
	`)
	require.NotEqual(t, true, result["isError"], "program failed: %v", result)
	structured := result["structuredContent"].(map[string]any)
	require.Equal(t, map[string]any{
		"done":    []any{float64(2)},
		"refused": map[string]any{del: "NotAllowedError", audit: "NotAllowedError"},
	}, structured["result"])
	require.Len(t, structured["calls"], 6)
	require.Zero(t, deletes.Load(), "a read-only program never reaches a tool that deletes")

	// The admin vouches for audit_log, which its server does not annotate.
	status, reg := sendRequest(t, http.MethodPut, fmt.Sprintf("%s/v1/gateways/%s/registries/%s", AdminURL, gatewayID, registryID), nil,
		map[string]any{"mcp_target": map[string]any{"read_only_tools": []string{"audit_log"}}})
	require.Equal(t, http.StatusOK, status, "registry update: %v", reg)
	require.Equal(t, []any{"audit_log"}, reg["mcp_target"].(map[string]any)["read_only_tools"])
	require.Eventually(t, func() bool {
		r := runProgram(t, gatewayID, consumerID, key, `return await tools.`+audit+`({ message: "x" });`)
		return r["isError"] != true
	}, 15*time.Second, 200*time.Millisecond, "a tool the admin lists is callable from a read-only program")
}

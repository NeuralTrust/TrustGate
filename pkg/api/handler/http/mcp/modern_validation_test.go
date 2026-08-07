package mcp

import (
	"encoding/json"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

func modernRPCRequest(t *testing.T, method string, params map[string]any) rpcRequest {
	t.Helper()
	params["_meta"] = map[string]any{
		"io.modelcontextprotocol/protocolVersion":    modernProtocolVersion,
		"io.modelcontextprotocol/clientCapabilities": map[string]any{},
	}
	raw, err := json.Marshal(params)
	require.NoError(t, err)
	return rpcRequest{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: method, Params: raw}
}

func TestValidateModernRequest(t *testing.T) {
	t.Parallel()
	validCall := modernRPCRequest(t, "tools/call", map[string]any{"name": "search"})
	validHeaders := modernRequestHeaders{protocolVersion: modernProtocolVersion, method: "tools/call", name: "search"}
	booleanID := validCall
	booleanID.ID = json.RawMessage(`true`)
	objectID := validCall
	objectID.ID = json.RawMessage(`{}`)
	arrayID := validCall
	arrayID.ID = json.RawMessage(`[]`)
	cases := []struct {
		name     string
		req      rpcRequest
		headers  modernRequestHeaders
		wantCode int
	}{
		{name: "valid tool call", req: validCall, headers: validHeaders},
		{name: "valid null ID", req: rpcRequest{JSONRPC: validCall.JSONRPC, ID: json.RawMessage(`null`), Method: validCall.Method, Params: validCall.Params}, headers: validHeaders},
		{name: "valid string ID", req: rpcRequest{JSONRPC: validCall.JSONRPC, ID: json.RawMessage(`"request"`), Method: validCall.Method, Params: validCall.Params}, headers: validHeaders},
		{name: "invalid boolean ID", req: booleanID, headers: validHeaders, wantCode: codeInvalidRequest},
		{name: "invalid object ID", req: objectID, headers: validHeaders, wantCode: codeInvalidRequest},
		{name: "invalid array ID", req: arrayID, headers: validHeaders, wantCode: codeInvalidRequest},
		{
			name:    "valid encoded UTF-8 name",
			req:     modernRPCRequest(t, "prompts/get", map[string]any{"name": "résumé"}),
			headers: modernRequestHeaders{protocolVersion: modernProtocolVersion, method: "prompts/get", name: "=?base64?csOpc3Vtw6k=?="},
		},
		{
			name:    "valid resource URI",
			req:     modernRPCRequest(t, "resources/read", map[string]any{"uri": "file:///tmp/a"}),
			headers: modernRequestHeaders{protocolVersion: modernProtocolVersion, method: "resources/read", name: "file:///tmp/a"},
		},
		{
			name:    "valid encoded sentinel literal",
			req:     modernRPCRequest(t, "tools/call", map[string]any{"name": "=?base64?literal?="}),
			headers: modernRequestHeaders{protocolVersion: modernProtocolVersion, method: "tools/call", name: "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?="},
		},
		{
			name:    "plain suffix is not a sentinel",
			req:     modernRPCRequest(t, "tools/call", map[string]any{"name": "plain?="}),
			headers: modernRequestHeaders{protocolVersion: modernProtocolVersion, method: "tools/call", name: "plain?="},
		},
		{
			name:    "valid list",
			req:     modernRPCRequest(t, "tools/list", map[string]any{}),
			headers: modernRequestHeaders{protocolVersion: modernProtocolVersion, method: "tools/list"},
		},
		{name: "invalid JSON-RPC", req: rpcRequest{JSONRPC: "1.0", Method: "tools/list"}, headers: validHeaders, wantCode: codeInvalidRequest},
		{name: "params must be object", req: rpcRequest{JSONRPC: "2.0", Method: "tools/list", Params: json.RawMessage(`[]`)}, headers: validHeaders, wantCode: codeInvalidParams},
		{
			name:     "metadata missing from modern signal",
			req:      rpcRequest{JSONRPC: "2.0", Method: "tools/list", Params: json.RawMessage(`{}`)},
			headers:  modernRequestHeaders{protocolVersion: modernProtocolVersion, method: "tools/list"},
			wantCode: codeHeaderMismatch,
		},
		{name: "metadata must be object", req: rpcRequest{JSONRPC: "2.0", Method: "tools/list", Params: json.RawMessage(`{"_meta":[]}`)}, headers: validHeaders, wantCode: codeInvalidParams},
		{
			name:     "protocol metadata missing",
			req:      rpcRequest{JSONRPC: "2.0", Method: "tools/list", Params: json.RawMessage(`{"_meta":{"io.modelcontextprotocol/clientCapabilities":{}}}`)},
			headers:  modernRequestHeaders{protocolVersion: modernProtocolVersion, method: "tools/list"},
			wantCode: codeHeaderMismatch,
		},
		{
			name:     "protocol metadata empty",
			req:      rpcRequest{JSONRPC: "2.0", Method: "tools/list", Params: json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":"","io.modelcontextprotocol/clientCapabilities":{}}}`)},
			headers:  modernRequestHeaders{protocolVersion: modernProtocolVersion, method: "tools/list"},
			wantCode: codeInvalidParams,
		},
		{
			name:     "protocol metadata unsupported",
			req:      rpcRequest{JSONRPC: "2.0", Method: "tools/list", Params: json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01","io.modelcontextprotocol/clientCapabilities":{}}}`)},
			headers:  modernRequestHeaders{protocolVersion: "2099-01-01", method: "tools/list"},
			wantCode: codeUnsupportedProtocolVersion,
		},
		{
			name:     "capabilities must be object",
			req:      rpcRequest{JSONRPC: "2.0", Method: "tools/list", Params: json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":[]}}`)},
			headers:  modernRequestHeaders{protocolVersion: modernProtocolVersion, method: "tools/list"},
			wantCode: codeInvalidParams,
		},
		{name: "protocol header missing", req: validCall, headers: modernRequestHeaders{method: "tools/call", name: "search"}, wantCode: codeHeaderMismatch},
		{name: "protocol mismatch", req: validCall, headers: modernRequestHeaders{protocolVersion: "2025-06-18", method: "tools/call", name: "search"}, wantCode: codeHeaderMismatch},
		{name: "method missing", req: validCall, headers: modernRequestHeaders{protocolVersion: modernProtocolVersion, name: "search"}, wantCode: codeHeaderMismatch},
		{name: "method mismatch", req: validCall, headers: modernRequestHeaders{protocolVersion: modernProtocolVersion, method: "tools/list", name: "search"}, wantCode: codeHeaderMismatch},
		{name: "name missing", req: validCall, headers: modernRequestHeaders{protocolVersion: modernProtocolVersion, method: "tools/call"}, wantCode: codeHeaderMismatch},
		{name: "name mismatch", req: validCall, headers: modernRequestHeaders{protocolVersion: modernProtocolVersion, method: "tools/call", name: "other"}, wantCode: codeHeaderMismatch},
		{name: "malformed sentinel", req: validCall, headers: modernRequestHeaders{protocolVersion: modernProtocolVersion, method: "tools/call", name: "=?base64?%%%?="}, wantCode: codeHeaderMismatch},
		{name: "non UTF-8 sentinel", req: validCall, headers: modernRequestHeaders{protocolVersion: modernProtocolVersion, method: "tools/call", name: "=?base64?/w==?="}, wantCode: codeHeaderMismatch},
		{name: "custom tool header", req: validCall, headers: modernRequestHeaders{protocolVersion: modernProtocolVersion, method: "tools/call", name: "search", hasToolParam: true}, wantCode: codeHeaderMismatch},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			protocolErr := validateModernRequest(tc.req, tc.headers)
			if tc.wantCode == 0 {
				require.Nil(t, protocolErr)
				return
			}
			require.NotNil(t, protocolErr)
			require.Equal(t, tc.wantCode, protocolErr.code)
			require.Equal(t, fiber.StatusBadRequest, protocolErr.status)
		})
	}
}

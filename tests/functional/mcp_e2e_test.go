//go:build functional

package functional_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

// --- harness -------------------------------------------------------------

// startMCPUpstream runs a real MCP server (streamable HTTP) inside the test
// process; the gateway process reaches it through the loopback interface.
func startMCPUpstream(t *testing.T, configure func(*sdk.Server)) *httptest.Server {
	t.Helper()
	server := sdk.NewServer(&sdk.Implementation{Name: "fake-upstream", Version: "1.0"}, nil)
	if configure != nil {
		configure(server)
	}
	srv := httptest.NewServer(sdk.NewStreamableHTTPHandler(
		func(*http.Request) *sdk.Server { return server }, nil))
	t.Cleanup(srv.Close)
	return srv
}

func addTool(server *sdk.Server, name string) {
	server.AddTool(
		&sdk.Tool{Name: name, InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(_ context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			var args struct {
				Message string `json:"message"`
			}
			_ = json.Unmarshal(req.Params.Arguments, &args)
			return &sdk.CallToolResult{
				Content: []sdk.Content{&sdk.TextContent{Text: name + ":" + args.Message}},
			}, nil
		},
	)
}

func addGreetPrompt(server *sdk.Server) {
	server.AddPrompt(
		&sdk.Prompt{Name: "greet", Description: "say hi"},
		func(_ context.Context, req *sdk.GetPromptRequest) (*sdk.GetPromptResult, error) {
			return &sdk.GetPromptResult{Messages: []*sdk.PromptMessage{
				{Role: "user", Content: &sdk.TextContent{Text: "hi " + req.Params.Arguments["name"]}},
			}}, nil
		},
	)
}

func addReadmeResource(server *sdk.Server, uri, text string) {
	server.AddResource(
		&sdk.Resource{URI: uri, Name: uri, MIMEType: "text/plain"},
		func(context.Context, *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
			return &sdk.ReadResourceResult{Contents: []*sdk.ResourceContents{
				{URI: uri, MIMEType: "text/plain", Text: text},
			}}, nil
		},
	)
}

// mcpPost posts a raw JSON body to the virtual MCP server. Unlike sendRequest
// it never injects the admin bearer token (the MCP plane authenticates the
// consumer credential, not the admin) and it pins the Host header to the
// gateway domain so the path-first auth scope resolves.
func mcpPost(t *testing.T, gatewayID, consumerID string, headers map[string]string, body any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	url := MCPURL + "/" + ConsumerSlug(t, consumerID) + "/mcp"
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(raw)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	host, ok := gatewayHosts.Load(gatewayID)
	require.True(t, ok, "gateway host missing for %s", gatewayID)
	req.Host = host.(string)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	decoded, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	if len(decoded) > 0 {
		if jerr := json.Unmarshal(decoded, &out); jerr != nil {
			out = map[string]any{"_raw": string(decoded)}
		}
	}
	return resp.StatusCode, out
}

// mcpRPC posts a JSON-RPC request to the virtual MCP server and returns the
// HTTP status plus the decoded response body (empty map for empty bodies).
func mcpRPC(t *testing.T, gatewayID, consumerID string, headers map[string]string, method string, params any) (int, map[string]any) {
	t.Helper()
	body := map[string]any{"jsonrpc": "2.0", "id": 1, "method": method}
	if params != nil {
		body["params"] = params
	}
	return mcpPost(t, gatewayID, consumerID, headers, body)
}

func apiKeyHeaders(key string) map[string]string {
	return map[string]string{"X-AG-API-Key": key}
}

func bearerHeaders(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func rpcResult(t *testing.T, status int, body map[string]any) map[string]any {
	t.Helper()
	require.Equal(t, http.StatusOK, status, "rpc failed: %v", body)
	require.Nil(t, body["error"], "rpc error: %v", body["error"])
	result, ok := body["result"].(map[string]any)
	require.True(t, ok, "rpc result missing: %v", body)
	return result
}

func rpcErrorCode(t *testing.T, status int, body map[string]any) float64 {
	t.Helper()
	rpcErr, ok := body["error"].(map[string]any)
	require.True(t, ok, "expected rpc error (http %d), got: %v", status, body)
	code, ok := rpcErr["code"].(float64)
	require.True(t, ok, "rpc error missing code: %v", rpcErr)
	return code
}

func listedNames(t *testing.T, result map[string]any, key string) []string {
	t.Helper()
	items, ok := result[key].([]any)
	require.True(t, ok, "result missing %s: %v", key, result)
	names := make([]string, 0, len(items))
	for _, item := range items {
		entry, ok := item.(map[string]any)
		require.True(t, ok)
		name, _ := entry["name"].(string)
		names = append(names, name)
	}
	return names
}

func mcpRegistryPayload(name, url string) map[string]any {
	return map[string]any{
		"name":       name,
		"type":       "mcp",
		"weight":     1,
		"mcp_target": map[string]any{"url": url},
	}
}

// createMCPConsumer creates an inline MCP consumer bound to the given
// registries with an optional toolkit/fail_mode, attaches a fresh API key and
// returns (consumerID, apiKey).
func createMCPConsumer(t *testing.T, gatewayID string, registryIDs []string, toolkit []map[string]any, failMode string) (string, string) {
	t.Helper()
	payload := map[string]any{
		"name": uniqueName("mcp-consumer"),
		"type": "mcp",
	}
	bindings := make([]map[string]any, 0, len(registryIDs))
	for _, id := range registryIDs {
		bindings = append(bindings, map[string]any{"id": id})
	}
	payload["registries"] = bindings
	if toolkit != nil {
		payload["toolkit"] = toolkit
	}
	if failMode != "" {
		payload["fail_mode"] = failMode
	}
	consumerID := CreateConsumer(t, gatewayID, payload)
	authID, key := CreateAPIKeyAuth(t, gatewayID, uniqueName("mcp-key"))
	AttachAuth(t, gatewayID, consumerID, authID)
	return consumerID, key
}

// --- inline consumer use cases -------------------------------------------

func TestMCPServer_RejectsUnauthenticatedRequests(t *testing.T) {
	upstream := startMCPUpstream(t, func(s *sdk.Server) { addTool(s, "echo") })
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	registryID := CreateRegistry(t, gatewayID, mcpRegistryPayload(uniqueName("mcp-reg"), upstream.URL))
	consumerID, _ := createMCPConsumer(t, gatewayID, []string{registryID}, nil, "")

	status, _ := mcpRPC(t, gatewayID, consumerID, nil, "tools/list", nil)
	require.Equal(t, http.StatusUnauthorized, status)
}

func TestMCPServer_InitializePingAndNotification(t *testing.T) {
	upstream := startMCPUpstream(t, func(s *sdk.Server) { addTool(s, "echo") })
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	registryID := CreateRegistry(t, gatewayID, mcpRegistryPayload(uniqueName("mcp-reg"), upstream.URL))
	consumerID, key := createMCPConsumer(t, gatewayID, []string{registryID}, nil, "")

	status, body := mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "initialize",
		map[string]any{"protocolVersion": "2025-03-26"})
	result := rpcResult(t, status, body)
	require.Equal(t, "2025-03-26", result["protocolVersion"])

	status, body = mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "ping", nil)
	require.Equal(t, http.StatusOK, status, "ping failed: %v", body)

	status, _ = mcpPost(t, gatewayID, consumerID, apiKeyHeaders(key),
		map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	require.Equal(t, http.StatusAccepted, status)

	url := MCPURL + "/" + ConsumerSlug(t, consumerID) + "/mcp"
	status, _ = sendRequest(t, http.MethodGet, url, apiKeyHeaders(key), nil)
	require.Equal(t, http.StatusMethodNotAllowed, status)
}

func TestMCPServer_ToolsListAndCallWithFullAccess(t *testing.T) {
	upstream := startMCPUpstream(t, func(s *sdk.Server) {
		addTool(s, "echo")
		addTool(s, "search")
	})
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	registryID := CreateRegistry(t, gatewayID, mcpRegistryPayload(uniqueName("mcp-reg"), upstream.URL))
	consumerID, key := createMCPConsumer(t, gatewayID, []string{registryID}, nil, "")

	status, body := mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "tools/list", nil)
	names := listedNames(t, rpcResult(t, status, body), "tools")
	require.ElementsMatch(t, []string{"echo", "search"}, names)

	status, body = mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "tools/call",
		map[string]any{"name": "echo", "arguments": map[string]any{"message": "hola"}})
	result := rpcResult(t, status, body)
	raw, err := json.Marshal(result)
	require.NoError(t, err)
	require.Contains(t, string(raw), "echo:hola")
}

func TestMCPServer_ListsPendingProviderConnectTools(t *testing.T) {
	live := startMCPUpstream(t, func(s *sdk.Server) { addTool(s, "echo") })
	pending := startMCPUpstream(t, func(s *sdk.Server) { addTool(s, "list_issues") })
	idp := newOAuthProviderStub(t)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	liveID := CreateRegistry(t, gatewayID, mcpRegistryPayload(uniqueName("mcp-live"), live.URL))
	pendingID := CreateRegistry(t, gatewayID, mcpForwardedRegistryPayload(
		uniqueName("mcp-linear"), pending.URL, "linear", idp))
	consumerID, key := createMCPConsumer(t, gatewayID, []string{liveID, pendingID}, nil, "")

	status, body := mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "tools/list", nil)
	names := listedNames(t, rpcResult(t, status, body), "tools")
	require.Contains(t, names, "echo")
	require.Contains(t, names, appmcp.ConnectToolName("linear"))
	require.NotContains(t, names, "list_issues")

	status, body = mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "tools/call",
		map[string]any{"name": appmcp.ConnectToolName("linear"), "arguments": map[string]any{}})
	connections := rpcResult(t, status, body)["structuredContent"].(map[string]any)
	require.Equal(t, "user_confirmation_required", connections["action"])
	require.Contains(t, connections["connect_url"], "/mcp/connect?ticket=")
	require.Nil(t, body["error"])
}

func TestMCPServer_ToolkitFiltersAndAliasesTools(t *testing.T) {
	upstream := startMCPUpstream(t, func(s *sdk.Server) {
		addTool(s, "echo")
		addTool(s, "secret")
	})
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	registryID := CreateRegistry(t, gatewayID, mcpRegistryPayload(uniqueName("mcp-reg"), upstream.URL))
	consumerID, key := createMCPConsumer(t, gatewayID, []string{registryID},
		[]map[string]any{{"registry_id": registryID, "tool": "echo", "expose_as": "alias-echo"}}, "")

	status, body := mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "tools/list", nil)
	names := listedNames(t, rpcResult(t, status, body), "tools")
	require.Equal(t, []string{"alias-echo"}, names)

	status, body = mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "tools/call",
		map[string]any{"name": "alias-echo", "arguments": map[string]any{"message": "hola"}})
	result := rpcResult(t, status, body)
	raw, err := json.Marshal(result)
	require.NoError(t, err)
	require.Contains(t, string(raw), "echo:hola")

	status, body = mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "tools/call",
		map[string]any{"name": "secret"})
	require.Equal(t, float64(-32001), rpcErrorCode(t, status, body))
}

func TestMCPServer_PromptsAndResources(t *testing.T) {
	upstream := startMCPUpstream(t, func(s *sdk.Server) {
		addTool(s, "echo")
		addGreetPrompt(s)
		addReadmeResource(s, "file:///docs/readme", "hello-docs")
		addReadmeResource(s, "file:///private/keys", "top-secret")
	})
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	registryID := CreateRegistry(t, gatewayID, mcpRegistryPayload(uniqueName("mcp-reg"), upstream.URL))
	consumerID, key := createMCPConsumer(t, gatewayID, []string{registryID},
		[]map[string]any{
			{"registry_id": registryID, "prompt": "*"},
			{"registry_id": registryID, "resource": "file:///docs/*"},
		}, "")

	status, body := mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "prompts/list", nil)
	names := listedNames(t, rpcResult(t, status, body), "prompts")
	require.Equal(t, []string{"greet"}, names)

	status, body = mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "prompts/get",
		map[string]any{"name": "greet", "arguments": map[string]any{"name": "ana"}})
	result := rpcResult(t, status, body)
	raw, err := json.Marshal(result)
	require.NoError(t, err)
	require.Contains(t, string(raw), "hi ana")

	status, body = mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "resources/list", nil)
	resources := rpcResult(t, status, body)["resources"].([]any)
	require.Len(t, resources, 1)
	uri := resources[0].(map[string]any)["uri"].(string)
	require.Equal(t, "file:///docs/readme", uri)

	status, body = mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "resources/read",
		map[string]any{"uri": "file:///docs/readme"})
	result = rpcResult(t, status, body)
	raw, err = json.Marshal(result)
	require.NoError(t, err)
	require.Contains(t, string(raw), "hello-docs")

	status, body = mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "resources/read",
		map[string]any{"uri": "file:///private/keys"})
	require.Equal(t, float64(-32002), rpcErrorCode(t, status, body))
}

func TestMCPServer_FailModeClosedRejectsWhenUpstreamIsDown(t *testing.T) {
	upstream := startMCPUpstream(t, func(s *sdk.Server) { addTool(s, "echo") })
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	liveRegistry := CreateRegistry(t, gatewayID, mcpRegistryPayload(uniqueName("mcp-live"), upstream.URL))
	deadRegistry := CreateRegistry(t, gatewayID, mcpRegistryPayload(uniqueName("mcp-dead"), "http://127.0.0.1:1/mcp"))
	consumerID, key := createMCPConsumer(t, gatewayID, []string{liveRegistry, deadRegistry}, nil, "closed")

	status, body := mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "tools/list", nil)
	require.Equal(t, float64(-32603), rpcErrorCode(t, status, body))
}

func TestMCPServer_FailModeOpenSkipsDeadUpstream(t *testing.T) {
	upstream := startMCPUpstream(t, func(s *sdk.Server) { addTool(s, "echo") })
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	liveRegistry := CreateRegistry(t, gatewayID, mcpRegistryPayload(uniqueName("mcp-live"), upstream.URL))
	deadRegistry := CreateRegistry(t, gatewayID, mcpRegistryPayload(uniqueName("mcp-dead"), "http://127.0.0.1:1/mcp"))
	consumerID, key := createMCPConsumer(t, gatewayID, []string{liveRegistry, deadRegistry}, nil, "open")

	status, body := mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "tools/list", nil)
	names := listedNames(t, rpcResult(t, status, body), "tools")
	require.Equal(t, []string{"echo"}, names)
}

func TestMCPServer_CredentialOfAnotherConsumerIsRejected(t *testing.T) {
	upstream := startMCPUpstream(t, func(s *sdk.Server) { addTool(s, "echo") })
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	registryID := CreateRegistry(t, gatewayID, mcpRegistryPayload(uniqueName("mcp-reg"), upstream.URL))
	victimID, _ := createMCPConsumer(t, gatewayID, []string{registryID}, nil, "")
	_, intruderKey := createMCPConsumer(t, gatewayID, []string{registryID}, nil, "")

	status, _ := mcpRPC(t, gatewayID, victimID, apiKeyHeaders(intruderKey), "tools/list", nil)
	require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, status)
}

func TestMCPServer_UnknownMethodAndMalformedBody(t *testing.T) {
	upstream := startMCPUpstream(t, func(s *sdk.Server) { addTool(s, "echo") })
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	registryID := CreateRegistry(t, gatewayID, mcpRegistryPayload(uniqueName("mcp-reg"), upstream.URL))
	consumerID, key := createMCPConsumer(t, gatewayID, []string{registryID}, nil, "")

	status, body := mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "tools/destroy", nil)
	require.Equal(t, float64(-32601), rpcErrorCode(t, status, body))

	status, body = mcpPost(t, gatewayID, consumerID, apiKeyHeaders(key),
		map[string]any{"jsonrpc": "1.0", "id": 1, "method": "tools/list"})
	require.Equal(t, float64(-32600), rpcErrorCode(t, status, body))
}

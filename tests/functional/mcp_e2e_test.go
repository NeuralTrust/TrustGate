//go:build functional

package functional_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

// --- harness -------------------------------------------------------------

// startMCPUpstream runs a real MCP server (streamable HTTP) inside the test
// process; the gateway process reaches it through the loopback interface.
// The handler is stateful, so it serves the legacy era only: the SDK withholds
// the 2026-07-28 protocol version unless the transport is stateless.
func startMCPUpstream(t *testing.T, configure func(*sdk.Server)) *httptest.Server {
	return startMCPUpstreamWithOptions(t, configure, nil)
}

// startModernMCPUpstream runs a stateless MCP server, the only mode in which the
// SDK advertises and serves the 2026-07-28 protocol.
func startModernMCPUpstream(t *testing.T, configure func(*sdk.Server)) *httptest.Server {
	return startMCPUpstreamWithOptions(t, configure, &sdk.StreamableHTTPOptions{Stateless: true})
}

func startMCPUpstreamWithOptions(
	t *testing.T,
	configure func(*sdk.Server),
	options *sdk.StreamableHTTPOptions,
) *httptest.Server {
	t.Helper()
	server := sdk.NewServer(&sdk.Implementation{Name: "fake-upstream", Version: "1.0"}, nil)
	if configure != nil {
		configure(server)
	}
	srv := httptest.NewServer(sdk.NewStreamableHTTPHandler(
		func(*http.Request) *sdk.Server { return server }, options))
	t.Cleanup(srv.Close)
	return srv
}

type eraMCPFixture struct {
	server      *httptest.Server
	initializes atomic.Int64
	rejected    atomic.Int64
}

func startEraMCPUpstream(t *testing.T, legacyOnly bool, toolName string) *eraMCPFixture {
	return startAuthenticatedEraMCPUpstream(t, legacyOnly, toolName, nil)
}

func startAuthenticatedEraMCPUpstream(
	t *testing.T,
	legacyOnly bool,
	toolName string,
	expectedHeaders map[string]string,
) *eraMCPFixture {
	t.Helper()
	server := sdk.NewServer(&sdk.Implementation{Name: "era-upstream", Version: "1.0"}, nil)
	addTool(server, toolName)
	var options *sdk.StreamableHTTPOptions
	if !legacyOnly {
		options = &sdk.StreamableHTTPOptions{Stateless: true}
	}
	sdkHandler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, options)
	fixture := &eraMCPFixture{}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for key, expected := range expectedHeaders {
			if r.Header.Get(key) != expected {
				fixture.rejected.Add(1)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if err := r.Body.Close(); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(strings.NewReader(string(raw)))
		var envelope struct {
			Method string `json:"method"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if legacyOnly && envelope.Method == "server/discover" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			if _, err := w.Write([]byte(`{`)); err != nil {
				return
			}
			return
		}
		if !legacyOnly && envelope.Method == "initialize" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			if _, err := w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"modern only"}}`)); err != nil {
				return
			}
			return
		}
		if envelope.Method == "initialize" {
			fixture.initializes.Add(1)
		}
		sdkHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
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
	status, _, out := mcpExchange(t, gatewayID, consumerID, headers, body)
	return status, out
}

func mcpExchange(
	t *testing.T,
	gatewayID, consumerID string,
	headers map[string]string,
	body any,
) (int, http.Header, map[string]any) {
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
	return resp.StatusCode, resp.Header.Clone(), out
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
	return mcpRegistryPayloadMode(name, url, "")
}

func mcpRegistryPayloadMode(name, url, protocolMode string) map[string]any {
	target := map[string]any{"url": url}
	if protocolMode != "" {
		target["protocol_mode"] = protocolMode
	}
	return map[string]any{
		"name":       name,
		"type":       "mcp",
		"weight":     1,
		"mcp_target": target,
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

// AttachRoleRegistry links a registry to a role via the association endpoint.
func AttachRoleRegistry(t *testing.T, gatewayID, roleID, registryID string) {
	t.Helper()
	url := fmt.Sprintf("%s/v1/gateways/%s/roles/%s/registries/%s",
		AdminURL, gatewayID, roleID, registryID)
	status, body := sendRequest(t, http.MethodPost, url, nil, nil)
	require.Equal(t, http.StatusNoContent, status, "attach role registry failed: %v", body)
}

// UpdateRole issues a PUT on the role, asserting the 200 contract.
func UpdateRole(t *testing.T, gatewayID, roleID string, payload map[string]any) {
	t.Helper()
	url := fmt.Sprintf("%s/v1/gateways/%s/roles/%s", AdminURL, gatewayID, roleID)
	status, body := sendRequest(t, http.MethodPut, url, nil, payload)
	require.Equal(t, http.StatusOK, status, "update role failed: %v", body)
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

func TestMCPServer_ProtocolModeMatrixPreservesTools(t *testing.T) {
	for _, mode := range []string{"auto", "modern", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			start := startMCPUpstream
			if mode == "modern" {
				start = startModernMCPUpstream
			}
			upstream := start(t, func(s *sdk.Server) { addTool(s, "echo-"+mode) })
			gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
			registryID := CreateRegistry(
				t,
				gatewayID,
				mcpRegistryPayloadMode(uniqueName("mcp-reg"), upstream.URL, mode),
			)
			consumerID, key := createMCPConsumer(t, gatewayID, []string{registryID}, nil, "")

			status, body := mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "tools/list", nil)
			names := listedNames(t, rpcResult(t, status, body), "tools")
			require.Equal(t, []string{"echo-" + mode}, names)

			status, body = mcpRPC(
				t,
				gatewayID,
				consumerID,
				apiKeyHeaders(key),
				"tools/call",
				map[string]any{"name": "echo-" + mode, "arguments": map[string]any{"message": mode}},
			)
			raw, err := json.Marshal(rpcResult(t, status, body))
			require.NoError(t, err)
			require.Contains(t, string(raw), "echo-"+mode+":"+mode)
		})
	}
}

func TestMCPServer_AutoNegotiatesEraSpecificUpstreams(t *testing.T) {
	tests := []struct {
		name            string
		legacyOnly      bool
		wantInitializes int64
	}{
		{name: "modern only"},
		{name: "legacy only", legacyOnly: true, wantInitializes: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			toolName := "echo-" + strings.ReplaceAll(tt.name, " ", "-")
			fixture := startEraMCPUpstream(t, tt.legacyOnly, toolName)
			gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
			registryID := CreateRegistry(
				t,
				gatewayID,
				mcpRegistryPayloadMode(uniqueName("mcp-reg"), fixture.server.URL, "auto"),
			)
			consumerID, key := createMCPConsumer(
				t,
				gatewayID,
				[]string{registryID},
				[]map[string]any{{"registry_id": registryID, "tool": toolName, "expose_as": "alias-era"}},
				"closed",
			)
			for range 2 {
				status, body := mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "tools/list", nil)
				require.Equal(t, []string{"alias-era"}, listedNames(t, rpcResult(t, status, body), "tools"))
			}
			require.Equal(t, tt.wantInitializes, fixture.initializes.Load())
		})
	}
}

func TestMCPServer_AutoNegotiationIsolatesSouthboundCredentials(t *testing.T) {
	const (
		modernAuthorization = "Bearer modern-southbound-secret"
		legacyAuthorization = "Bearer legacy-southbound-secret"
	)
	modern := startAuthenticatedEraMCPUpstream(t, false, "modern-authenticated", map[string]string{
		"Authorization": modernAuthorization,
		"X-Target-ID":   "modern-target",
	})
	legacy := startAuthenticatedEraMCPUpstream(t, true, "legacy-authenticated", map[string]string{
		"Authorization": legacyAuthorization,
		"X-Target-ID":   "legacy-target",
	})
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	createRegistry := func(name string, fixture *eraMCPFixture, authorization string, marker string) string {
		payload := mcpRegistryPayloadMode(name, fixture.server.URL, "auto")
		target := payload["mcp_target"].(map[string]any)
		target["headers"] = map[string]string{"X-Target-ID": marker}
		target["auth"] = map[string]any{
			"mode":   "static",
			"header": "Authorization",
			"value":  authorization,
		}
		return CreateRegistry(t, gatewayID, payload)
	}
	modernRegistry := createRegistry(uniqueName("mcp-modern"), modern, modernAuthorization, "modern-target")
	legacyRegistry := createRegistry(uniqueName("mcp-legacy"), legacy, legacyAuthorization, "legacy-target")
	consumerID, key := createMCPConsumer(
		t,
		gatewayID,
		[]string{modernRegistry, legacyRegistry},
		[]map[string]any{
			{"registry_id": modernRegistry, "tool": "modern-authenticated", "expose_as": "modern-tool"},
			{"registry_id": legacyRegistry, "tool": "legacy-authenticated", "expose_as": "legacy-tool"},
		},
		"closed",
	)

	status, body := mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "tools/list", nil)
	require.ElementsMatch(t, []string{"modern-tool", "legacy-tool"}, listedNames(t, rpcResult(t, status, body), "tools"))
	for _, tool := range []string{"modern-tool", "legacy-tool"} {
		status, body = mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "tools/call",
			map[string]any{"name": tool, "arguments": map[string]any{"message": "isolated"}})
		raw, err := json.Marshal(rpcResult(t, status, body))
		require.NoError(t, err)
		require.NotContains(t, string(raw), modernAuthorization)
		require.NotContains(t, string(raw), legacyAuthorization)
	}
	require.Zero(t, modern.rejected.Load())
	require.Zero(t, legacy.rejected.Load())
	require.Equal(t, int64(1), legacy.initializes.Load())
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

// --- role_based consumer use cases ----------------------------------------

type mcpIDPStub struct {
	key    *rsa.PrivateKey
	kid    string
	issuer string
	server *httptest.Server
}

func newMCPIDPStub(t *testing.T) *mcpIDPStub {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	s := &mcpIDPStub{key: key, kid: "kid-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": s.kid,
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	})
	s.server = httptest.NewServer(mux)
	s.issuer = s.server.URL
	t.Cleanup(s.server.Close)
	return s
}

func (s *mcpIDPStub) sign(t *testing.T, audience string, groups []string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": s.issuer,
		"sub": "user-1",
		"aud": audience,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	if groups != nil {
		claims["groups"] = groups
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.kid
	raw, err := token.SignedString(s.key)
	require.NoError(t, err)
	return raw
}

func TestMCPServer_RoleBasedConsumerAppliesRoleMCPPolicies(t *testing.T) {
	upstream := startMCPUpstream(t, func(s *sdk.Server) {
		addTool(s, "echo")
		addTool(s, "secret")
	})
	stub := newMCPIDPStub(t)
	audience := "mcp-" + strings.ToLower(uniqueName("aud"))

	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	registryID := CreateRegistry(t, gatewayID, mcpRegistryPayload(uniqueName("mcp-reg"), upstream.URL))

	roleID := CreateRole(t, gatewayID, map[string]any{
		"name": uniqueName("mcp-role"),
		"oidc_mapping": map[string]any{
			"match": "any",
			"claims": []map[string]any{
				{"path": "groups", "op": "contains_any", "values": []string{"mcp-users"}},
			},
		},
	})
	AttachRoleRegistry(t, gatewayID, roleID, registryID)
	UpdateRole(t, gatewayID, roleID, map[string]any{
		"mcp_policies": map[string]any{
			"toolkit":   []map[string]any{{"registry_id": registryID, "tool": "echo"}},
			"fail_mode": "closed",
		},
	})

	oauthAuthID := CreateAuth(t, gatewayID, map[string]any{
		"name":    uniqueName("mcp-oauth"),
		"type":    "oauth2",
		"enabled": true,
		"config": map[string]any{
			"oauth2": map[string]any{
				"issuer":    stub.issuer,
				"audiences": []string{audience},
				"jwks_url":  stub.server.URL + "/jwks",
			},
		},
	})

	consumerID := CreateConsumer(t, gatewayID, map[string]any{
		"name":         uniqueName("mcp-rb-consumer"),
		"type":         "mcp",
		"routing_mode": "role_based",
		"roles":        []string{roleID},
	})
	AttachAuth(t, gatewayID, consumerID, oauthAuthID)

	granted := stub.sign(t, audience, []string{"mcp-users"})
	status, body := mcpRPC(t, gatewayID, consumerID, bearerHeaders(granted), "tools/list", nil)
	names := listedNames(t, rpcResult(t, status, body), "tools")
	require.Equal(t, []string{"echo"}, names, "role toolkit must filter upstream tools")

	status, body = mcpRPC(t, gatewayID, consumerID, bearerHeaders(granted), "tools/call",
		map[string]any{"name": "echo", "arguments": map[string]any{"message": "hola"}})
	result := rpcResult(t, status, body)
	raw, err := json.Marshal(result)
	require.NoError(t, err)
	require.Contains(t, string(raw), "echo:hola")

	status, body = mcpRPC(t, gatewayID, consumerID, bearerHeaders(granted), "tools/call",
		map[string]any{"name": "secret"})
	require.Equal(t, float64(-32001), rpcErrorCode(t, status, body))
}

func TestMCPServer_RoleBasedConsumerEmptyToolkitDeniesAll(t *testing.T) {
	upstream := startMCPUpstream(t, func(s *sdk.Server) {
		addTool(s, "echo")
		addTool(s, "search")
	})
	stub := newMCPIDPStub(t)
	audience := "mcp-" + strings.ToLower(uniqueName("aud"))

	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	registryID := CreateRegistry(t, gatewayID, mcpRegistryPayload(uniqueName("mcp-reg"), upstream.URL))

	roleID := CreateRole(t, gatewayID, map[string]any{
		"name": uniqueName("mcp-role"),
		"oidc_mapping": map[string]any{
			"match": "any",
			"claims": []map[string]any{
				{"path": "groups", "op": "contains_any", "values": []string{"mcp-users"}},
			},
		},
	})
	AttachRoleRegistry(t, gatewayID, roleID, registryID)
	UpdateRole(t, gatewayID, roleID, map[string]any{
		"mcp_policies": map[string]any{
			"toolkit":   []map[string]any{},
			"fail_mode": "closed",
		},
	})

	oauthAuthID := CreateAuth(t, gatewayID, map[string]any{
		"name":    uniqueName("mcp-oauth"),
		"type":    "oauth2",
		"enabled": true,
		"config": map[string]any{
			"oauth2": map[string]any{
				"issuer":    stub.issuer,
				"audiences": []string{audience},
				"jwks_url":  stub.server.URL + "/jwks",
			},
		},
	})

	consumerID := CreateConsumer(t, gatewayID, map[string]any{
		"name":         uniqueName("mcp-rb-consumer"),
		"type":         "mcp",
		"routing_mode": "role_based",
		"roles":        []string{roleID},
	})
	AttachAuth(t, gatewayID, consumerID, oauthAuthID)

	granted := stub.sign(t, audience, []string{"mcp-users"})
	status, body := mcpRPC(t, gatewayID, consumerID, bearerHeaders(granted), "tools/list", nil)
	names := listedNames(t, rpcResult(t, status, body), "tools")
	require.Empty(t, names, "an explicit empty toolkit must deny every tool")
}

func TestMCPServer_RoleBasedConsumerRejectsIdentityWithoutMatchingRole(t *testing.T) {
	upstream := startMCPUpstream(t, func(s *sdk.Server) { addTool(s, "echo") })
	stub := newMCPIDPStub(t)
	audience := "mcp-" + strings.ToLower(uniqueName("aud"))

	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	registryID := CreateRegistry(t, gatewayID, mcpRegistryPayload(uniqueName("mcp-reg"), upstream.URL))

	roleID := CreateRole(t, gatewayID, map[string]any{
		"name": uniqueName("mcp-role"),
		"oidc_mapping": map[string]any{
			"match": "any",
			"claims": []map[string]any{
				{"path": "groups", "op": "contains_any", "values": []string{"mcp-users"}},
			},
		},
	})
	AttachRoleRegistry(t, gatewayID, roleID, registryID)

	oauthAuthID := CreateAuth(t, gatewayID, map[string]any{
		"name":    uniqueName("mcp-oauth"),
		"type":    "oauth2",
		"enabled": true,
		"config": map[string]any{
			"oauth2": map[string]any{
				"issuer":    stub.issuer,
				"audiences": []string{audience},
				"jwks_url":  stub.server.URL + "/jwks",
			},
		},
	})

	consumerID := CreateConsumer(t, gatewayID, map[string]any{
		"name":         uniqueName("mcp-rb-consumer"),
		"type":         "mcp",
		"routing_mode": "role_based",
		"roles":        []string{roleID},
	})
	AttachAuth(t, gatewayID, consumerID, oauthAuthID)

	denied := stub.sign(t, audience, []string{"other-team"})
	status, body := mcpRPC(t, gatewayID, consumerID, bearerHeaders(denied), "tools/list", nil)
	require.Equal(t, http.StatusForbidden, status, "identity without a matching role must be rejected: %v", body)

	// A role_based consumer is backed by a single identity-provider auth, so a
	// claimless API key cannot be attached in the first place: the association is
	// rejected before any request can reach the MCP process.
	apiKeyAuthID, _ := CreateAPIKeyAuth(t, gatewayID, uniqueName("mcp-key"))
	status, body = sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s/auths/%s", AdminURL, gatewayID, consumerID, apiKeyAuthID),
		nil, nil,
	)
	require.Equal(t, http.StatusConflict, status,
		"a role_based consumer must reject a non-IdP auth at attach time: %v", body)
}

func TestMCPServer_RoleBasedConsumerMergesMultipleRoles(t *testing.T) {
	upstreamA := startMCPUpstream(t, func(s *sdk.Server) { addTool(s, "alpha") })
	upstreamB := startMCPUpstream(t, func(s *sdk.Server) { addTool(s, "beta") })
	stub := newMCPIDPStub(t)
	audience := "mcp-" + strings.ToLower(uniqueName("aud"))

	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	registryA := CreateRegistry(t, gatewayID, mcpRegistryPayload(uniqueName("mcp-reg-a"), upstreamA.URL))
	registryB := CreateRegistry(t, gatewayID, mcpRegistryPayload(uniqueName("mcp-reg-b"), upstreamB.URL))

	mapping := map[string]any{
		"match": "any",
		"claims": []map[string]any{
			{"path": "groups", "op": "contains_any", "values": []string{"mcp-users"}},
		},
	}
	roleA := CreateRole(t, gatewayID, map[string]any{"name": uniqueName("role-a"), "oidc_mapping": mapping})
	AttachRoleRegistry(t, gatewayID, roleA, registryA)
	UpdateRole(t, gatewayID, roleA, map[string]any{
		"mcp_policies": map[string]any{
			"toolkit": []map[string]any{{"registry_id": registryA, "tool": "alpha"}},
		},
	})
	roleB := CreateRole(t, gatewayID, map[string]any{"name": uniqueName("role-b"), "oidc_mapping": mapping})
	AttachRoleRegistry(t, gatewayID, roleB, registryB)

	oauthAuthID := CreateAuth(t, gatewayID, map[string]any{
		"name":    uniqueName("mcp-oauth"),
		"type":    "oauth2",
		"enabled": true,
		"config": map[string]any{
			"oauth2": map[string]any{
				"issuer":    stub.issuer,
				"audiences": []string{audience},
				"jwks_url":  stub.server.URL + "/jwks",
			},
		},
	})

	consumerID := CreateConsumer(t, gatewayID, map[string]any{
		"name":         uniqueName("mcp-rb-consumer"),
		"type":         "mcp",
		"routing_mode": "role_based",
		"roles":        []string{roleA, roleB},
	})
	AttachAuth(t, gatewayID, consumerID, oauthAuthID)

	granted := stub.sign(t, audience, []string{"mcp-users"})
	status, body := mcpRPC(t, gatewayID, consumerID, bearerHeaders(granted), "tools/list", nil)
	names := listedNames(t, rpcResult(t, status, body), "tools")
	require.ElementsMatch(t, []string{"alpha", "beta"}, names,
		"explicit grant from role A plus full grant from role B must merge")
}

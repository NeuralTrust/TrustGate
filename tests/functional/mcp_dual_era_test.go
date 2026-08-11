//go:build functional

package functional_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

const modernProtocolVersion = "2026-07-28"

func modernMeta() map[string]any {
	return map[string]any{
		"io.modelcontextprotocol/protocolVersion":    modernProtocolVersion,
		"io.modelcontextprotocol/clientCapabilities": map[string]any{},
	}
}

func withModernMeta(params map[string]any) map[string]any {
	if params == nil {
		params = map[string]any{}
	}
	params["_meta"] = modernMeta()
	return params
}

func modernClientHeaders(apiKey, method, name string) map[string]string {
	headers := apiKeyHeaders(apiKey)
	headers["MCP-Protocol-Version"] = modernProtocolVersion
	headers["Mcp-Method"] = method
	if name != "" {
		headers["Mcp-Name"] = name
	}
	return headers
}

func mcpRPCModern(
	t *testing.T,
	gatewayID, consumerID, apiKey, method string,
	params map[string]any,
	name string,
) (int, http.Header, map[string]any) {
	t.Helper()
	body := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  withModernMeta(params),
	}
	return mcpExchange(t, gatewayID, consumerID, modernClientHeaders(apiKey, method, name), body)
}

func requireNoModernSessionHeader(t *testing.T, headers http.Header) {
	t.Helper()
	for key := range headers {
		require.False(t, strings.EqualFold(key, "Mcp-Session-Id"), "modern response leaked %s", key)
	}
}

func requireModernListHints(t *testing.T, result map[string]any) {
	t.Helper()
	require.Equal(t, "complete", result["resultType"])
	require.Equal(t, float64(300000), result["ttlMs"])
	require.Equal(t, "private", result["cacheScope"])
}

func TestMCPServer_DualEraClientUpstreamMatrix(t *testing.T) {
	cases := []struct {
		name       string
		client     string
		upstream   string
		mode       string
		legacyOnly bool
	}{
		{name: "modern→modern", client: "modern", upstream: "modern", mode: "auto"},
		{name: "modern→legacy", client: "modern", upstream: "legacy", mode: "auto", legacyOnly: true},
		{name: "legacy→modern", client: "legacy", upstream: "modern", mode: "auto"},
		{name: "legacy→legacy", client: "legacy", upstream: "legacy", mode: "auto", legacyOnly: true},
		{name: "modern→modern pinned", client: "modern", upstream: "modern", mode: "modern"},
		{name: "legacy→legacy pinned", client: "legacy", upstream: "legacy", mode: "legacy", legacyOnly: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toolName := "echo-" + strings.ReplaceAll(tc.name, "→", "-")
			toolName = strings.ReplaceAll(toolName, " ", "-")
			fixture := startEraMCPUpstream(t, tc.legacyOnly, toolName)

			gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
			registryID := CreateRegistry(
				t,
				gatewayID,
				mcpRegistryPayloadMode(uniqueName("mcp-reg"), fixture.server.URL, tc.mode),
			)
			consumerID, key := createMCPConsumer(t, gatewayID, []string{registryID}, nil, "")

			if tc.client == "modern" {
				status, headers, body := mcpRPCModern(t, gatewayID, consumerID, key, "tools/list", nil, "")
				result := rpcResult(t, status, body)
				require.Equal(t, []string{toolName}, listedNames(t, result, "tools"))
				requireModernListHints(t, result)
				requireNoModernSessionHeader(t, headers)

				status, headers, body = mcpRPCModern(
					t,
					gatewayID,
					consumerID,
					key,
					"tools/call",
					map[string]any{"name": toolName, "arguments": map[string]any{"message": "ok"}},
					toolName,
				)
				raw, err := json.Marshal(rpcResult(t, status, body))
				require.NoError(t, err)
				require.Contains(t, string(raw), toolName+":ok")
				requireNoModernSessionHeader(t, headers)
			} else {
				status, body := mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "tools/list", nil)
				require.Equal(t, []string{toolName}, listedNames(t, rpcResult(t, status, body), "tools"))
				status, body = mcpRPC(
					t,
					gatewayID,
					consumerID,
					apiKeyHeaders(key),
					"tools/call",
					map[string]any{"name": toolName, "arguments": map[string]any{"message": "ok"}},
				)
				raw, err := json.Marshal(rpcResult(t, status, body))
				require.NoError(t, err)
				require.Contains(t, string(raw), toolName+":ok")
			}

			if !tc.legacyOnly {
				require.Equal(t, int64(0), fixture.initializes.Load(), "modern upstream must stay sessionless")
			}
		})
	}
}

func TestMCPServer_ModernServerDiscoverAndNoSession(t *testing.T) {
	upstream := startModernMCPUpstream(t, func(s *sdk.Server) { addTool(s, "echo") })
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	registryID := CreateRegistry(t, gatewayID, mcpRegistryPayloadMode(uniqueName("mcp-reg"), upstream.URL, "auto"))
	consumerID, key := createMCPConsumer(t, gatewayID, []string{registryID}, nil, "")

	status, headers, body := mcpRPCModern(t, gatewayID, consumerID, key, "server/discover", nil, "")
	result := rpcResult(t, status, body)
	require.Contains(t, result["supportedVersions"], modernProtocolVersion)
	caps, ok := result["capabilities"].(map[string]any)
	require.True(t, ok)
	require.Contains(t, caps, "tools")
	requireModernListHints(t, result)
	requireNoModernSessionHeader(t, headers)

	status, headers, body = mcpRPCModern(t, gatewayID, consumerID, key, "tools/list", nil, "")
	require.Equal(t, []string{"echo"}, listedNames(t, rpcResult(t, status, body), "tools"))
	requireNoModernSessionHeader(t, headers)
}

func TestMCPServer_ModernNorthboundValidation(t *testing.T) {
	upstream := startMCPUpstream(t, func(s *sdk.Server) { addTool(s, "echo") })
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	registryID := CreateRegistry(t, gatewayID, mcpRegistryPayload(uniqueName("mcp-reg"), upstream.URL))
	consumerID, key := createMCPConsumer(t, gatewayID, []string{registryID}, nil, "")

	t.Run("unsupported version", func(t *testing.T) {
		headers := apiKeyHeaders(key)
		headers["MCP-Protocol-Version"] = "2099-01-01"
		headers["Mcp-Method"] = "tools/list"
		status, body := mcpPost(t, gatewayID, consumerID, headers, map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/list",
			"params":  withModernMeta(nil),
		})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, float64(-32022), rpcErrorCode(t, status, body))
	})

	t.Run("missing _meta", func(t *testing.T) {
		status, _, body := mcpExchange(
			t,
			gatewayID,
			consumerID,
			modernClientHeaders(key, "tools/list", ""),
			map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": map[string]any{}},
		)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, float64(-32602), rpcErrorCode(t, status, body))
	})

	t.Run("header body protocol mismatch", func(t *testing.T) {
		params := map[string]any{
			"_meta": map[string]any{
				"io.modelcontextprotocol/protocolVersion":    "2025-06-18",
				"io.modelcontextprotocol/clientCapabilities": map[string]any{},
			},
		}
		status, _, body := mcpExchange(
			t,
			gatewayID,
			consumerID,
			modernClientHeaders(key, "tools/list", ""),
			map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": params},
		)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, float64(-32602), rpcErrorCode(t, status, body))
	})

	t.Run("method mismatch", func(t *testing.T) {
		status, _, body := mcpExchange(
			t,
			gatewayID,
			consumerID,
			modernClientHeaders(key, "tools/call", "echo"),
			map[string]any{
				"jsonrpc": "2.0",
				"id":      1,
				"method":  "tools/list",
				"params":  withModernMeta(nil),
			},
		)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, float64(-32602), rpcErrorCode(t, status, body))
	})

	t.Run("name mismatch", func(t *testing.T) {
		status, _, body := mcpRPCModern(
			t,
			gatewayID,
			consumerID,
			key,
			"tools/call",
			map[string]any{"name": "echo", "arguments": map[string]any{"message": "x"}},
			"other",
		)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, float64(-32602), rpcErrorCode(t, status, body))
	})
}

func TestMCPServer_StrictModernModeFailsClosedAgainstLegacyUpstream(t *testing.T) {
	fixture := startEraMCPUpstream(t, true, "legacy-only-tool")
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	registryID := CreateRegistry(
		t,
		gatewayID,
		mcpRegistryPayloadMode(uniqueName("mcp-reg"), fixture.server.URL, "modern"),
	)
	consumerID, key := createMCPConsumer(t, gatewayID, []string{registryID}, nil, "closed")

	status, body := mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "tools/list", nil)
	require.NotNil(t, body["error"], "strict modern mode must fail closed against legacy-only upstream: http=%d body=%v", status, body)
	require.Equal(t, int64(0), fixture.initializes.Load())
}

func TestMCPServer_CachedEraSurvivesConcurrentModernClients(t *testing.T) {
	fixture := startEraMCPUpstream(t, true, "concurrent-echo")
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	registryID := CreateRegistry(
		t,
		gatewayID,
		mcpRegistryPayloadMode(uniqueName("mcp-reg"), fixture.server.URL, "auto"),
	)
	consumerID, key := createMCPConsumer(t, gatewayID, []string{registryID}, nil, "")

	status, _, body := mcpRPCModern(t, gatewayID, consumerID, key, "tools/list", nil, "")
	require.Equal(t, []string{"concurrent-echo"}, listedNames(t, rpcResult(t, status, body), "tools"))
	require.Equal(t, int64(1), fixture.initializes.Load())

	host, ok := gatewayHosts.Load(gatewayID)
	require.True(t, ok)
	url := MCPURL + "/" + ConsumerSlug(t, consumerID) + "/mcp"
	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
		"params":  withModernMeta(nil),
	})
	require.NoError(t, err)

	var wg sync.WaitGroup
	type outcome struct {
		status  int
		session string
		errCode any
		tools   int
	}
	out := make(chan outcome, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, reqErr := http.NewRequest(http.MethodPost, url, strings.NewReader(string(payload)))
			if reqErr != nil {
				out <- outcome{status: -1}
				return
			}
			req.Header.Set("Content-Type", "application/json")
			for k, v := range modernClientHeaders(key, "tools/list", "") {
				req.Header.Set(k, v)
			}
			req.Host = host.(string)
			resp, doErr := http.DefaultClient.Do(req)
			if doErr != nil {
				out <- outcome{status: -1}
				return
			}
			defer func() { _ = resp.Body.Close() }()
			var decoded map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&decoded)
			got := outcome{status: resp.StatusCode, session: resp.Header.Get("Mcp-Session-Id")}
			if rpcErr, ok := decoded["error"].(map[string]any); ok {
				got.errCode = rpcErr["code"]
			}
			if result, ok := decoded["result"].(map[string]any); ok {
				if tools, ok := result["tools"].([]any); ok {
					got.tools = len(tools)
				}
			}
			out <- got
		}()
	}
	wg.Wait()
	close(out)
	for got := range out {
		require.Equal(t, http.StatusOK, got.status)
		require.Nil(t, got.errCode)
		require.Empty(t, got.session)
		require.Equal(t, 1, got.tools)
	}
	require.Equal(t, int64(1), fixture.initializes.Load())
}

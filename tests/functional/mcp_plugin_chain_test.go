//go:build functional

package functional_test

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

const rpcCodePolicyBlocked = float64(-32001)

func addCountingEchoTool(server *sdk.Server, name string, calls *int64) {
	server.AddTool(
		&sdk.Tool{Name: name, InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(_ context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			atomic.AddInt64(calls, 1)
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

func addCountingFixedTool(server *sdk.Server, name, text string, calls *int64) {
	server.AddTool(
		&sdk.Tool{Name: name, InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(_ context.Context, _ *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			atomic.AddInt64(calls, 1)
			return &sdk.CallToolResult{
				Content: []sdk.Content{&sdk.TextContent{Text: text}},
			}, nil
		},
	)
}

func attachTrustGuardMCPPolicy(t *testing.T, gatewayID, consumerID, inspect, mode string) {
	t.Helper()
	payload := map[string]any{
		"name":     uniqueName("mcp-tg-pol"),
		"slug":     "trustguard",
		"enabled":  true,
		"priority": 0,
		"settings": map[string]any{
			"collector_id": trustGuardFunctionalCollectorID,
			"inspect":      inspect,
		},
	}
	if mode != "" {
		payload["mode"] = mode
	}
	policyID := CreatePolicy(t, gatewayID, payload)
	AttachPolicy(t, gatewayID, consumerID, policyID)
}

func setupMCPPluginChain(t *testing.T, configure func(*sdk.Server), inspect, mode string) (string, string, map[string]string) {
	t.Helper()
	upstream := startMCPUpstream(t, configure)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	registryID := CreateRegistry(t, gatewayID, mcpRegistryPayload(uniqueName("mcp-reg"), upstream.URL))
	consumerID, key := createMCPConsumer(t, gatewayID, []string{registryID}, nil, "")
	attachTrustGuardMCPPolicy(t, gatewayID, consumerID, inspect, mode)
	return gatewayID, consumerID, apiKeyHeaders(key)
}

func TestMCPPluginChain_PreRequestEnforceBlockSkipsUpstream(t *testing.T) {
	require.NotNil(t, TrustGuardFunctionalStub, "TrustGuard stub must be started in TestMain")
	TrustGuardFunctionalStub.Reset()

	var calls int64
	gatewayID, consumerID, headers := setupMCPPluginChain(t,
		func(s *sdk.Server) { addCountingEchoTool(s, "echo", &calls) },
		"request", "")

	status, body := mcpRPC(t, gatewayID, consumerID, headers, "tools/call",
		map[string]any{"name": "echo", "arguments": map[string]any{"message": "please run " + trustGuardBlockWord}})

	require.Equal(t, rpcCodePolicyBlocked, rpcErrorCode(t, status, body))
	require.Zero(t, atomic.LoadInt64(&calls), "upstream tool must not be invoked when PreRequest blocks")
}

func TestMCPPluginChain_PreResponseEnforceBlockDiscardsResult(t *testing.T) {
	require.NotNil(t, TrustGuardFunctionalStub, "TrustGuard stub must be started in TestMain")
	TrustGuardFunctionalStub.Reset()

	var calls int64
	gatewayID, consumerID, headers := setupMCPPluginChain(t,
		func(s *sdk.Server) { addCountingFixedTool(s, "leak", "leaked "+trustGuardBlockWord+" content", &calls) },
		"response", "")

	status, body := mcpRPC(t, gatewayID, consumerID, headers, "tools/call",
		map[string]any{"name": "leak", "arguments": map[string]any{"message": "benign"}})

	require.Equal(t, rpcCodePolicyBlocked, rpcErrorCode(t, status, body))
	require.Equal(t, int64(1), atomic.LoadInt64(&calls), "upstream tool must run once before PreResponse blocks its result")
}

func TestMCPPluginChain_ObserveModeNeverBlocks(t *testing.T) {
	require.NotNil(t, TrustGuardFunctionalStub, "TrustGuard stub must be started in TestMain")

	cases := []struct {
		name         string
		inspect      string
		toolName     string
		configure    func(*sdk.Server, *int64)
		arguments    map[string]any
		wantContains string
	}{
		{
			name:         "input direction",
			inspect:      "request",
			toolName:     "echo",
			configure:    func(s *sdk.Server, c *int64) { addCountingEchoTool(s, "echo", c) },
			arguments:    map[string]any{"message": trustGuardBlockWord},
			wantContains: "echo:" + trustGuardBlockWord,
		},
		{
			name:         "output direction",
			inspect:      "response",
			toolName:     "leak",
			configure:    func(s *sdk.Server, c *int64) { addCountingFixedTool(s, "leak", "leaked "+trustGuardBlockWord, c) },
			arguments:    map[string]any{"message": "benign"},
			wantContains: "leaked " + trustGuardBlockWord,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			TrustGuardFunctionalStub.Reset()

			var calls int64
			gatewayID, consumerID, headers := setupMCPPluginChain(t,
				func(s *sdk.Server) { tc.configure(s, &calls) },
				tc.inspect, "observe")

			status, body := mcpRPC(t, gatewayID, consumerID, headers, "tools/call",
				map[string]any{"name": tc.toolName, "arguments": tc.arguments})

			result := rpcResult(t, status, body)
			raw, err := json.Marshal(result)
			require.NoError(t, err)
			require.Contains(t, string(raw), tc.wantContains, "observe mode must return the tool result")
			require.Equal(t, int64(1), atomic.LoadInt64(&calls))
			require.GreaterOrEqual(t, TrustGuardFunctionalStub.GuardHits(), 1, "guard must be evaluated in observe mode")
		})
	}
}

func TestMCPPluginChain_GuardErrorFailsOpen(t *testing.T) {
	require.NotNil(t, TrustGuardFunctionalStub, "TrustGuard stub must be started in TestMain")
	TrustGuardFunctionalStub.Reset()

	var calls int64
	gatewayID, consumerID, headers := setupMCPPluginChain(t,
		func(s *sdk.Server) { addCountingEchoTool(s, "echo", &calls) },
		"request", "")

	status, body := mcpRPC(t, gatewayID, consumerID, headers, "tools/call",
		map[string]any{"name": "echo", "arguments": map[string]any{"message": "trigger " + trustGuardErrorWord}})

	result := rpcResult(t, status, body)
	raw, err := json.Marshal(result)
	require.NoError(t, err)
	require.Contains(t, string(raw), "echo:trigger "+trustGuardErrorWord, "guard error must fail open and return the tool result")
	require.Equal(t, int64(1), atomic.LoadInt64(&calls), "guard error must fail open and still invoke the upstream tool")
	require.GreaterOrEqual(t, TrustGuardFunctionalStub.GuardHits(), 1, "guard must have been attempted before failing open")
}

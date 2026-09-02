//go:build functional

package functional_test

import (
	"net/http"
	"sync/atomic"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

// notionShapedResult mirrors what a real MCP server (Notion's notion-fetch)
// returns: a single text content block whose text is itself a JSON document.
// The PII lives only here, on the response leg — a read tool's arguments carry
// nothing but an identifier.
const notionShapedResult = `{"metadata":{"type":"page"},"title":"Q3 Incident Postmortem",` +
	`"text":"Affected customer sample: alice.chen@tesco.example, card 4111 1111 1111 1111"}`

// TestMCPPluginChain_ToolsCallEvaluatesBothLegs pins the contract that was
// silently broken in production: a tools/call must reach TrustGuard TWICE —
// once for the request leg and once for the response leg. Every existing test
// in this package asserts what a single stage does once it runs; none asserts
// that the response stage runs at all. That gap let a policy configured with
// direction=request_response evaluate only the request, so DLP rules bound to
// the output direction never saw a tool result.
func TestMCPPluginChain_ToolsCallEvaluatesBothLegs(t *testing.T) {
	require.NotNil(t, TrustGuardFunctionalStub, "TrustGuard stub must be started in TestMain")
	TrustGuardFunctionalStub.Reset()

	var calls int64
	gatewayID, consumerID, headers := setupMCPPluginChain(t,
		func(s *sdk.Server) { addCountingFixedTool(s, "notion-fetch", notionShapedResult, &calls) },
		"request_response", "")

	status, body := mcpRPC(t, gatewayID, consumerID, headers, "tools/call",
		map[string]any{
			"name":      "notion-fetch",
			"arguments": map[string]any{"id": "https://app.notion.com/p/3cda09705f7a819c8ba4cada28b24f6d"},
		})

	require.Equal(t, http.StatusOK, status, "tools/call must succeed: %v", body)
	require.Equal(t, int64(1), atomic.LoadInt64(&calls), "upstream tool must run exactly once")

	require.Equal(t, 2, TrustGuardFunctionalStub.GuardHits(),
		"tools/call must evaluate BOTH legs with direction=request_response; "+
			"only %d evaluate call(s) reached the guard", TrustGuardFunctionalStub.GuardHits())

	// PreResponse runs after the upstream, so the final evaluate is the response
	// leg. Asserting the direction catches an evaluate that fires twice on the
	// request instead of once per leg.
	require.Equal(t, "output", TrustGuardFunctionalStub.lastGuard().Direction,
		"the last evaluate must carry the response leg")
}

// TestMCPPluginChain_InspectRequestSkipsResponseLeg documents the gate that
// produced the outage and guards the catalog default. The catalog ships
// direction=request as the prefilled value while the plugin's own default is
// request_response, so a policy created through the UI inspects the request
// only — and plugin.go returns passThrough on pre_response without a log or an
// event, which is what made the loss invisible.
func TestMCPPluginChain_InspectRequestSkipsResponseLeg(t *testing.T) {
	require.NotNil(t, TrustGuardFunctionalStub, "TrustGuard stub must be started in TestMain")
	TrustGuardFunctionalStub.Reset()

	var calls int64
	gatewayID, consumerID, headers := setupMCPPluginChain(t,
		func(s *sdk.Server) { addCountingFixedTool(s, "notion-fetch", notionShapedResult, &calls) },
		"request", "")

	status, body := mcpRPC(t, gatewayID, consumerID, headers, "tools/call",
		map[string]any{
			"name":      "notion-fetch",
			"arguments": map[string]any{"id": "page-id"},
		})

	require.Equal(t, http.StatusOK, status, "tools/call must succeed: %v", body)
	require.Equal(t, 1, TrustGuardFunctionalStub.GuardHits(),
		"direction=request must evaluate the request leg only")
	require.Equal(t, "input", TrustGuardFunctionalStub.lastGuard().Direction)
}

// attachTrustGuardMCPPolicyWithSettings attaches the guardrail policy with the
// exact settings map given, so a test can reproduce a policy that carries both
// leg keys. The shared helper only writes `inspect`.
func attachTrustGuardMCPPolicyWithSettings(t *testing.T, gatewayID, consumerID string, settings map[string]any) {
	t.Helper()
	merged := map[string]any{"collector_id": trustGuardFunctionalCollectorID}
	for k, v := range settings {
		merged[k] = v
	}
	policyID := CreatePolicy(t, gatewayID, map[string]any{
		"name":     uniqueName("mcp-tg-pol"),
		"slug":     "trustguard",
		"enabled":  true,
		"priority": 0,
		"settings": merged,
	})
	AttachPolicy(t, gatewayID, consumerID, policyID)
}

// TestMCPPluginChain_DirectionWinsOverStaleInspect reproduces the production
// policy end to end: direction=request_response — the key the catalog declares
// and the console form edits — beside a stale inspect=request. The response leg
// must still be evaluated, because a value the operator cannot see must not
// override the one they can.
func TestMCPPluginChain_DirectionWinsOverStaleInspect(t *testing.T) {
	require.NotNil(t, TrustGuardFunctionalStub, "TrustGuard stub must be started in TestMain")
	TrustGuardFunctionalStub.Reset()

	var calls int64
	upstream := startMCPUpstream(t, func(s *sdk.Server) {
		addCountingFixedTool(s, "notion-fetch", notionShapedResult, &calls)
	})
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	registryID := CreateRegistry(t, gatewayID, mcpRegistryPayload(uniqueName("mcp-reg"), upstream.URL))
	consumerID, key := createMCPConsumer(t, gatewayID, []string{registryID}, nil, "")
	attachTrustGuardMCPPolicyWithSettings(t, gatewayID, consumerID, map[string]any{
		"direction": "request_response",
		"inspect":   "request",
	})

	status, body := mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "tools/call",
		map[string]any{"name": "notion-fetch", "arguments": map[string]any{"id": "page-id"}})

	require.Equal(t, http.StatusOK, status, "tools/call must succeed: %v", body)
	require.Equal(t, 2, TrustGuardFunctionalStub.GuardHits(),
		"direction=request_response must win over a stale inspect=request and evaluate both legs; "+
			"only %d evaluate call(s) reached the guard", TrustGuardFunctionalStub.GuardHits())
	require.Equal(t, "output", TrustGuardFunctionalStub.lastGuard().Direction)
}

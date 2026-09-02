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
// The PII lives only there, on the response leg — a read tool's arguments carry
// nothing but an identifier.
const notionShapedResult = `{"metadata":{"type":"page"},"title":"Q3 Incident Postmortem",` +
	`"text":"Affected customer sample: alice.chen@tesco.example, card 4111 1111 1111 1111"}`

// attachTrustGuardMCPPolicyWithSettings attaches the guardrail policy with the
// exact settings map given, so a test can provision a policy that still stores
// the removed legacy key. The shared helper writes only `direction`.
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

func setupNotionFetchChain(t *testing.T, settings map[string]any) (string, string, map[string]string, *int64) {
	t.Helper()
	var calls int64
	upstream := startMCPUpstream(t, func(s *sdk.Server) {
		addCountingFixedTool(s, "notion-fetch", notionShapedResult, &calls)
	})
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	registryID := CreateRegistry(t, gatewayID, mcpRegistryPayload(uniqueName("mcp-reg"), upstream.URL))
	consumerID, key := createMCPConsumer(t, gatewayID, []string{registryID}, nil, "")
	attachTrustGuardMCPPolicyWithSettings(t, gatewayID, consumerID, settings)
	return gatewayID, consumerID, apiKeyHeaders(key), &calls
}

// TestMCPPluginChain_ToolsCallEvaluatesBothLegs pins the contract that broke in
// production: a tools/call must reach TrustGuard twice, once per leg. Every
// other test in this package asserts what a stage does once it runs; none
// asserted that the response stage runs at all, which is how a policy resolving
// to request-only went unnoticed — DLP rules bound to the output direction never
// saw a tool result.
func TestMCPPluginChain_ToolsCallEvaluatesBothLegs(t *testing.T) {
	require.NotNil(t, TrustGuardFunctionalStub, "TrustGuard stub must be started in TestMain")
	TrustGuardFunctionalStub.Reset()

	gatewayID, consumerID, headers, calls := setupNotionFetchChain(t,
		map[string]any{"direction": "request_response"})

	status, body := mcpRPC(t, gatewayID, consumerID, headers, "tools/call",
		map[string]any{
			"name":      "notion-fetch",
			"arguments": map[string]any{"id": "https://app.notion.com/p/3cda09705f7a819c8ba4cada28b24f6d"},
		})

	require.Equal(t, http.StatusOK, status, "tools/call must succeed: %v", body)
	require.Equal(t, int64(1), atomic.LoadInt64(calls), "upstream tool must run exactly once")
	require.Equal(t, 2, TrustGuardFunctionalStub.GuardHits(),
		"direction=request_response must evaluate both legs; only %d evaluate call(s) reached the guard",
		TrustGuardFunctionalStub.GuardHits())

	// PreResponse runs after the upstream, so the final evaluate is the response
	// leg. Asserting the direction catches an evaluate firing twice on the
	// request instead of once per leg.
	require.Equal(t, "output", TrustGuardFunctionalStub.lastGuard().Direction,
		"the last evaluate must carry the response leg")
}

// TestMCPPluginChain_StoredLegacyInspectKeyIsIgnored covers the state the
// migration exists to clear. A policy that still stores the removed key must not
// let it decide anything: `direction` is now the only key the plugin reads.
func TestMCPPluginChain_StoredLegacyInspectKeyIsIgnored(t *testing.T) {
	require.NotNil(t, TrustGuardFunctionalStub, "TrustGuard stub must be started in TestMain")
	TrustGuardFunctionalStub.Reset()

	gatewayID, consumerID, headers, _ := setupNotionFetchChain(t, map[string]any{
		"direction": "request_response",
		"inspect":   "request",
	})

	status, body := mcpRPC(t, gatewayID, consumerID, headers, "tools/call",
		map[string]any{"name": "notion-fetch", "arguments": map[string]any{"id": "page-id"}})

	require.Equal(t, http.StatusOK, status, "tools/call must succeed: %v", body)
	require.Equal(t, 2, TrustGuardFunctionalStub.GuardHits(),
		"a stored legacy inspect key must not suppress the response leg; only %d evaluate call(s) reached the guard",
		TrustGuardFunctionalStub.GuardHits())
	require.Equal(t, "output", TrustGuardFunctionalStub.lastGuard().Direction)
}

// TestMCPPluginChain_DirectionRequestSkipsResponseLeg documents the intentional
// single-leg case, so the skip stays a deliberate configuration and not an
// accident nobody notices.
func TestMCPPluginChain_DirectionRequestSkipsResponseLeg(t *testing.T) {
	require.NotNil(t, TrustGuardFunctionalStub, "TrustGuard stub must be started in TestMain")
	TrustGuardFunctionalStub.Reset()

	gatewayID, consumerID, headers, _ := setupNotionFetchChain(t, map[string]any{"direction": "request"})

	status, body := mcpRPC(t, gatewayID, consumerID, headers, "tools/call",
		map[string]any{"name": "notion-fetch", "arguments": map[string]any{"id": "page-id"}})

	require.Equal(t, http.StatusOK, status, "tools/call must succeed: %v", body)
	require.Equal(t, 1, TrustGuardFunctionalStub.GuardHits(),
		"direction=request must evaluate the request leg only")
	require.Equal(t, "input", TrustGuardFunctionalStub.lastGuard().Direction)
}

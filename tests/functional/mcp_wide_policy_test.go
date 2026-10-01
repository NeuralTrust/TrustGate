//go:build functional

package functional_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const orphanPolicyWarning = "policy has no consumers and is not global: it runs nowhere"

func placementURL(gatewayID, policyID, placement string) string {
	return fmt.Sprintf("%s/v1/gateways/%s/policies/%s/%s", AdminURL, gatewayID, policyID, placement)
}

func groupDenyAllPolicyPayload(groups ...string) map[string]any {
	payload := toolAllowlistMCPPolicyPayload(denyAllTools())
	payload["mcp_scope"] = map[string]any{"groups": groups}
	return payload
}

func requirePlacement(t *testing.T, body map[string]any, global, mcpWide bool) {
	t.Helper()
	require.Equal(t, global, body["global"], "global: %v", body)
	require.Equal(t, mcpWide, body["mcp_wide"], "mcp_wide: %v", body)
}

func createPolicyBody(t *testing.T, gatewayID string, payload map[string]any) (string, map[string]any) {
	t.Helper()
	status, body := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/v1/gateways/%s/policies", AdminURL, gatewayID), nil, payload)
	require.Equal(t, http.StatusCreated, status, "create policy failed: %v", body)
	id, ok := body["id"].(string)
	require.True(t, ok, "create policy response missing id: %v", body)
	return id, body
}

func isPolicyBlocked(body map[string]any) bool {
	rpcErr, ok := body["error"].(map[string]any)
	if !ok {
		return false
	}
	code, ok := rpcErr["code"].(float64)
	return ok && code == rpcCodePolicyBlocked
}

// requireBlockedOnceSynced polls until the admin plane's invalidation reaches
// the MCP plane and the call is denied, then proves a denied call never reaches
// the upstream.
func requireBlockedOnceSynced(t *testing.T, gatewayID, consumerID string, headers map[string]string, up *scopedUpstream) {
	t.Helper()
	require.Eventually(t, func() bool {
		_, body := callEcho(t, gatewayID, consumerID, headers, up.exposed("echo"), "hi")
		return isPolicyBlocked(body)
	}, 10*time.Second, 100*time.Millisecond, "the MCP-wide policy must reach the MCP plane")
	before := up.callCount()
	status, body := callEcho(t, gatewayID, consumerID, headers, up.exposed("echo"), "hi")
	requirePolicyBlocked(t, status, body)
	require.Equal(t, before, up.callCount(), "the denied call must not reach the upstream")
}

func requireEchoedOnceSynced(t *testing.T, gatewayID, consumerID string, headers map[string]string, up *scopedUpstream) {
	t.Helper()
	require.Eventually(t, func() bool {
		_, body := callEcho(t, gatewayID, consumerID, headers, up.exposed("echo"), "hi")
		return body["error"] == nil && body["result"] != nil
	}, 10*time.Second, 100*time.Millisecond, "the demotion must reach the MCP plane")
	status, body := callEcho(t, gatewayID, consumerID, headers, up.exposed("echo"), "hi")
	requireEchoed(t, status, body, "echo", "hi")
}

func TestMCPWidePolicy_PromoteSwapAndDemote(t *testing.T) {
	defer Track(t, "MCPWidePolicy")()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-wide-gw")})
	policyID, created := createPolicyBody(t, gatewayID, groupDenyAllPolicyPayload("Finanzas"))
	requirePlacement(t, created, false, false)
	require.Contains(t, responseWarnings(created), orphanPolicyWarning, "a new policy is a draft")

	t.Run("promoting answers the MCP-wide policy without the orphan warning", func(t *testing.T) {
		body := SetPolicyMCPWide(t, gatewayID, policyID)
		requirePlacement(t, body, false, true)
		assert.NotContains(t, responseWarnings(body), orphanPolicyWarning,
			"an MCP-wide policy runs on every MCP consumer, so it is not a draft")
	})

	t.Run("the placement and the scope read back", func(t *testing.T) {
		body := getPolicy(t, gatewayID, policyID)
		requirePlacement(t, body, false, true)
		scope, ok := body["mcp_scope"].(map[string]any)
		require.True(t, ok, "mcp_scope: %v", body)
		assert.Equal(t, []any{"Finanzas"}, scope["groups"])
	})

	t.Run("promoting to global clears mcp_wide and back", func(t *testing.T) {
		status, body := sendRequest(t, http.MethodPost, placementURL(gatewayID, policyID, "global"), nil, nil)
		require.Equal(t, http.StatusOK, status, "body=%v", body)
		requirePlacement(t, body, true, false)
		requirePlacement(t, getPolicy(t, gatewayID, policyID), true, false)

		requirePlacement(t, SetPolicyMCPWide(t, gatewayID, policyID), false, true)
		requirePlacement(t, getPolicy(t, gatewayID, policyID), false, true)
	})

	t.Run("DELETE /global leaves an MCP-wide policy as it is", func(t *testing.T) {
		status, body := sendRequest(t, http.MethodDelete, placementURL(gatewayID, policyID, "global"), nil, nil)
		require.Equal(t, http.StatusOK, status, "body=%v", body)
		requirePlacement(t, body, false, true)
	})

	t.Run("DELETE /mcp-wide demotes and is idempotent", func(t *testing.T) {
		for range 2 {
			status, body := sendRequest(t, http.MethodDelete, placementURL(gatewayID, policyID, "mcp-wide"), nil, nil)
			require.Equal(t, http.StatusOK, status, "body=%v", body)
			requirePlacement(t, body, false, false)
		}
		requirePlacement(t, getPolicy(t, gatewayID, policyID), false, false)
	})
}

// An MCP-wide policy takes the all-consumers cell of every group it names, the
// cell a global policy of that scope takes too, so a second promotion of the
// same plugin onto an overlapping group is refused with the wording the console
// matches on, whichever placement holds the cell.
func TestMCPWidePolicy_OverlappingGroupsConflict(t *testing.T) {
	defer Track(t, "MCPWidePolicy")()
	for _, occupant := range []string{"mcp-wide", "global"} {
		t.Run("against a "+occupant+" policy", func(t *testing.T) {
			gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-wide-level-gw")})
			first := CreatePolicy(t, gatewayID, groupDenyAllPolicyPayload("Finanzas"))
			second := CreatePolicy(t, gatewayID, groupDenyAllPolicyPayload("Finanzas", "Marketing"))
			status, body := sendRequest(t, http.MethodPost, placementURL(gatewayID, first, occupant), nil, nil)
			require.Equal(t, http.StatusOK, status, "body=%v", body)

			status, body = sendRequest(t, http.MethodPost, placementURL(gatewayID, second, "mcp-wide"), nil, nil)
			require.Equal(t, http.StatusConflict, status, "body=%v", body)
			assert.Equal(t, "conflict", body["error"])
			assert.Contains(t, body["message"], "already runs plugin")
			assert.Contains(t, body["message"], first)
			requirePlacement(t, getPolicy(t, gatewayID, second), false, false)
		})
	}
}

func TestMCPWidePolicy_PluginWithoutMCPIsRefused(t *testing.T) {
	defer Track(t, "MCPWidePolicy")()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-wide-llm-gw")})
	policyID := CreatePolicy(t, gatewayID, map[string]any{
		"name":     uniqueName("mcp-wide-llm-pol"),
		"slug":     "model_allowlist",
		"enabled":  true,
		"priority": 0,
		"settings": map[string]any{
			"allowed_models":         []string{"gpt-5*"},
			"behavior_on_disallowed": "reject",
		},
	})

	status, body := sendRequest(t, http.MethodPost, placementURL(gatewayID, policyID, "mcp-wide"), nil, nil)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
	assert.Contains(t, body["message"], "does not support protocol")
	requirePlacement(t, getPolicy(t, gatewayID, policyID), false, false)
}

// A group-scoped deny-all promoted MCP-wide runs for members of the group on
// every MCP consumer of the gateway, one created after the promotion included,
// and spares everyone else. Before the promotion it is a draft and runs nowhere.
func TestMCPWidePolicy_RunsForGroupMembersOnEveryMCPConsumer(t *testing.T) {
	defer Track(t, "MCPWidePolicy")()
	gatewayID, consumerID, audience, stub, x, _ := setupScopedOAuthConsumer(t, []string{"echo"}, []string{"echo"})
	policyID := CreatePolicy(t, gatewayID, groupDenyAllPolicyPayload("Finanzas"))

	finance := bearerHeaders(stub.mint(t, audience, map[string]any{
		"sub": "fin-subject", "groups": []string{"Finanzas"}}))
	marketing := bearerHeaders(stub.mint(t, audience, map[string]any{
		"sub": "mkt-subject", "groups": []string{"Marketing"}}))

	t.Run("created and not promoted, it runs nowhere", func(t *testing.T) {
		status, body := callEcho(t, gatewayID, consumerID, finance, x.exposed("echo"), "hi")
		requireEchoed(t, status, body, "echo", "hi")
	})

	SetPolicyMCPWide(t, gatewayID, policyID)

	t.Run("promoted, it denies a member of the group", func(t *testing.T) {
		requireBlockedOnceSynced(t, gatewayID, consumerID, finance, x)
	})

	t.Run("and spares a member of another group", func(t *testing.T) {
		status, body := callEcho(t, gatewayID, consumerID, marketing, x.exposed("echo"), "hi")
		requireEchoed(t, status, body, "echo", "hi")
	})

	t.Run("an MCP consumer created after the promotion is covered too", func(t *testing.T) {
		laterID, laterAudience := createOAuthMCPConsumer(t, gatewayID, []string{x.registryID}, stub)
		laterFinance := bearerHeaders(stub.mint(t, laterAudience, map[string]any{
			"sub": "fin-subject", "groups": []string{"Finanzas"}}))
		laterMarketing := bearerHeaders(stub.mint(t, laterAudience, map[string]any{
			"sub": "mkt-subject", "groups": []string{"Marketing"}}))

		requireBlockedOnceSynced(t, gatewayID, laterID, laterFinance, x)
		status, body := callEcho(t, gatewayID, laterID, laterMarketing, x.exposed("echo"), "hi")
		requireEchoed(t, status, body, "echo", "hi")
	})

	t.Run("demoted, it runs nowhere again", func(t *testing.T) {
		status, body := sendRequest(t, http.MethodDelete, placementURL(gatewayID, policyID, "mcp-wide"), nil, nil)
		require.Equal(t, http.StatusOK, status, "body=%v", body)
		requireEchoedOnceSynced(t, gatewayID, consumerID, finance, x)
	})
}

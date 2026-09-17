//go:build functional

package functional_test

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

// scopedUpstream is one stub MCP server behind its own registry. It counts the
// tools/list requests it answers and the tool invocations that reach it, which
// is how a test proves a policy ran (or did not) on this upstream.
type scopedUpstream struct {
	registryID string
	lists      int64
	calls      int64
}

func (u *scopedUpstream) listCount() int64 { return atomic.LoadInt64(&u.lists) }
func (u *scopedUpstream) callCount() int64 { return atomic.LoadInt64(&u.calls) }

// exposed is the name the consumer's surface gives one of this upstream's
// tools. A consumer bound to more than one registry hashes every name, so a
// policy written against the native name must still find it.
func (u *scopedUpstream) exposed(tool string) string { return federatedRPCName(u.registryID, tool) }

func countListTools(lists *int64) sdk.Middleware {
	return func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if method == "tools/list" {
				atomic.AddInt64(lists, 1)
			}
			return next(ctx, method, req)
		}
	}
}

func startScopedUpstream(t *testing.T, gatewayID string, tools ...string) *scopedUpstream {
	t.Helper()
	up := &scopedUpstream{}
	server := startMCPUpstream(t, func(s *sdk.Server) {
		s.AddReceivingMiddleware(countListTools(&up.lists))
		for _, name := range tools {
			addCountingEchoTool(s, name, &up.calls)
		}
	})
	up.registryID = CreateRegistry(t, gatewayID, mcpRegistryPayload(uniqueName("mcp-reg"), server.URL))
	return up
}

func setupMCPPluginChainTwoUpstreams(
	t *testing.T,
	toolsX, toolsY []string,
) (gatewayID, consumerID string, headers map[string]string, x, y *scopedUpstream) {
	t.Helper()
	gatewayID = CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	x = startScopedUpstream(t, gatewayID, toolsX...)
	y = startScopedUpstream(t, gatewayID, toolsY...)
	consumerID, key := createMCPConsumer(t, gatewayID, []string{x.registryID, y.registryID}, nil, "")
	return gatewayID, consumerID, apiKeyHeaders(key), x, y
}

// attachScopedPolicy creates payload with the given mcp_scope (nil leaves the
// policy unscoped) and attaches it to the consumer.
func attachScopedPolicy(t *testing.T, gatewayID, consumerID string, payload, mcpScope map[string]any) string {
	t.Helper()
	if mcpScope != nil {
		payload["mcp_scope"] = mcpScope
	}
	policyID := CreatePolicy(t, gatewayID, payload)
	AttachPolicy(t, gatewayID, consumerID, policyID)
	return policyID
}

func toolAllowlistMCPPolicyPayload(settings map[string]any) map[string]any {
	return map[string]any{
		"name":     uniqueName("mcp-ta-pol"),
		"slug":     "tool_allowlist",
		"enabled":  true,
		"priority": 0,
		"settings": settings,
	}
}

func denyAllTools() map[string]any { return map[string]any{"deny_tools": []string{"*"}} }

func registryScope(registryIDs ...string) map[string]any {
	return map[string]any{"registry_ids": registryIDs}
}

func toolScope(registryID, tool string) map[string]any {
	return map[string]any{"tools": []map[string]any{{"registry_id": registryID, "tool": tool}}}
}

func withScope(scope map[string]any, extra map[string]any) map[string]any {
	for k, v := range extra {
		scope[k] = v
	}
	return scope
}

func callEcho(t *testing.T, gatewayID, consumerID string, headers map[string]string, exposed, message string) (int, map[string]any) {
	t.Helper()
	return mcpRPC(t, gatewayID, consumerID, headers, "tools/call",
		map[string]any{"name": exposed, "arguments": map[string]any{"message": message}})
}

func requirePolicyBlocked(t *testing.T, status int, body map[string]any) {
	t.Helper()
	require.Equal(t, rpcCodePolicyBlocked, rpcErrorCode(t, status, body))
	require.Equal(t, http.StatusOK, status,
		"policy-blocked tools/call must stay on HTTP 200 with a JSON-RPC error (non-2xx drops MCP sessions): %v", body)
}

func requireEchoed(t *testing.T, status int, body map[string]any, tool, message string) {
	t.Helper()
	raw, err := json.Marshal(rpcResult(t, status, body))
	require.NoError(t, err)
	require.Contains(t, string(raw), tool+":"+message, "tools/call must return the upstream result")
}

func TestMCPPolicyScope_FederatedSurfaceKeepsNativeNamesForScopes(t *testing.T) {
	gatewayID, consumerID, headers, x, y := setupMCPPluginChainTwoUpstreams(t, []string{"echo"}, []string{"echo"})

	status, body := mcpRPC(t, gatewayID, consumerID, headers, "tools/list", nil)
	names := listedNames(t, rpcResult(t, status, body), "tools")

	require.NotContains(t, names, "echo", "two registries must federate every tool name")
	require.Contains(t, names, x.exposed("echo"))
	require.Contains(t, names, y.exposed("echo"))
}

func TestMCPPolicyScope_ToolScopedTrustGuardGuardsOnlyThatTool(t *testing.T) {
	require.NotNil(t, TrustGuardFunctionalStub, "TrustGuard stub must be started in TestMain")
	TrustGuardFunctionalStub.Reset()

	gatewayID, consumerID, headers, x, y := setupMCPPluginChainTwoUpstreams(t, []string{"echo", "other"}, []string{"echo"})
	attachScopedPolicy(t, gatewayID, consumerID, trustGuardMCPPolicyPayload("request", ""), toolScope(x.registryID, "echo"))
	message := "please run " + trustGuardBlockWord

	status, body := callEcho(t, gatewayID, consumerID, headers, y.exposed("echo"), message)
	requireEchoed(t, status, body, "echo", message)
	require.Equal(t, int64(1), y.callCount())
	require.Zero(t, TrustGuardFunctionalStub.GuardHits(), "a policy scoped to a tool of X must never evaluate a call to Y")

	status, body = callEcho(t, gatewayID, consumerID, headers, x.exposed("other"), message)
	requireEchoed(t, status, body, "other", message)
	require.Equal(t, int64(1), x.callCount())
	require.Zero(t, TrustGuardFunctionalStub.GuardHits(), "a policy scoped to one tool must not evaluate the registry's other tools")

	status, body = callEcho(t, gatewayID, consumerID, headers, x.exposed("echo"), message)
	requirePolicyBlocked(t, status, body)
	require.Equal(t, int64(1), x.callCount(), "the denied call must not reach the upstream")
	require.GreaterOrEqual(t, TrustGuardFunctionalStub.GuardHits(), 1, "the scoped tool must be evaluated")
}

func TestMCPPolicyScope_RegistryScopedPolicyCoversEveryToolOfThatRegistry(t *testing.T) {
	require.NotNil(t, TrustGuardFunctionalStub, "TrustGuard stub must be started in TestMain")
	TrustGuardFunctionalStub.Reset()

	gatewayID, consumerID, headers, x, y := setupMCPPluginChainTwoUpstreams(t, []string{"echo"}, []string{"echo", "other"})
	attachScopedPolicy(t, gatewayID, consumerID, trustGuardMCPPolicyPayload("request", ""), registryScope(y.registryID))
	message := "please run " + trustGuardBlockWord

	for _, tool := range []string{"echo", "other"} {
		status, body := callEcho(t, gatewayID, consumerID, headers, y.exposed(tool), message)
		requirePolicyBlocked(t, status, body)
	}
	require.Zero(t, y.callCount(), "no denied call may reach Y")
	hits := TrustGuardFunctionalStub.GuardHits()
	require.GreaterOrEqual(t, hits, 2, "every tool of the scoped registry must be evaluated")

	status, body := callEcho(t, gatewayID, consumerID, headers, x.exposed("echo"), message)
	requireEchoed(t, status, body, "echo", message)
	require.Equal(t, int64(1), x.callCount())
	require.Equal(t, hits, TrustGuardFunctionalStub.GuardHits(), "a policy scoped to Y must not evaluate a call to X")
}

func TestMCPPolicyScope_ToolAllowlistDenyAllScopedToOneTool(t *testing.T) {
	gatewayID, consumerID, headers, x, y := setupMCPPluginChainTwoUpstreams(t, []string{"echo", "other"}, []string{"echo"})
	attachScopedPolicy(t, gatewayID, consumerID, toolAllowlistMCPPolicyPayload(denyAllTools()), toolScope(x.registryID, "echo"))

	status, body := callEcho(t, gatewayID, consumerID, headers, x.exposed("echo"), "hi")
	requirePolicyBlocked(t, status, body)
	require.Zero(t, x.callCount(), "tool_allowlist deny must refuse the call before the upstream")

	status, body = callEcho(t, gatewayID, consumerID, headers, x.exposed("other"), "hi")
	requireEchoed(t, status, body, "other", "hi")
	status, body = callEcho(t, gatewayID, consumerID, headers, y.exposed("echo"), "hi")
	requireEchoed(t, status, body, "echo", "hi")
	require.Equal(t, int64(1), x.callCount())
	require.Equal(t, int64(1), y.callCount())
}

func TestMCPPolicyScope_ToolAllowlistObserveNeverBlocks(t *testing.T) {
	gatewayID, consumerID, headers, x, _ := setupMCPPluginChainTwoUpstreams(t, []string{"echo"}, []string{"echo"})
	payload := toolAllowlistMCPPolicyPayload(denyAllTools())
	payload["mode"] = "observe"
	attachScopedPolicy(t, gatewayID, consumerID, payload, toolScope(x.registryID, "echo"))

	status, body := callEcho(t, gatewayID, consumerID, headers, x.exposed("echo"), "hi")
	requireEchoed(t, status, body, "echo", "hi")
	require.Equal(t, int64(1), x.callCount(), "observe mode must let the call through")
}

func TestMCPPolicyScope_UnscopedPolicyKeepsConsumerWideBehaviour(t *testing.T) {
	require.NotNil(t, TrustGuardFunctionalStub, "TrustGuard stub must be started in TestMain")
	TrustGuardFunctionalStub.Reset()

	gatewayID, consumerID, headers, x, y := setupMCPPluginChainTwoUpstreams(t, []string{"echo"}, []string{"echo"})
	attachScopedPolicy(t, gatewayID, consumerID, trustGuardMCPPolicyPayload("request", ""), nil)
	message := "please run " + trustGuardBlockWord

	for _, up := range []*scopedUpstream{x, y} {
		status, body := callEcho(t, gatewayID, consumerID, headers, up.exposed("echo"), message)
		requirePolicyBlocked(t, status, body)
		require.Zero(t, up.callCount())
	}
	require.GreaterOrEqual(t, TrustGuardFunctionalStub.GuardHits(), 2, "an unscoped policy runs on every registry")
}

// An API-key consumer that does not act for users runs as the application
// principal: a subject, no email, no groups. Scopes that select by user or
// group therefore never match it, and an exception for a group never exempts
// it. The positive half of the "only Finanzas" pattern needs a caller that
// bears a groups claim, which this suite cannot mint yet.
func TestMCPPolicyScope_PrincipalScopedPoliciesAgainstAPIKeyCallers(t *testing.T) {
	gatewayID, consumerID, headers, x, _ := setupMCPPluginChainTwoUpstreams(t, []string{"echo", "other"}, []string{"echo"})
	attachScopedPolicy(t, gatewayID, consumerID, toolAllowlistMCPPolicyPayload(denyAllTools()),
		withScope(toolScope(x.registryID, "echo"), map[string]any{"groups": []string{"Finanzas"}}))
	attachScopedPolicy(t, gatewayID, consumerID, toolAllowlistMCPPolicyPayload(denyAllTools()),
		withScope(toolScope(x.registryID, "echo"), map[string]any{"users": []string{"ana@acme.com"}}))
	attachScopedPolicy(t, gatewayID, consumerID, toolAllowlistMCPPolicyPayload(denyAllTools()),
		withScope(toolScope(x.registryID, "other"), map[string]any{"except_groups": []string{"Finanzas"}}))

	t.Run("group and user scopes stay dormant", func(t *testing.T) {
		status, body := callEcho(t, gatewayID, consumerID, headers, x.exposed("echo"), "hi")
		requireEchoed(t, status, body, "echo", "hi")
		require.Equal(t, int64(1), x.callCount())
	})

	t.Run("except_groups denies a caller outside the group", func(t *testing.T) {
		status, body := callEcho(t, gatewayID, consumerID, headers, x.exposed("other"), "hi")
		requirePolicyBlocked(t, status, body)
		require.Equal(t, int64(1), x.callCount(), "the denied call must not reach the upstream")
	})

	t.Run("except_groups exempts a member of the group", func(t *testing.T) {
		t.Skip("needs an MCP caller bearing a groups claim: oauthIDPStub serves a JWKS but discards its signing key, " +
			"and no functional helper mints a bearer token the MCP plane accepts (RUN-1597 follow-up)")
	})
}

func TestMCPPolicyScope_ListToolsOncePerRegistryWithinTTL(t *testing.T) {
	gatewayID, consumerID, headers, x, y := setupMCPPluginChainTwoUpstreams(t, []string{"echo"}, []string{"echo"})
	attachScopedPolicy(t, gatewayID, consumerID, toolAllowlistMCPPolicyPayload(denyAllTools()), toolScope(x.registryID, "never"))
	attachScopedPolicy(t, gatewayID, consumerID, toolAllowlistMCPPolicyPayload(map[string]any{"allow_tools": []string{"*"}}),
		registryScope(y.registryID))

	listsX, listsY := x.listCount(), y.listCount()
	status, body := callEcho(t, gatewayID, consumerID, headers, x.exposed("echo"), "one")
	requireEchoed(t, status, body, "echo", "one")
	require.LessOrEqual(t, x.listCount()-listsX, int64(1), "resolving a call lists X at most once")
	require.LessOrEqual(t, y.listCount()-listsY, int64(1), "resolving a call lists Y at most once")

	listsX, listsY = x.listCount(), y.listCount()
	status, body = callEcho(t, gatewayID, consumerID, headers, x.exposed("echo"), "two")
	requireEchoed(t, status, body, "echo", "two")
	require.Equal(t, listsX, x.listCount(), "a second call within the TTL must not list X again")
	require.Equal(t, listsY, y.listCount(), "a second call within the TTL must not list Y again")
	require.Equal(t, int64(2), x.callCount())
}

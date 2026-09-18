//go:build functional

package functional_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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
// tools: server-prefixed, so a policy written against the native name must
// still find it.
func (u *scopedUpstream) exposed(tool string) string { return exposedToolName(u.registryID, tool) }

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
	attachPolicyWarnings(t, gatewayID, consumerID, policyID)
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

	require.NotContains(t, names, "echo", "every tool carries its server prefix")
	require.Contains(t, names, x.exposed("echo"))
	require.Contains(t, names, y.exposed("echo"))
	require.NotEqual(t, x.exposed("echo"), y.exposed("echo"), "the same native tool on two registries must expose two names")
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
// principal: a subject, no groups. Its principal is inert, so the group
// dimension of a scope does not gate for it: a scope naming groups selects it,
// and an exception for a group still never exempts it. This is the api-key half
// of the principal dimension; the half where a caller carries a groups claim is
// covered by the tests below that authenticate with a token from oauthIDPStub.
func TestMCPPolicyScope_PrincipalScopedPoliciesAgainstAPIKeyCallers(t *testing.T) {
	gatewayID, consumerID, headers, x, _ := setupMCPPluginChainTwoUpstreams(t, []string{"echo", "other"}, []string{"echo"})
	attachScopedPolicy(t, gatewayID, consumerID, toolAllowlistMCPPolicyPayload(denyAllTools()),
		withScope(toolScope(x.registryID, "echo"), map[string]any{"groups": []string{"Finanzas"}}))
	attachScopedPolicy(t, gatewayID, consumerID, toolAllowlistMCPPolicyPayload(denyAllTools()),
		withScope(toolScope(x.registryID, "other"), map[string]any{"except_groups": []string{"Finanzas"}}))

	t.Run("a group scope runs for the api-key caller", func(t *testing.T) {
		status, body := callEcho(t, gatewayID, consumerID, headers, x.exposed("echo"), "hi")
		requirePolicyBlocked(t, status, body)
		require.Zero(t, x.callCount(),
			"the group dimension is inert for an api key, so the policy runs and the plugin denies")
	})

	t.Run("except_groups denies a caller outside the group", func(t *testing.T) {
		status, body := callEcho(t, gatewayID, consumerID, headers, x.exposed("other"), "hi")
		requirePolicyBlocked(t, status, body)
		require.Zero(t, x.callCount(), "the denied call must not reach the upstream")
	})

	// A member of the group is exempted rather than denied, which needs a
	// caller bearing a groups claim: see
	// TestMCPPolicyScope_ExceptGroupsExemptsMembersAndDeniesTheRest.
}

// createDualAuthMCPConsumer binds the registries to one MCP consumer that
// accepts both a bearer token from stub and an api key. That is the shape the
// inert principal is about: one consumer, two credentials, and a group scope
// that answers differently depending on which of the two a caller presents.
func createDualAuthMCPConsumer(
	t *testing.T,
	gatewayID string,
	registryIDs []string,
	stub *oauthIDPStub,
) (consumerID, audience, apiKey string) {
	t.Helper()
	consumerID, audience = createOAuthMCPConsumer(t, gatewayID, registryIDs, stub)
	authID, key := CreateAPIKeyAuth(t, gatewayID, uniqueName("mcp-key"))
	AttachAuth(t, gatewayID, consumerID, authID)
	return consumerID, audience, key
}

func setupScopedDualAuthConsumer(
	t *testing.T,
	toolsX, toolsY []string,
) (gatewayID, consumerID, audience, apiKey string, stub *oauthIDPStub, x, y *scopedUpstream) {
	t.Helper()
	gatewayID = CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	x = startScopedUpstream(t, gatewayID, toolsX...)
	y = startScopedUpstream(t, gatewayID, toolsY...)
	stub = newOAuthIDPStub(t)
	consumerID, audience, apiKey = createDualAuthMCPConsumer(t, gatewayID, []string{x.registryID, y.registryID}, stub)
	return gatewayID, consumerID, audience, apiKey, stub, x, y
}

// The whole of rule 5 on one consumer that admits both credentials: the group
// dimension gates a token caller and does not gate an api-key caller, and the
// relaxation is one-directional. Both callers are in the same test because the
// asymmetry is the point — a groups scope answers differently for the two, an
// except_groups scope answers the same.
func TestMCPPolicyScope_APIKeyCallerIsInertOnGroupsAndUnchangedOnExceptGroups(t *testing.T) {
	gatewayID, consumerID, audience, apiKey, stub, x, _ := setupScopedDualAuthConsumer(t,
		[]string{"echo", "other"}, []string{"echo"})
	attachScopedPolicy(t, gatewayID, consumerID, toolAllowlistMCPPolicyPayload(denyAllTools()),
		withScope(toolScope(x.registryID, "echo"), map[string]any{"groups": []string{"Finanzas"}}))
	attachScopedPolicy(t, gatewayID, consumerID, toolAllowlistMCPPolicyPayload(denyAllTools()),
		withScope(toolScope(x.registryID, "other"), map[string]any{"except_groups": []string{"Finanzas"}}))

	key := apiKeyHeaders(apiKey)
	finance := bearerHeaders(stub.mint(t, audience, map[string]any{
		"sub": "fin-subject", "groups": []string{"Finanzas"}}))
	marketing := bearerHeaders(stub.mint(t, audience, map[string]any{
		"sub": "mkt-subject", "groups": []string{"Marketing"}}))

	t.Run("groups: the api key is selected like a member of the group", func(t *testing.T) {
		before := x.callCount()
		status, body := callEcho(t, gatewayID, consumerID, key, x.exposed("echo"), "hi")
		requirePolicyBlocked(t, status, body)
		status, body = callEcho(t, gatewayID, consumerID, finance, x.exposed("echo"), "hi")
		requirePolicyBlocked(t, status, body)
		require.Equal(t, before, x.callCount(), "neither denied call reaches the upstream")
	})

	t.Run("groups: a token caller outside the group is still not selected", func(t *testing.T) {
		status, body := callEcho(t, gatewayID, consumerID, marketing, x.exposed("echo"), "hi")
		requireEchoed(t, status, body, "echo", "hi")
	})

	t.Run("except_groups: the api key answers as it did before the rule", func(t *testing.T) {
		before := x.callCount()
		status, body := callEcho(t, gatewayID, consumerID, key, x.exposed("other"), "hi")
		requirePolicyBlocked(t, status, body)
		require.Equal(t, before, x.callCount(),
			"an api-key caller carries no groups, so it never fell in the exception and still does not")
	})

	t.Run("except_groups: the excepted group is still excepted", func(t *testing.T) {
		status, body := callEcho(t, gatewayID, consumerID, finance, x.exposed("other"), "hi")
		requireEchoed(t, status, body, "other", "hi")
	})
}

// The write path says out loud what the inert principal costs: a policy that
// narrows to groups and reaches a consumer admitting api keys gets a warning
// naming that consumer.
func TestMCPPolicyScope_GroupScopeWarnsAboutTheAPIKeyConsumer(t *testing.T) {
	gatewayID, consumerID, _, _, _, x, _ := setupScopedDualAuthConsumer(t, []string{"echo"}, []string{"echo"})
	payload := toolAllowlistMCPPolicyPayload(denyAllTools())
	payload["mcp_scope"] = withScope(toolScope(x.registryID, "echo"), map[string]any{"groups": []string{"Finanzas"}})
	policyID := CreatePolicy(t, gatewayID, payload)

	warnings := attachPolicyWarnings(t, gatewayID, consumerID, policyID)
	require.Contains(t, warnings,
		"policy narrows to groups but consumer "+consumerID+" accepts api-key auth: group checks do not apply to those callers",
		"attaching a group-scoped policy to a consumer that admits api keys must name it")
}

// attachPolicyWarnings attaches and returns the warnings the attach answered
// with. AttachPolicy asserts the 204 of the no-warning case; a group-scoped
// policy on a consumer that admits api keys is warned about, so the same
// endpoint answers 200 with a body, and both are the documented contract.
func attachPolicyWarnings(t *testing.T, gatewayID, consumerID, policyID string) []string {
	t.Helper()
	url := fmt.Sprintf("%s/v1/gateways/%s/consumers/%s/policies/%s",
		AdminURL, gatewayID, consumerID, policyID)
	status, body := sendRequest(t, http.MethodPost, url, nil, nil)
	require.Contains(t, []int{http.StatusOK, http.StatusNoContent}, status,
		"attach policy failed: %v", body)
	raw, _ := body["warnings"].([]any)
	out := make([]string, 0, len(raw))
	for _, w := range raw {
		if text, ok := w.(string); ok {
			out = append(out, text)
		}
	}
	return out
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

// createOAuthMCPConsumer binds the registries to an MCP consumer whose only
// credential is a bearer token from stub, and returns the consumer and the
// audience its tokens must carry. createMCPConsumer attaches an API key
// instead, and an API key carries no groups, so a policy scoped by group can
// never match a caller created that way.
func createOAuthMCPConsumer(
	t *testing.T,
	gatewayID string,
	registryIDs []string,
	stub *oauthIDPStub,
) (consumerID, audience string) {
	t.Helper()
	audience = "mcp-" + strings.ToLower(uniqueName("aud"))
	authID := CreateAuth(t, gatewayID, oauth2AuthPayload(
		uniqueName("idp"), stub.issuer, stub.jwksURL(), audience,
		"client-"+strings.ToLower(uniqueName("c")), idpStubScope))
	bindings := make([]map[string]any, 0, len(registryIDs))
	for _, id := range registryIDs {
		bindings = append(bindings, map[string]any{"id": id})
	}
	consumerID = CreateConsumer(t, gatewayID, map[string]any{
		"name":       uniqueName("mcp-consumer"),
		"type":       "mcp",
		"registries": bindings,
	})
	AttachAuth(t, gatewayID, consumerID, authID)
	return consumerID, audience
}

// setupScopedOAuthConsumer is setupMCPPluginChainTwoUpstreams for a consumer
// that authenticates with bearer tokens, so each call can present a different
// identity to the same consumer.
func setupScopedOAuthConsumer(
	t *testing.T,
	toolsX, toolsY []string,
) (gatewayID, consumerID, audience string, stub *oauthIDPStub, x, y *scopedUpstream) {
	t.Helper()
	gatewayID = CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	x = startScopedUpstream(t, gatewayID, toolsX...)
	y = startScopedUpstream(t, gatewayID, toolsY...)
	stub = newOAuthIDPStub(t)
	consumerID, audience = createOAuthMCPConsumer(t, gatewayID, []string{x.registryID, y.registryID}, stub)
	return gatewayID, consumerID, audience, stub, x, y
}

// Two tools of one registry scoped to two different groups: each policy runs
// for its own group and spares the other, so the principal is read per
// destination and not once for the registry.
func TestMCPPolicyScope_ToolScopedGroupPoliciesSelectTheirOwnGroup(t *testing.T) {
	gatewayID, consumerID, audience, stub, x, _ := setupScopedOAuthConsumer(t,
		[]string{"echo", "other"}, []string{"echo"})
	attachScopedPolicy(t, gatewayID, consumerID, toolAllowlistMCPPolicyPayload(denyAllTools()),
		withScope(toolScope(x.registryID, "echo"), map[string]any{"groups": []string{"Finanzas"}}))
	attachScopedPolicy(t, gatewayID, consumerID, toolAllowlistMCPPolicyPayload(denyAllTools()),
		withScope(toolScope(x.registryID, "other"), map[string]any{"groups": []string{"Marketing"}}))

	finance := bearerHeaders(stub.mint(t, audience, map[string]any{
		"sub": "fin-subject", "groups": []string{"Finanzas"}}))
	marketing := bearerHeaders(stub.mint(t, audience, map[string]any{
		"sub": "mkt-subject", "groups": []string{"Marketing"}}))

	t.Run("the group the policy names is denied", func(t *testing.T) {
		before := x.callCount()
		status, body := callEcho(t, gatewayID, consumerID, finance, x.exposed("echo"), "hi")
		requirePolicyBlocked(t, status, body)
		require.Equal(t, before, x.callCount(), "the denied call must not reach the upstream")
	})

	t.Run("another group keeps the tool", func(t *testing.T) {
		status, body := callEcho(t, gatewayID, consumerID, marketing, x.exposed("echo"), "hi")
		requireEchoed(t, status, body, "echo", "hi")
	})

	t.Run("the other tool denies the group it names", func(t *testing.T) {
		before := x.callCount()
		status, body := callEcho(t, gatewayID, consumerID, marketing, x.exposed("other"), "hi")
		requirePolicyBlocked(t, status, body)
		require.Equal(t, before, x.callCount())
	})

	t.Run("and that policy spares the other group", func(t *testing.T) {
		status, body := callEcho(t, gatewayID, consumerID, finance, x.exposed("other"), "hi")
		requireEchoed(t, status, body, "other", "hi")
	})
}

// A policy naming groups runs for members of those groups, on the destination
// it scopes and nowhere else.
func TestMCPPolicyScope_GroupScopedPolicySelectsMembers(t *testing.T) {
	gatewayID, consumerID, audience, stub, x, y := setupScopedOAuthConsumer(t,
		[]string{"echo"}, []string{"echo"})
	attachScopedPolicy(t, gatewayID, consumerID, toolAllowlistMCPPolicyPayload(denyAllTools()),
		withScope(registryScope(x.registryID), map[string]any{"groups": []string{"Finanzas"}}))

	finance := bearerHeaders(stub.mint(t, audience, map[string]any{
		"sub": "fin-subject", "groups": []string{"Finanzas"}}))
	marketing := bearerHeaders(stub.mint(t, audience, map[string]any{
		"sub": "mkt-subject", "groups": []string{"Marketing"}}))

	t.Run("a member is denied on the scoped registry", func(t *testing.T) {
		status, body := callEcho(t, gatewayID, consumerID, finance, x.exposed("echo"), "hi")
		requirePolicyBlocked(t, status, body)
		require.Zero(t, x.callCount(), "the denied call must not reach the upstream")
	})

	t.Run("a member of another group is not", func(t *testing.T) {
		status, body := callEcho(t, gatewayID, consumerID, marketing, x.exposed("echo"), "hi")
		requireEchoed(t, status, body, "echo", "hi")
	})

	t.Run("the member keeps every registry the policy does not scope", func(t *testing.T) {
		status, body := callEcho(t, gatewayID, consumerID, finance, y.exposed("echo"), "hi")
		requireEchoed(t, status, body, "echo", "hi")
	})
}

// "only Finanzas may call this tool" is a deny-all scoped with except_groups:
// members fall out of the plan and the call proceeds, everyone else is denied.
// This is the pattern docs/mcp-policy-scope.md documents as the deny primitive.
func TestMCPPolicyScope_ExceptGroupsExemptsMembersAndDeniesTheRest(t *testing.T) {
	gatewayID, consumerID, audience, stub, x, _ := setupScopedOAuthConsumer(t,
		[]string{"echo"}, []string{"echo"})
	attachScopedPolicy(t, gatewayID, consumerID, toolAllowlistMCPPolicyPayload(denyAllTools()),
		withScope(toolScope(x.registryID, "echo"), map[string]any{"except_groups": []string{"Finanzas"}}))

	finance := bearerHeaders(stub.mint(t, audience, map[string]any{
		"sub": "fin-subject", "groups": []string{"Finanzas"}}))
	marketing := bearerHeaders(stub.mint(t, audience, map[string]any{
		"sub": "mkt-subject", "groups": []string{"Marketing"}}))
	groupless := bearerHeaders(stub.mint(t, audience, map[string]any{"sub": "none-subject"}))

	t.Run("a member of the excepted group may call the tool", func(t *testing.T) {
		status, body := callEcho(t, gatewayID, consumerID, finance, x.exposed("echo"), "hi")
		requireEchoed(t, status, body, "echo", "hi")
	})

	t.Run("a member of another group may not", func(t *testing.T) {
		before := x.callCount()
		status, body := callEcho(t, gatewayID, consumerID, marketing, x.exposed("echo"), "hi")
		requirePolicyBlocked(t, status, body)
		require.Equal(t, before, x.callCount(), "the denied call must not reach the upstream")
	})

	t.Run("a caller carrying no groups claim may not either", func(t *testing.T) {
		before := x.callCount()
		status, body := callEcho(t, gatewayID, consumerID, groupless, x.exposed("echo"), "hi")
		requirePolicyBlocked(t, status, body)
		require.Equal(t, before, x.callCount())
	})
}

// A scope with a principal and no destination is the one plan shape that is
// not precompiled per destination: it is filtered against the caller on every
// tools/call, so it must reach every registry of the consumer.
func TestMCPPolicyScope_PrincipalOnlyScopeCoversEveryRegistry(t *testing.T) {
	gatewayID, consumerID, audience, stub, x, y := setupScopedOAuthConsumer(t,
		[]string{"echo"}, []string{"echo"})
	attachScopedPolicy(t, gatewayID, consumerID, toolAllowlistMCPPolicyPayload(denyAllTools()),
		map[string]any{"groups": []string{"Finanzas"}})

	finance := bearerHeaders(stub.mint(t, audience, map[string]any{
		"sub": "fin-subject", "groups": []string{"Finanzas"}}))
	marketing := bearerHeaders(stub.mint(t, audience, map[string]any{
		"sub": "mkt-subject", "groups": []string{"Marketing"}}))

	t.Run("the named group is denied on every registry", func(t *testing.T) {
		for _, up := range []*scopedUpstream{x, y} {
			status, body := callEcho(t, gatewayID, consumerID, finance, up.exposed("echo"), "hi")
			requirePolicyBlocked(t, status, body)
		}
		require.Zero(t, x.callCount())
		require.Zero(t, y.callCount())
	})

	t.Run("every other caller keeps every registry", func(t *testing.T) {
		for _, up := range []*scopedUpstream{x, y} {
			status, body := callEcho(t, gatewayID, consumerID, marketing, up.exposed("echo"), "hi")
			requireEchoed(t, status, body, "echo", "hi")
		}
	})
}

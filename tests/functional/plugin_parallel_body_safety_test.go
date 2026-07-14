//go:build functional

package functional_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This suite locks the single-writer / capability-aware batching invariant the
// plugin executor enforces (RUN-713) end-to-end through the proxy plane. The
// data plane must guarantee that, no matter how policies are flagged, every
// request-body mutation survives to the upstream:
//
//   - two request-body mutators flagged parallel at the SAME priority must NOT
//     lose an update: the planner demotes them to back-to-back single-mutator
//     blocks and folds each transformed body into the next (no shallow-copy
//     lost update, no last-writer-wins).
//   - a request-body mutator flagged parallel alongside a NON-mutator at the
//     same priority still runs as a genuine concurrent batch (at most one body
//     mutator per batch is allowed), and both effects survive.
//   - request-body mutators placed in DISTINCT priority blocks fold in order:
//     each block starts from the previous block's transformed body, so an
//     earlier block's mutation is visible to (and preserved past) a later one.
//
// model_allowlist (substitute) rewrites the "model" field and tool_allowlist
// (deny) strips disallowed tools: their effects are on disjoint fields, so the
// forwarded upstream body deterministically reveals whether BOTH ran.

// chatRequestModelWithTools builds an OpenAI chat body carrying both an explicit
// model and a tools array, so a model-body mutator and a tools-body mutator can
// each act on a disjoint field of the same request.
func chatRequestModelWithTools(model string, tools ...string) map[string]any {
	body := chatRequestWithTools(tools...)
	body["model"] = model
	return body
}

// substituteModelSettings rewrites any model outside allow to replacement.
func substituteModelSettings(allow, replacement string) map[string]any {
	return map[string]any{
		"allowed_models":         []string{allow},
		"behavior_on_disallowed": "substitute",
		"substitute_with":        replacement,
	}
}

// denyToolsSettings strips every tool matching pattern from the request body.
func denyToolsSettings(pattern string) map[string]any {
	return map[string]any{"deny_tools": []string{pattern}}
}

// Two request-body mutators flagged parallel at the SAME priority must both
// reach the upstream. Pre-RUN-713, the executor isolated each plugin over a
// shallow request copy that shared the body slice and never merged the body
// back, so one mutation was silently lost; even with Result-returned bodies the
// last writer in the batch won. The planner now caps a parallel batch at one
// mutator per kind, demoting these two to ordered single-mutator blocks and
// folding both transformed bodies. Both the substituted model and the filtered
// tools must therefore survive.
func TestPolicyE2E_ParallelRequestBodyMutatorsBothSurvive(t *testing.T) {
	defer Track(t, "ParallelBodySafety")()

	up := newJSONUpstream(t, "parallel-mutators")
	gatewayID, backendID := setupGatewayBackend(t, up)
	model := createScopedPolicy(t, gatewayID, "model_allowlist",
		substituteModelSettings("gpt-5*", "gpt-5"), 0, true)
	tools := createScopedPolicy(t, gatewayID, "tool_allowlist",
		denyToolsSettings("delete_*"), 0, true)
	path, apiKey := addConsumerRoute(t, gatewayID, backendID, model, tools)

	body := mustJSON(t, chatRequestModelWithTools("claude-opus-4-5", "search_web", "delete_db"))

	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	require.Equal(t, http.StatusOK, status, "body: %s", raw)
	require.Equal(t, 1, up.Hits())

	forwarded := up.LastBody()
	assert.Contains(t, string(forwarded), `"model":"gpt-5"`,
		"the model-body mutation must survive the parallel batch")
	assert.NotContains(t, string(forwarded), "claude-opus-4-5",
		"the original disallowed model must not reach the upstream")
	assert.Equal(t, []string{"search_web"}, forwardedToolNames(t, forwarded),
		"the tools-body mutation must survive the SAME parallel batch (no lost update)")
}

// A request-body mutator flagged parallel alongside a non-mutator at the same
// priority is allowed to stay a real concurrent batch (one body mutator per
// batch is fine). rate_limiter only contributes response headers, model_allowlist
// only rewrites the request body, so they run together and BOTH effects survive.
func TestPolicyE2E_RequestBodyMutatorParallelWithNonMutator(t *testing.T) {
	defer Track(t, "ParallelBodySafety")()

	up := newJSONUpstream(t, "mutator-with-nonmutator")
	gatewayID, backendID := setupGatewayBackend(t, up)
	model := createScopedPolicy(t, gatewayID, "model_allowlist",
		substituteModelSettings("gpt-5*", "gpt-5"), 0, true)
	rl := createScopedPolicy(t, gatewayID, "rate_limiter", rateLimitSettings(100), 0, true)
	path, apiKey := addConsumerRoute(t, gatewayID, backendID, model, rl)

	body := mustJSON(t, chatRequestModel("claude-opus-4-5"))

	status, headers, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	require.Equal(t, http.StatusOK, status, "body: %s", raw)
	require.Equal(t, 1, up.Hits())

	assert.Equal(t, "100", headers.Get("X-RateLimit-consumer-Limit"),
		"the non-mutator's parallel response header must survive")
	assert.Contains(t, string(up.LastBody()), `"model":"gpt-5"`,
		"the body mutator must still rewrite the request when batched with a non-mutator")
}

// Request-body mutators placed in distinct priority blocks must fold in order:
// the later (higher-priority value) block has to start from the body the
// earlier block produced. If the executor did not thread each block's
// transformed body into the next, one of the two disjoint mutations would be
// lost. Both must reach the upstream.
func TestPolicyE2E_RequestBodyMutatorsFoldAcrossPriorityBlocks(t *testing.T) {
	defer Track(t, "ParallelBodySafety")()

	up := newJSONUpstream(t, "priority-fold")
	gatewayID, backendID := setupGatewayBackend(t, up)
	// Distinct priorities land the two mutators in separate ordered blocks.
	tools := createScopedPolicy(t, gatewayID, "tool_allowlist",
		denyToolsSettings("delete_*"), 1, true)
	model := createScopedPolicy(t, gatewayID, "model_allowlist",
		substituteModelSettings("gpt-5*", "gpt-5"), 2, true)
	path, apiKey := addConsumerRoute(t, gatewayID, backendID, tools, model)

	body := mustJSON(t, chatRequestModelWithTools("claude-opus-4-5", "search_web", "delete_db"))

	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	require.Equal(t, http.StatusOK, status, "body: %s", raw)
	require.Equal(t, 1, up.Hits())

	forwarded := up.LastBody()
	assert.Equal(t, []string{"search_web"}, forwardedToolNames(t, forwarded),
		"the priority-1 block's tools mutation must be preserved into the priority-2 block")
	assert.Contains(t, string(forwarded), `"model":"gpt-5"`,
		"the priority-2 block's model mutation must fold on top of the priority-1 block's body")
	assert.NotContains(t, string(forwarded), "claude-opus-4-5",
		"the original disallowed model must not reach the upstream")
}

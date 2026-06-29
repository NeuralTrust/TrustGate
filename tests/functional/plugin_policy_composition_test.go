//go:build functional

package functional_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This suite exercises the plugin executor / stage-plan / policy-composition
// machinery end-to-end through the proxy plane. It covers the full matrix the
// data plane has to get right:
//
//   - gateway-global policies vs consumer-scoped policies
//   - composition of both levels (different slugs) and slug override (same slug)
//   - sequential ordering with short-circuit
//   - parallel batches (executor isolation + header merge-back)
//   - cross-stage plugins (pre_request gate fed by post_response accrual)
//
// All assertions are deterministic: every scenario is fully wired before the
// first proxy request, so the proxy loads a fresh consumer-data aggregate (with
// its precomputed StagePlan) on the first hit and no cache-invalidation timing
// is involved.

// ---- payload builders -------------------------------------------------------

// rateLimitSettings configures the rate_limiter plugin with a single sliding
// window over 1 minute, rejecting with 429 + Retry-After once exceeded. Whether
// the limit is gateway-wide or per consumer is decided by the policy scope.
func rateLimitSettings(limit int) map[string]any {
	return map[string]any{
		"limit":       limit,
		"window":      "1m",
		"retry_after": "30",
	}
}

// requestSizeSettings rejects bodies larger than maxBytes.
func requestSizeSettings(maxBytes int) map[string]any {
	return map[string]any{
		"allowed_payload_size": maxBytes,
		"size_unit":            "bytes",
	}
}

// corsSimpleSettings allows a single origin so a success request carries the
// CORS allow-origin header and a foreign origin is rejected with 403.
func corsSimpleSettings() map[string]any {
	return map[string]any{
		"allowed_origins": []string{"https://allowed.com"},
		"allowed_methods": []string{"GET", "POST"},
	}
}

// ---- admin-plane helpers ----------------------------------------------------

// policyPayload builds a single-plugin policy body with explicit priority and
// parallel flags so tests can shape the executor chain precisely.
func policyPayload(slug string, settings map[string]any, priority int, parallel bool) map[string]any {
	return map[string]any{
		"name":     uniqueName(slug),
		"slug":     slug,
		"enabled":  true,
		"priority": priority,
		"parallel": parallel,
		"settings": settings,
	}
}

// createScopedPolicy creates a consumer-scoped (non-global) policy and returns
// its id.
func createScopedPolicy(t *testing.T, gatewayID, slug string, settings map[string]any, priority int, parallel bool) string {
	t.Helper()
	return CreatePolicy(t, gatewayID, policyPayload(slug, settings, priority, parallel))
}

// createGlobalPolicy creates a policy and promotes it to gateway-wide scope.
func createGlobalPolicy(t *testing.T, gatewayID, slug string, settings map[string]any) string {
	t.Helper()
	id := CreatePolicy(t, gatewayID, policyPayload(slug, settings, 0, false))
	SetPolicyGlobal(t, gatewayID, id)
	return id
}

// setupGatewayBackend creates a gateway and one OpenAI-compatible backend
// pointing at up, returning both ids.
func setupGatewayBackend(t *testing.T, up *fakeUpstream) (string, string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("pol-gw")})
	backendID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be"), up.URL()))
	return gatewayID, backendID
}

// addConsumerRoute creates a consumer, attaches the backend, any policies and a
// fresh api_key credential, and returns its fixed chat-completions route
// together with that credential's key (to authenticate at the proxy plane).
func addConsumerRoute(t *testing.T, gatewayID, backendID string, policyIDs ...string) (string, string) {
	t.Helper()
	name := uniqueName("cons")
	coID := CreateConsumerWithRegistries(t, gatewayID, name, backendID)
	for _, pid := range policyIDs {
		AttachPolicy(t, gatewayID, coID, pid)
	}
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	return chatCompletionsPath(t, coID), apiKey
}

// ---- global policies --------------------------------------------------------

// A gateway-global policy must apply to a consumer that has no policies of its
// own: scope is resolved at composition time, not by attachment.
func TestPolicyE2E_GlobalAppliesToConsumerWithoutPolicies(t *testing.T) {
	defer Track(t, "PolicyComposition")()

	up := newJSONUpstream(t, "global-no-policy")
	gatewayID, backendID := setupGatewayBackend(t, up)
	createGlobalPolicy(t, gatewayID, "rate_limiter", rateLimitSettings(2))
	path, apiKey := addConsumerRoute(t, gatewayID, backendID) // no consumer-scoped policies

	body := mustJSON(t, chatRequest(false))
	for i := 1; i <= 2; i++ {
		status, headers, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
		require.Equal(t, http.StatusOK, status, "request %d should pass, body: %s", i, raw)
		assert.Equal(t, "2", headers.Get("X-RateLimit-global-Limit"))
	}
	status, _, _ := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	assert.Equal(t, http.StatusTooManyRequests, status, "the global limit must reject the 3rd request")
	assert.Equal(t, 2, up.Hits(), "rejected requests must not reach the upstream")
}

// A single gateway-global policy is shared by every consumer of the gateway: a
// global rate limit is enforced across consumers (one shared counter).
func TestPolicyE2E_GlobalAppliesAcrossConsumers(t *testing.T) {
	defer Track(t, "PolicyComposition")()

	up := newJSONUpstream(t, "global-shared")
	gatewayID, backendID := setupGatewayBackend(t, up)
	createGlobalPolicy(t, gatewayID, "rate_limiter", rateLimitSettings(2))
	pathA, keyA := addConsumerRoute(t, gatewayID, backendID)
	pathB, keyB := addConsumerRoute(t, gatewayID, backendID)

	body := mustJSON(t, chatRequest(false))

	statusA, _, _ := proxyRequest(t, http.MethodPost, keyA, pathA, nil, body)
	require.Equal(t, http.StatusOK, statusA, "consumer A first request should pass")
	statusB, _, _ := proxyRequest(t, http.MethodPost, keyB, pathB, nil, body)
	require.Equal(t, http.StatusOK, statusB, "consumer B first request should pass")

	// The global budget (2) is now exhausted across both consumers.
	statusA2, _, _ := proxyRequest(t, http.MethodPost, keyA, pathA, nil, body)
	assert.Equal(t, http.StatusTooManyRequests, statusA2,
		"the global counter is shared, so the 3rd request (any consumer) is rejected")
}

// ---- consumer-scoped isolation ----------------------------------------------

// A consumer-scoped policy must only affect the consumer it is attached to; a
// sibling consumer in the same gateway is unaffected.
func TestPolicyE2E_ConsumerScopedIsIsolated(t *testing.T) {
	defer Track(t, "PolicyComposition")()

	up := newJSONUpstream(t, "scoped-isolation")
	gatewayID, backendID := setupGatewayBackend(t, up)
	limited := createScopedPolicy(t, gatewayID, "rate_limiter", rateLimitSettings(2), 0, false)
	pathLimited, keyLimited := addConsumerRoute(t, gatewayID, backendID, limited)
	pathFree, keyFree := addConsumerRoute(t, gatewayID, backendID) // no policies

	body := mustJSON(t, chatRequest(false))

	// The unguarded consumer is never limited.
	for i := 1; i <= 5; i++ {
		status, _, raw := proxyRequest(t, http.MethodPost, keyFree, pathFree, nil, body)
		require.Equal(t, http.StatusOK, status, "free consumer request %d must pass, body: %s", i, raw)
	}
	// The guarded consumer is limited at its own budget.
	for i := 1; i <= 2; i++ {
		status, _, _ := proxyRequest(t, http.MethodPost, keyLimited, pathLimited, nil, body)
		require.Equal(t, http.StatusOK, status, "limited consumer request %d should pass", i)
	}
	status, _, _ := proxyRequest(t, http.MethodPost, keyLimited, pathLimited, nil, body)
	assert.Equal(t, http.StatusTooManyRequests, status, "the consumer-scoped limit must reject the 3rd request")
}

// ---- composition: global + consumer, different slugs ------------------------

// A global policy and a consumer-scoped policy with different slugs must both
// run for the consumer: the chain composes both levels.
func TestPolicyE2E_GlobalAndConsumerComposeDifferentSlugs(t *testing.T) {
	defer Track(t, "PolicyComposition")()

	up := newJSONUpstream(t, "compose-different")
	gatewayID, backendID := setupGatewayBackend(t, up)
	createGlobalPolicy(t, gatewayID, "cors", corsSimpleSettings())
	rl := createScopedPolicy(t, gatewayID, "rate_limiter", rateLimitSettings(2), 10, false)
	path, apiKey := addConsumerRoute(t, gatewayID, backendID, rl)

	body := mustJSON(t, chatRequest(false))
	allowed := map[string]string{"Origin": "https://allowed.com"}

	// Both ran: CORS contributed the allow-origin header (global) and the rate
	// limiter contributed its quota header (consumer-scoped).
	status, headers, raw := proxyRequest(t, http.MethodPost, apiKey, path, allowed, body)
	require.Equal(t, http.StatusOK, status, "body: %s", raw)
	assert.Equal(t, "https://allowed.com", headers.Get("Access-Control-Allow-Origin"), "global CORS must run")
	assert.Equal(t, "2", headers.Get("X-RateLimit-consumer-Limit"), "consumer rate limiter must run")

	// The global CORS rejection still fires for a foreign origin.
	statusBad, _, _ := proxyRequest(t, http.MethodPost, apiKey, path,
		map[string]string{"Origin": "https://evil.com"}, body)
	assert.Equal(t, http.StatusForbidden, statusBad, "global CORS must reject a disallowed origin")

	// And the consumer rate limit still enforces (1 budget left after the first OK).
	status2, _, _ := proxyRequest(t, http.MethodPost, apiKey, path, allowed, body)
	require.Equal(t, http.StatusOK, status2)
	status3, _, _ := proxyRequest(t, http.MethodPost, apiKey, path, allowed, body)
	assert.Equal(t, http.StatusTooManyRequests, status3, "consumer rate limit must reject after its budget")
}

// ---- composition: slug override (same slug) ---------------------------------

// When a consumer-scoped policy shares a slug with a global one, the
// consumer-scoped policy WINS and the global is dropped (composePolicies). With
// a permissive consumer limit (100) over a strict global limit (2), the consumer
// must NOT be limited at the global threshold.
func TestPolicyE2E_ConsumerOverridesGlobalBySlug(t *testing.T) {
	defer Track(t, "PolicyComposition")()

	up := newJSONUpstream(t, "override")
	gatewayID, backendID := setupGatewayBackend(t, up)
	createGlobalPolicy(t, gatewayID, "rate_limiter", rateLimitSettings(2))                       // strict global
	scoped := createScopedPolicy(t, gatewayID, "rate_limiter", rateLimitSettings(100), 0, false) // permissive override
	path, apiKey := addConsumerRoute(t, gatewayID, backendID, scoped)

	body := mustJSON(t, chatRequest(false))
	for i := 1; i <= 3; i++ {
		status, headers, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
		require.Equal(t, http.StatusOK, status,
			"request %d must pass: the permissive consumer policy overrides the strict global one, body: %s", i, raw)
		// The applied limit is the consumer's (100), proving the global was dropped.
		assert.Equal(t, "100", headers.Get("X-RateLimit-consumer-Limit"))
	}
	assert.Equal(t, 3, up.Hits())
}

// ---- sequential ordering + short-circuit ------------------------------------

// Two sequential pre_request plugins ordered by priority: the lower-priority
// request-size limiter runs first and short-circuits an oversized request, so
// the higher-priority rate limiter never records it. A later small request thus
// still has its full budget.
func TestPolicyE2E_SequentialShortCircuitSkipsLaterPlugin(t *testing.T) {
	defer Track(t, "PolicyComposition")()

	up := newJSONUpstream(t, "sequential")
	gatewayID, backendID := setupGatewayBackend(t, up)
	// priority 1 runs before priority 2; neither is parallel.
	size := createScopedPolicy(t, gatewayID, "request_size_limiter", requestSizeSettings(1000), 1, false)
	rl := createScopedPolicy(t, gatewayID, "rate_limiter", rateLimitSettings(1), 2, false)
	path, apiKey := addConsumerRoute(t, gatewayID, backendID, size, rl)

	oversized := mustJSON(t, map[string]any{
		"model":    "gpt-4o-mini",
		"messages": []map[string]string{{"role": "user", "content": strings.Repeat("a", 4000)}},
	})
	small := mustJSON(t, chatRequest(false))

	// Oversized requests are rejected by the size limiter (runs first) and must
	// not consume the rate-limiter budget.
	for i := 0; i < 2; i++ {
		status, _, _ := proxyRequest(t, http.MethodPost, apiKey, path, nil, oversized)
		require.Equal(t, http.StatusRequestEntityTooLarge, status, "oversized request %d must be rejected", i)
	}
	assert.Equal(t, 0, up.Hits(), "no oversized request may reach the upstream")

	// The rate budget (1) is intact: the first small request passes, the second
	// is limited. If the size limiter had not short-circuited first, the budget
	// would already be exhausted by the rejected requests.
	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, small)
	require.Equal(t, http.StatusOK, status, "first small request should pass, body: %s", raw)
	status2, _, _ := proxyRequest(t, http.MethodPost, apiKey, path, nil, small)
	assert.Equal(t, http.StatusTooManyRequests, status2, "rate budget is 1, so the second small request is limited")
}

// ---- parallel batches -------------------------------------------------------

// Two plugins flagged parallel with the same priority run as a concurrent
// batch. The executor isolates each plugin's request/response and merges the
// mutations back, so BOTH plugins' response headers must survive on a success.
func TestPolicyE2E_ParallelBatchBothApply(t *testing.T) {
	defer Track(t, "PolicyComposition")()

	up := newJSONUpstream(t, "parallel")
	gatewayID, backendID := setupGatewayBackend(t, up)
	cors := createScopedPolicy(t, gatewayID, "cors", corsSimpleSettings(), 0, true)
	rl := createScopedPolicy(t, gatewayID, "rate_limiter", rateLimitSettings(2), 0, true)
	path, apiKey := addConsumerRoute(t, gatewayID, backendID, cors, rl)

	body := mustJSON(t, chatRequest(false))
	allowed := map[string]string{"Origin": "https://allowed.com"}

	// Both parallel plugins ran and both header sets were merged back into the
	// shared response (exercises the executor's per-plugin isolation + merge).
	status, headers, raw := proxyRequest(t, http.MethodPost, apiKey, path, allowed, body)
	require.Equal(t, http.StatusOK, status, "body: %s", raw)
	assert.Equal(t, "https://allowed.com", headers.Get("Access-Control-Allow-Origin"), "parallel CORS header must survive")
	assert.Equal(t, "2", headers.Get("X-RateLimit-consumer-Limit"), "parallel rate-limiter header must survive")

	// A rejection from any plugin in the parallel batch still short-circuits.
	statusBad, _, _ := proxyRequest(t, http.MethodPost, apiKey, path,
		map[string]string{"Origin": "https://evil.com"}, body)
	assert.Equal(t, http.StatusForbidden, statusBad, "a parallel CORS rejection must short-circuit")
}

// ---- multi-stage plugin in the chain ----------------------------------------

// token_rate_limiter is a multi-stage plugin: the plan schedules it on both
// pre_request and post_response. It must coexist in the same consumer chain with
// a pre_request-only plugin (rate_limiter) without breaking traffic, while the
// pre_request limiter still gates deterministically. This exercises a plan that
// fans a single policy across multiple stages alongside a single-stage policy.
func TestPolicyE2E_MultiStagePluginComposesWithPreRequest(t *testing.T) {
	defer Track(t, "PolicyComposition")()

	up := newUsageUpstream(t, "multi-stage", 8)
	gatewayID, backendID := setupGatewayBackend(t, up)
	tok := createScopedPolicy(t, gatewayID, "token_rate_limiter",
		map[string]any{"window": map[string]any{"unit": "minute", "max": 1000}}, 5, false)
	rl := createScopedPolicy(t, gatewayID, "rate_limiter", rateLimitSettings(2), 10, false)
	path, apiKey := addConsumerRoute(t, gatewayID, backendID, tok, rl)

	body := mustJSON(t, chatRequest(false))
	for i := 1; i <= 2; i++ {
		status, headers, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
		require.Equal(t, http.StatusOK, status, "request %d should pass, body: %s", i, raw)
		assert.Equal(t, "2", headers.Get("X-RateLimit-consumer-Limit"),
			"the pre_request rate limiter must run alongside the multi-stage token limiter")
	}
	status, _, _ := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	assert.Equal(t, http.StatusTooManyRequests, status,
		"the pre_request rate limiter must gate the 3rd request even with a multi-stage plugin present")
	assert.Equal(t, 2, up.Hits())
}

// ---- cross-stage enforcement ------------------------------------------------

// token_rate_limiter records consumed tokens at post_response and gates at
// pre_request. A response that consumes more tokens than the window budget must,
// once its async post_response recording lands, cause the next request to be
// rejected at pre_request. This proves cross-stage state flows through the plan:
// the post_response side feeds the pre_request side on the following request.
func TestPolicyE2E_CrossStageTokenBudgetGatesNextRequest(t *testing.T) {
	defer Track(t, "PolicyComposition")()

	const budget = 5
	up := newUsageUpstream(t, "cross-stage", 8) // each response consumes 8 > budget
	gatewayID, backendID := setupGatewayBackend(t, up)
	tok := createScopedPolicy(t, gatewayID, "token_rate_limiter",
		map[string]any{"window": map[string]any{"unit": "minute", "max": budget}}, 0, false)
	path, apiKey := addConsumerRoute(t, gatewayID, backendID, tok)

	body := mustJSON(t, chatRequest(false))

	// The first request passes the gate (no tokens consumed yet).
	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	require.Equal(t, http.StatusOK, status, "first request should pass, body: %s", raw)

	// post_response recording is asynchronous; once it lands, the pre_request
	// gate rejects subsequent requests. Poll until the budget bites.
	require.Eventually(t, func() bool {
		s, _, _ := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
		return s == http.StatusTooManyRequests
	}, 5*time.Second, 100*time.Millisecond,
		"the token budget must eventually gate further requests once post_response accrual lands")
}

//go:build functional

package functional_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPluginE2E_TokenRateLimiter verifies the token budget limiter is wired into
// the proxy and lets legitimate chat traffic through. Enforcement records the
// tokens a response consumed at PostResponse; the PreRequest check keys off the
// request provider, so a route guarded by the limiter must not break normal
// provider traffic.
func TestPluginE2E_TokenRateLimiter(t *testing.T) {
	defer Track(t, "PluginTokenRateLimiter")()

	up := newUsageUpstream(t, "token-upstream", 8)
	apiKey, path := setupPolicyRoute(t, up,
		policyPlugin("token_rate_limiter", map[string]any{
			"window": map[string]any{"unit": "minute", "max": 100},
		}),
	)

	body := mustJSON(t, chatRequest(false))
	for i := 0; i < 5; i++ {
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
		require.Equal(t, http.StatusOK, status, "request %d should pass through, body: %s", i, raw)
	}
	assert.Equal(t, 5, up.Hits())
}

// A global token_rate_limiter shares one budget across every consumer of the
// gateway: tokens consumed by one consumer must, once the async post_response
// accrual lands, gate a different consumer that never consumed tokens itself.
func TestPluginE2E_TokenRateLimiter_GlobalSharedAcrossConsumers(t *testing.T) {
	defer Track(t, "PluginTokenRateLimiter")()

	const budget = 5
	up := newUsageUpstream(t, "token-global", 8) // each response consumes 8 > budget
	gatewayID, backendID := setupGatewayBackend(t, up)
	createGlobalPolicy(t, gatewayID, "token_rate_limiter",
		map[string]any{"window": map[string]any{"unit": "minute", "max": budget}})
	pathA, keyA := addConsumerRoute(t, gatewayID, backendID)
	pathB, keyB := addConsumerRoute(t, gatewayID, backendID)

	body := mustJSON(t, chatRequest(false))

	// Consumer A consumes the shared global budget.
	statusA, _, raw := proxyRequest(t, http.MethodPost, keyA, pathA, nil, body)
	require.Equal(t, http.StatusOK, statusA, "consumer A first request should pass, body: %s", raw)

	// Consumer B never consumed tokens, but the shared global counter must gate
	// it once A's post_response accrual lands.
	require.Eventually(t, func() bool {
		s, _, _ := proxyRequest(t, http.MethodPost, keyB, pathB, nil, body)
		return s == http.StatusTooManyRequests
	}, 5*time.Second, 100*time.Millisecond,
		"a global token budget must gate other consumers once consumer A's accrual lands")
}

// With group_by_header set, the token budget is counted per header value within
// the policy scope: one header value's budget must not gate another's.
func TestPluginE2E_TokenRateLimiter_GroupByHeader(t *testing.T) {
	defer Track(t, "PluginTokenRateLimiter")()

	const budget = 5
	up := newUsageUpstream(t, "token-group-header", 8) // each response consumes 8 > budget
	gatewayID, backendID := setupGatewayBackend(t, up)
	tok := createScopedPolicy(t, gatewayID, "token_rate_limiter", map[string]any{
		"window":          map[string]any{"unit": "minute", "max": budget},
		"group_by_header": "X-User-Id",
	}, 0, false)
	path, apiKey := addConsumerRoute(t, gatewayID, backendID, tok)

	body := mustJSON(t, chatRequest(false))
	user1 := map[string]string{"X-User-Id": "user-1"}

	// user-1 consumes its own budget.
	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, user1, body)
	require.Equal(t, http.StatusOK, status, "user-1 first request should pass, body: %s", raw)

	// Once user-1's accrual lands, user-1 is gated on its own bucket.
	require.Eventually(t, func() bool {
		s, _, _ := proxyRequest(t, http.MethodPost, apiKey, path, user1, body)
		return s == http.StatusTooManyRequests
	}, 5*time.Second, 100*time.Millisecond,
		"user-1's token budget must gate its own further requests")

	// A different header value keeps an independent budget on the same route.
	statusU2, _, raw := proxyRequest(t, http.MethodPost, apiKey, path,
		map[string]string{"X-User-Id": "user-2"}, body)
	require.Equal(t, http.StatusOK, statusU2, "a different header value must have its own budget, body: %s", raw)
}

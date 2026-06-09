//go:build functional

package functional_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A non-global rate_limiter policy partitions its budget per consumer: a single
// guarded route is limited at its own budget and rejects once exceeded.
func TestPluginE2E_RateLimiter_ConsumerScoped(t *testing.T) {
	defer Track(t, "PluginRateLimiter")()

	const limit = 5
	up := newJSONUpstream(t, "rl-upstream")
	apiKey, path := setupPolicyRoute(t, up,
		policyPlugin("rate_limiter", map[string]any{
			"limit":       limit,
			"window":      "1m",
			"retry_after": "60",
		}),
	)

	body := mustJSON(t, chatRequest(false))

	for i := 1; i <= limit; i++ {
		status, headers, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
		require.Equal(t, http.StatusOK, status, "request %d should be allowed, body: %s", i, raw)
		assert.Equal(t, "5", headers.Get("X-RateLimit-consumer-Limit"))
	}

	status, headers, _ := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	assert.Equal(t, http.StatusTooManyRequests, status, "request beyond the limit must be rejected")
	assert.Equal(t, "60", headers.Get("Retry-After"))
	assert.Equal(t, limit, up.Hits(), "rejected requests must not reach the upstream")
}

// A single non-global policy shared by two consumers must give each its own
// budget: exhausting one consumer must not affect the other.
func TestPluginE2E_RateLimiter_ConsumerIsolation(t *testing.T) {
	defer Track(t, "PluginRateLimiter")()

	up := newJSONUpstream(t, "rl-isolation")
	gatewayID, backendID := setupGatewayBackend(t, up)
	// One consumer-scoped policy (limit 2) attached to two distinct consumers.
	rl := createScopedPolicy(t, gatewayID, "rate_limiter", rateLimitSettings(2), 0, false)
	pathA, keyA := addConsumerRoute(t, gatewayID, backendID, rl)
	pathB, keyB := addConsumerRoute(t, gatewayID, backendID, rl)

	body := mustJSON(t, chatRequest(false))

	// Exhaust consumer A's budget (2 allowed, 3rd rejected).
	for i := 1; i <= 2; i++ {
		status, _, raw := proxyRequest(t, http.MethodPost, keyA, pathA, nil, body)
		require.Equal(t, http.StatusOK, status, "consumer A request %d should pass, body: %s", i, raw)
	}
	statusA, _, _ := proxyRequest(t, http.MethodPost, keyA, pathA, nil, body)
	require.Equal(t, http.StatusTooManyRequests, statusA, "consumer A must be limited at its own budget")

	// Consumer B shares the policy but keeps an independent budget.
	for i := 1; i <= 2; i++ {
		status, _, raw := proxyRequest(t, http.MethodPost, keyB, pathB, nil, body)
		require.Equal(t, http.StatusOK, status,
			"consumer B request %d must pass: a sibling consumer's usage must not count against it, body: %s", i, raw)
	}
}

// With group_by_header set, the budget is counted per header value within the
// consumer scope, so distinct header values get independent budgets.
func TestPluginE2E_RateLimiter_GroupByHeader(t *testing.T) {
	defer Track(t, "PluginRateLimiter")()

	const limit = 2
	up := newJSONUpstream(t, "rl-group-header")
	apiKey, path := setupPolicyRoute(t, up,
		policyPlugin("rate_limiter", map[string]any{
			"limit":           limit,
			"window":          "1m",
			"group_by_header": "X-User-Id",
		}),
	)

	body := mustJSON(t, chatRequest(false))

	for i := 1; i <= limit; i++ {
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, map[string]string{"X-User-Id": "user-1"}, body)
		require.Equal(t, http.StatusOK, status, "user-1 request %d should pass, body: %s", i, raw)
	}
	status, _, _ := proxyRequest(t, http.MethodPost, apiKey, path, map[string]string{"X-User-Id": "user-1"}, body)
	require.Equal(t, http.StatusTooManyRequests, status, "user-1 must be limited by its own header value")

	// A different header value keeps an independent budget on the same route.
	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, map[string]string{"X-User-Id": "user-2"}, body)
	require.Equal(t, http.StatusOK, status, "a different header value must not be limited, body: %s", raw)
}

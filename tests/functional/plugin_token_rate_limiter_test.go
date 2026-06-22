//go:build functional

package functional_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestPluginE2E_TokenRateLimiter_GlobalSharedAcrossConsumers(t *testing.T) {
	defer Track(t, "PluginTokenRateLimiter")()

	const budget = 5
	up := newUsageUpstream(t, "token-global", 8)
	gatewayID, backendID := setupGatewayBackend(t, up)
	createGlobalPolicy(t, gatewayID, "token_rate_limiter",
		map[string]any{"window": map[string]any{"unit": "minute", "max": budget}})
	pathA, keyA := addConsumerRoute(t, gatewayID, backendID)
	pathB, keyB := addConsumerRoute(t, gatewayID, backendID)

	body := mustJSON(t, chatRequest(false))

	statusA, _, raw := proxyRequest(t, http.MethodPost, keyA, pathA, nil, body)
	require.Equal(t, http.StatusOK, statusA, "consumer A first request should pass, body: %s", raw)

	require.Eventually(t, func() bool {
		s, _, _ := proxyRequest(t, http.MethodPost, keyB, pathB, nil, body)
		return s == http.StatusTooManyRequests
	}, 5*time.Second, 100*time.Millisecond,
		"a global token budget must gate other consumers once consumer A's accrual lands")
}

func TestPluginE2E_TokenRateLimiter_GroupByHeader(t *testing.T) {
	defer Track(t, "PluginTokenRateLimiter")()

	const budget = 5
	up := newUsageUpstream(t, "token-group-header", 8)
	gatewayID, backendID := setupGatewayBackend(t, up)
	tok := createScopedPolicy(t, gatewayID, "token_rate_limiter", map[string]any{
		"window":          map[string]any{"unit": "minute", "max": budget},
		"group_by_header": "X-User-Id",
	}, 0, false)
	path, apiKey := addConsumerRoute(t, gatewayID, backendID, tok)

	body := mustJSON(t, chatRequest(false))
	user1 := map[string]string{"X-User-Id": "user-1"}

	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, user1, body)
	require.Equal(t, http.StatusOK, status, "user-1 first request should pass, body: %s", raw)

	require.Eventually(t, func() bool {
		s, _, _ := proxyRequest(t, http.MethodPost, apiKey, path, user1, body)
		return s == http.StatusTooManyRequests
	}, 5*time.Second, 100*time.Millisecond,
		"user-1's token budget must gate its own further requests")

	statusU2, _, raw := proxyRequest(t, http.MethodPost, apiKey, path,
		map[string]string{"X-User-Id": "user-2"}, body)
	require.Equal(t, http.StatusOK, statusU2, "a different header value must have its own budget, body: %s", raw)
}

func TestPluginE2E_TokenRateLimiter_PerModelIsolation(t *testing.T) {
	defer Track(t, "PluginTokenRateLimiter")()

	const budget = 5
	up := newUsageUpstream(t, "token-per-model", 8)
	gatewayID, backendID := setupGatewayBackend(t, up)
	tok := createScopedPolicy(t, gatewayID, "token_rate_limiter", map[string]any{
		"per_model": true,
		"rules": []map[string]any{
			{"model": "gpt-4o-mini", "max": budget, "time_window": "1m"},
			{"model": "gpt-4o", "max": budget, "time_window": "1m"},
		},
	}, 0, false)
	path, apiKey := addConsumerRoute(t, gatewayID, backendID, tok)

	bodyMini := mustJSON(t, chatRequestModel("gpt-4o-mini"))
	bodyBig := mustJSON(t, chatRequestModel("gpt-4o"))

	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, bodyMini)
	require.Equal(t, http.StatusOK, status, "first gpt-4o-mini request should pass, body: %s", raw)

	require.Eventually(t, func() bool {
		s, _, _ := proxyRequest(t, http.MethodPost, apiKey, path, nil, bodyMini)
		return s == http.StatusTooManyRequests
	}, 5*time.Second, 100*time.Millisecond,
		"the gpt-4o-mini budget must gate further gpt-4o-mini requests once accrual lands")

	statusBig, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, bodyBig)
	require.Equal(t, http.StatusOK, statusBig, "a different model must keep an independent budget, body: %s", raw)
}

func TestPluginE2E_TokenRateLimiter_AggregateBudget(t *testing.T) {
	defer Track(t, "PluginTokenRateLimiter")()

	const budget = 5
	up := newUsageUpstream(t, "token-aggregate", 8)
	gatewayID, backendID := setupGatewayBackend(t, up)
	tok := createScopedPolicy(t, gatewayID, "token_rate_limiter", map[string]any{
		"aggregate": map[string]any{"max": budget, "time_window": "1m"},
	}, 0, false)
	path, apiKey := addConsumerRoute(t, gatewayID, backendID, tok)

	body := mustJSON(t, chatRequest(false))

	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	require.Equal(t, http.StatusOK, status, "the crossing request must pass, body: %s", raw)

	require.Eventually(t, func() bool {
		s, _, _ := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
		return s == http.StatusTooManyRequests
	}, 5*time.Second, 100*time.Millisecond,
		"an aggregate token budget must reject the next request once accrual lands")
}

func TestPluginE2E_TokenRateLimiter_AggregateDollarBudget(t *testing.T) {
	defer Track(t, "PluginTokenRateLimiter")()

	up := newUsageUpstream(t, "token-dollars", 8)
	gatewayID, backendID := setupGatewayBackend(t, up)
	tok := createScopedPolicy(t, gatewayID, "token_rate_limiter", map[string]any{
		"unit":          "dollars",
		"pricing_table": "custom",
		"custom_pricing": map[string]any{
			"gpt-4o-mini": map[string]any{"input": 0.001, "output": 0},
		},
		"aggregate": map[string]any{"max": 0.005, "time_window": "1m"},
	}, 0, false)
	path, apiKey := addConsumerRoute(t, gatewayID, backendID, tok)

	body := mustJSON(t, chatRequest(false))

	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	require.Equal(t, http.StatusOK, status, "the crossing request must pass, body: %s", raw)

	require.Eventually(t, func() bool {
		s, _, _ := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
		return s == http.StatusTooManyRequests
	}, 5*time.Second, 100*time.Millisecond,
		"a dollar budget must reject the next request once the micro-USD accrual crosses the scaled max")
}

func TestPluginE2E_TokenRateLimiter_LegacyBackCompat(t *testing.T) {
	defer Track(t, "PluginTokenRateLimiter")()

	const budget = 5
	up := newUsageUpstream(t, "token-legacy", 8)
	gatewayID, backendID := setupGatewayBackend(t, up)
	tok := createScopedPolicy(t, gatewayID, "token_rate_limiter", map[string]any{
		"window": map[string]any{"unit": "minute", "max": budget},
	}, 0, false)
	path, apiKey := addConsumerRoute(t, gatewayID, backendID, tok)

	body := mustJSON(t, chatRequest(false))

	status, headers, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	require.Equal(t, http.StatusOK, status, "legacy window first request should pass, body: %s", raw)
	assert.Equal(t, "5", headers.Get("X-Ratelimit-Limit-Tokens"))

	require.Eventually(t, func() bool {
		s, _, _ := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
		return s == http.StatusTooManyRequests
	}, 5*time.Second, 100*time.Millisecond,
		"a legacy window must still reject identically once accrual lands")
}

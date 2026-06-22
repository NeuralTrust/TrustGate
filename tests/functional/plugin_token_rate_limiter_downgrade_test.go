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

func TestPluginE2E_TokenRateLimiter_CostCapDowngradeSameProvider(t *testing.T) {
	defer Track(t, "PluginTokenRateLimiter")()

	up := newUsageUpstream(t, "token-downgrade", 8)
	gatewayID, backendID := setupGatewayBackend(t, up)
	tok := createScopedPolicy(t, gatewayID, "token_rate_limiter", map[string]any{
		"pricing_table": "custom",
		"custom_pricing": map[string]any{
			"gpt-4o":      map[string]any{"input": 0.001, "output": 0.002},
			"gpt-4o-mini": map[string]any{"input": 0.0001, "output": 0.0001},
		},
		"cost_cap": map[string]any{
			"enabled":                       true,
			"max_input_cost_per_1k_tokens":  0.5,
			"max_output_cost_per_1k_tokens": 0.5,
			"behavior_on_violation":         "downgrade",
			"downgrade_to":                  "gpt-4o-mini",
		},
	}, 0, false)
	path, apiKey := addConsumerRoute(t, gatewayID, backendID, tok)

	body := mustJSON(t, chatRequestModel("gpt-4o"))
	status, headers, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	require.Equal(t, http.StatusOK, status, "a downgradeable violation must pass through, body: %s", raw)
	assert.Equal(t, "gpt-4o→gpt-4o-mini", headers.Get("X-NeuralTrust-Model-Downgraded"))
	assert.Equal(t, 1, up.Hits())
	assert.Contains(t, string(up.LastBody()), `"model":"gpt-4o-mini"`,
		"the upstream must receive the downgraded model")
}

func TestPluginE2E_TokenRateLimiter_CostCapDowngradeCrossProviderRejects(t *testing.T) {
	defer Track(t, "PluginTokenRateLimiter")()

	up := newUsageUpstream(t, "token-downgrade-cross", 8)
	gatewayID, backendID := setupGatewayBackend(t, up)
	tok := createScopedPolicy(t, gatewayID, "token_rate_limiter", map[string]any{
		"pricing_table": "custom",
		"custom_pricing": map[string]any{
			"gpt-4o": map[string]any{"input": 0.001, "output": 0.002},
		},
		"cost_cap": map[string]any{
			"enabled":                       true,
			"max_input_cost_per_1k_tokens":  0.5,
			"max_output_cost_per_1k_tokens": 0.5,
			"behavior_on_violation":         "downgrade",
			"downgrade_to":                  "@anthropic/claude-3-haiku",
		},
	}, 0, false)
	path, apiKey := addConsumerRoute(t, gatewayID, backendID, tok)

	body := mustJSON(t, chatRequestModel("gpt-4o"))
	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	require.Equal(t, http.StatusForbidden, status, "a cross-provider downgrade must fall back to reject, body: %s", raw)
	assert.Contains(t, string(raw), "model_too_expensive")
	assert.Equal(t, 0, up.Hits(), "a rejected downgrade must never reach the upstream")
}

func TestPluginE2E_TokenRateLimiter_ObserveNeverBlocks(t *testing.T) {
	defer Track(t, "PluginTokenRateLimiter")()

	up := newUsageUpstream(t, "token-observe", 8)
	gatewayID, backendID := setupGatewayBackend(t, up)
	tok := CreatePolicy(t, gatewayID, map[string]any{
		"name":     uniqueName("token_rate_limiter"),
		"slug":     "token_rate_limiter",
		"enabled":  true,
		"priority": 0,
		"parallel": false,
		"mode":     "observe",
		"settings": map[string]any{
			"pricing_table": "custom",
			"custom_pricing": map[string]any{
				"gpt-4o": map[string]any{"input": 0.001, "output": 0.002},
			},
			"aggregate": map[string]any{"max": 5, "time_window": "1m"},
			"cost_cap": map[string]any{
				"enabled":                       true,
				"max_input_cost_per_1k_tokens":  0.5,
				"max_output_cost_per_1k_tokens": 0.5,
				"behavior_on_violation":         "reject",
			},
		},
	})
	path, apiKey := addConsumerRoute(t, gatewayID, backendID, tok)

	body := mustJSON(t, chatRequestModel("gpt-4o"))

	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	require.Equal(t, http.StatusOK, status, "observe must not reject an over-priced model, body: %s", raw)

	require.Eventually(t, func() bool {
		s, _, _ := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
		return s == http.StatusOK
	}, 5*time.Second, 100*time.Millisecond,
		"observe must keep passing requests even after the budget is exceeded")
	assert.True(t, up.Hits() >= 2, "observe records the breach but the upstream still serves every request")
}

func TestPluginE2E_TokenRateLimiter_EnforceTokenBudgetExceeded(t *testing.T) {
	defer Track(t, "PluginTokenRateLimiter")()

	up := newUsageUpstream(t, "token-enforce-429", 8)
	gatewayID, backendID := setupGatewayBackend(t, up)
	tok := createScopedPolicy(t, gatewayID, "token_rate_limiter", map[string]any{
		"aggregate": map[string]any{"max": 5, "time_window": "1m"},
	}, 0, false)
	path, apiKey := addConsumerRoute(t, gatewayID, backendID, tok)

	body := mustJSON(t, chatRequest(false))
	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	require.Equal(t, http.StatusOK, status, "the crossing request must pass, body: %s", raw)

	require.Eventually(t, func() bool {
		s, h, b := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
		if s != http.StatusTooManyRequests {
			return false
		}
		return h.Get("X-Budget-Unit") == "tokens" &&
			h.Get("X-Budget-Scope") == "consumer" &&
			h.Get("X-Budget-Window") == "1m" &&
			strings.Contains(string(b), "token_budget_exceeded")
	}, 5*time.Second, 100*time.Millisecond,
		"an exceeded token budget must 429 with X-Budget-* headers and a structured body")
}

func TestPluginE2E_TokenRateLimiter_EnforceDollarBudgetExceeded(t *testing.T) {
	defer Track(t, "PluginTokenRateLimiter")()

	up := newUsageUpstream(t, "token-dollar-429", 8)
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
		s, h, b := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
		if s != http.StatusTooManyRequests {
			return false
		}
		return h.Get("X-Budget-Unit") == "dollars" &&
			h.Get("X-Ratelimit-Limit-Tokens") == "" &&
			strings.Contains(string(b), "dollar_budget_exceeded")
	}, 5*time.Second, 100*time.Millisecond,
		"an exceeded dollar budget must 429 with dollar-appropriate X-Budget-* headers and body")
}

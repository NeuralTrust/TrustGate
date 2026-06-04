//go:build functional

package functional_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPluginE2E_RateLimiter_Global(t *testing.T) {
	defer Track(t, "PluginRateLimiter")()

	const limit = 5
	up := newJSONUpstream(t, "rl-upstream")
	apiKey, path := setupPolicyRoute(t, up,
		policyPlugin("rate_limiter", map[string]any{
			"limits": map[string]any{
				"global": map[string]any{"limit": limit, "window": "1m"},
			},
			"actions": map[string]any{"type": "reject", "retry_after": "60"},
		}),
	)

	body := mustJSON(t, chatRequest(false))

	for i := 1; i <= limit; i++ {
		status, headers, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
		require.Equal(t, http.StatusOK, status, "request %d should be allowed, body: %s", i, raw)
		assert.Equal(t, "5", headers.Get("X-RateLimit-global-Limit"))
	}

	status, headers, _ := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	assert.Equal(t, http.StatusTooManyRequests, status, "request beyond the limit must be rejected")
	assert.Equal(t, "60", headers.Get("Retry-After"))
	assert.Equal(t, limit, up.Hits(), "rejected requests must not reach the upstream")
}

func TestPluginE2E_RateLimiter_PerUserIsolation(t *testing.T) {
	defer Track(t, "PluginRateLimiter")()

	const perUser = 3
	up := newJSONUpstream(t, "rl-user-upstream")
	apiKey, path := setupPolicyRoute(t, up,
		policyPlugin("rate_limiter", map[string]any{
			"limits": map[string]any{
				"per_user": map[string]any{"limit": perUser, "window": "1m"},
				"global":   map[string]any{"limit": 1000, "window": "1m"},
			},
			"actions": map[string]any{"type": "reject", "retry_after": "30"},
		}),
	)

	body := mustJSON(t, chatRequest(false))

	exhaust := func(user string) {
		for i := 1; i <= perUser; i++ {
			status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path,
				map[string]string{"X-User-ID": user}, body)
			require.Equal(t, http.StatusOK, status, "user %s request %d, body: %s", user, i, raw)
		}
		status, _, _ := proxyRequest(t, http.MethodPost, apiKey, path,
			map[string]string{"X-User-ID": user}, body)
		assert.Equal(t, http.StatusTooManyRequests, status, "user %s should be limited after %d requests", user, perUser)
	}

	exhaust("alice")
	// Bob has an independent budget: alice being limited must not affect bob.
	exhaust("bob")
}

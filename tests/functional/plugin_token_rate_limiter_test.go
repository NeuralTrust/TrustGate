//go:build functional

package functional_test

import (
	"net/http"
	"testing"

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
	gatewayID, path := setupPolicyRoute(t, up,
		policyPlugin("token_rate_limiter", "pre_request", map[string]any{
			"window": map[string]any{"unit": "minute", "max": 100},
		}),
	)

	body := mustJSON(t, chatRequest(false))
	for i := 0; i < 5; i++ {
		status, _, raw := proxyRequest(t, http.MethodPost, gatewayID, path, nil, body)
		require.Equal(t, http.StatusOK, status, "request %d should pass through, body: %s", i, raw)
	}
	assert.Equal(t, 5, up.Hits())
}

func TestPluginE2E_TokenRateLimiter_WithIdentifierHeader(t *testing.T) {
	defer Track(t, "PluginTokenRateLimiter")()

	up := newUsageUpstream(t, "token-hdr-upstream", 8)
	gatewayID, path := setupPolicyRoute(t, up,
		policyPlugin("token_rate_limiter", "pre_request", map[string]any{
			"identifier_header": "X-Client-ID",
			"window":            map[string]any{"unit": "hour", "max": 1000},
		}),
	)

	body := mustJSON(t, chatRequest(false))
	for _, clientID := range []string{"client-a", "client-b"} {
		status, _, raw := proxyRequest(t, http.MethodPost, gatewayID, path,
			map[string]string{"X-Client-ID": clientID}, body)
		assert.Equal(t, http.StatusOK, status, "client %s should pass through, body: %s", clientID, raw)
	}
}

//go:build functional

package functional_test

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPlanRateLimitE2E covers the per-tenant plan limiter end to end: the plan
// stamped on a gateway is the cap, the proxy answers 429 from memory once the
// burst is spent, and the response carries the headers a client needs to back
// off. The policy-level rate_limiter plugin is a different feature with its own
// tests; this one is about the plan.
//
// It runs on a tenant of its own. The counter is per tenant, so a small burst
// on the shared functional tenant would starve every other test in the package.
// The tenant id is unique per run, so no row left by an earlier run on a reused
// database can answer for it.
func TestPlanRateLimitE2E(t *testing.T) {
	defer Track(t, "PlanRateLimit")()

	const burst = 2
	tenant := uniqueName("plan-tenant")
	plan := map[string]any{
		"tier":            "free",
		"burst_per_min":   burst,
		"quota_per_month": 0,
		"max_instances":   10,
	}
	gatewayID := CreateGateway(t, map[string]any{
		"slug":         uniqueName("plan-gw"),
		"tenant_id":    tenant,
		"entitlements": plan,
	})
	up := newJSONUpstream(t, "plan-upstream")
	registryID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("plan-be"), up.URL()))
	coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("plan-co")})
	AttachRegistry(t, gatewayID, coID, registryID)
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	path := chatCompletionsPath(t, coID)

	// The burst window is a fixed minute, so a run that straddles a boundary can
	// admit up to 2*burst requests before the first refusal. burst*2+1 requests
	// always contain one.
	var refused http.Header
	admitted := 0
	for i := 0; i < burst*2+1; i++ {
		status, headers, body := proxyPost(t, apiKey, path, chatRequest(false))
		if status == http.StatusTooManyRequests {
			refused = headers
			assert.Contains(t, string(body), "rate limit exceeded")
			break
		}
		require.Equal(t, http.StatusOK, status, "body: %s", body)
		admitted++
	}

	require.NotNil(t, refused, "the plan burst of %d was never enforced: %d requests admitted", burst, admitted)
	assert.GreaterOrEqual(t, admitted, burst, "the plan must admit at least its burst")
	assert.LessOrEqual(t, admitted, burst*2, "the plan must refuse once the burst (plus one window rollover) is spent")
	assert.Equal(t, "burst", refused.Get("X-RateLimit-Reason"))
	assert.Equal(t, strconv.Itoa(burst), refused.Get("X-RateLimit-Limit"))
	assert.Equal(t, "0", refused.Get("X-RateLimit-Remaining"))
	retryAfter, err := strconv.Atoi(refused.Get("Retry-After"))
	require.NoError(t, err, "Retry-After must be whole seconds")
	assert.Positive(t, retryAfter)
	assert.Equal(t, admitted, up.Hits(), "a refused request must never reach the upstream")
}

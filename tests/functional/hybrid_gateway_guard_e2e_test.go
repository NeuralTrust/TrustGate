//go:build functional

package functional_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupHybridRoute mirrors setupRoute but stamps the gateway with
// entitlements.data_plane=hybrid, marking its traffic as belonging to a
// customer-run data plane.
func setupHybridRoute(t *testing.T, up *fakeUpstream) (apiKey, path string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{
		"slug": uniqueName("hybrid-gw"),
		"entitlements": map[string]any{
			"tier":            "free",
			"burst_per_min":   60,
			"quota_per_month": 10000,
			"max_instances":   1000,
			"data_plane":      "hybrid",
		},
	})
	registryID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("hybrid-be"), up.URL()))
	coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("hybrid-co")})
	AttachRegistry(t, gatewayID, coID, registryID)
	return createAndAttachAPIKey(t, gatewayID, coID), chatCompletionsPath(t, coID)
}

// TestHybridGatewayGuardE2E exercises the hosted-proxy refusal of hybrid
// gateways: the functional proxy runs without CONFIG_SYNC_DATA_PLANE_ENABLED,
// so it must answer 421 before any plugin, forwarder, or exporter can touch
// the payload of a gateway stamped data_plane=hybrid.
func TestHybridGatewayGuardE2E(t *testing.T) {
	defer Track(t, "HybridGatewayGuard")()

	t.Run("hybrid gateway is refused with 421 and the upstream is never called", func(t *testing.T) {
		up := newJSONUpstream(t, "hybrid-upstream")
		apiKey, path := setupHybridRoute(t, up)

		status, _, body := proxyPost(t, apiKey, path, chatRequest(false))

		assert.Equal(t, http.StatusMisdirectedRequest, status, "body: %s", body)
		assert.Contains(t, string(body), "gateway_served_by_external_data_plane")
		assert.Equal(t, 0, up.Hits(), "a refused hybrid gateway must never reach the upstream")
	})

	t.Run("hosted gateway keeps being served", func(t *testing.T) {
		up := newJSONUpstream(t, "hosted-upstream")
		apiKey, path := setupRoute(t, "", up)

		status, _, body := proxyPost(t, apiKey, path, chatRequest(false))

		require.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(body), "hosted-upstream")
	})
}

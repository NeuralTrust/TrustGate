//go:build functional

package functional_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupSmartRoute wires a gateway with two OpenAI-compatible upstreams and a
// consumer whose load balancer uses the smart-routing algorithm. The tiers map
// score >= 0.0 to the low upstream and score >= 0.5 to the high upstream. Each
// registry declares its own default model, so once smart routing picks a
// registry by score the request is forwarded with that registry's default
// model injected.
func setupSmartRoute(t *testing.T, low, high *fakeUpstream, lowModel, highModel string) (string, string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("smart-gw")})
	lowID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be-low"), low.URL()))
	highID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be-high"), high.URL()))

	coID := CreateConsumer(t, gatewayID, map[string]any{
		"name": uniqueName("smart-cons"),
		"registries": []map[string]any{
			{"id": lowID, "model_policies": map[string]any{"allowed": []string{lowModel}, "default": lowModel}},
			{"id": highID, "model_policies": map[string]any{"allowed": []string{highModel}, "default": highModel}},
		},
		"lb_config": map[string]any{
			"enabled":   true,
			"algorithm": "smart-routing",
			"members": []map[string]any{
				{"registry_id": lowID},
				{"registry_id": highID},
			},
			"smart_routing": map[string]any{
				"tiers": []map[string]any{
					{"min_score": 0.0, "registry_id": lowID},
					{"min_score": 0.5, "registry_id": highID},
				},
			},
		},
	})
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	return apiKey, chatCompletionsPath(t, coID)
}

// smartChatRequest builds an OpenAI chat body whose user message carries the
// content marker the complexity stub keys its score off. It intentionally omits
// the "model" field so the selected registry's default model is injected.
func smartChatRequest(content string) map[string]any {
	return map[string]any{
		"messages": []map[string]string{{"role": "user", "content": content}},
	}
}

func TestSmartRoutingE2E_RoutesByScoreAndInjectsRegistryDefaultModel(t *testing.T) {
	defer Track(t, "SmartRoutingE2E")()

	const (
		lowModel  = "model-low-tier"
		highModel = "model-high-tier"
	)

	t.Run("low score routes to the low tier and injects its default model", func(t *testing.T) {
		low := newJSONUpstream(t, "served-by-low")
		high := newJSONUpstream(t, "served-by-high")
		apiKey, path := setupSmartRoute(t, low, high, lowModel, highModel)

		status, _, body := proxyPost(t, apiKey, path, smartChatRequest(smartRouteLowContent))

		require.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(body), "served-by-low", "a low score must route to the low-tier registry")
		assert.Equal(t, 1, low.Hits())
		assert.Equal(t, 0, high.Hits())
		assert.Contains(t, string(low.LastBody()), lowModel,
			"the low-tier registry's default model must be injected into the upstream request")
	})

	t.Run("high score routes to the high tier and injects its default model", func(t *testing.T) {
		low := newJSONUpstream(t, "served-by-low")
		high := newJSONUpstream(t, "served-by-high")
		apiKey, path := setupSmartRoute(t, low, high, lowModel, highModel)

		status, _, body := proxyPost(t, apiKey, path, smartChatRequest(smartRouteHighContent))

		require.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(body), "served-by-high", "a high score must route to the high-tier registry")
		assert.Equal(t, 1, high.Hits())
		assert.Equal(t, 0, low.Hits())
		assert.Contains(t, string(high.LastBody()), highModel,
			"the high-tier registry's default model must be injected into the upstream request")
	})
}

func TestSmartRoutingE2E_FallsBackToRoundRobinOnScoreError(t *testing.T) {
	defer Track(t, "SmartRoutingE2E")()

	low := newJSONUpstream(t, "served-by-low")
	high := newJSONUpstream(t, "served-by-high")
	apiKey, path := setupSmartRoute(t, low, high, "model-low-tier", "model-high-tier")

	const total = 6
	for i := 0; i < total; i++ {
		status, _, body := proxyPost(t, apiKey, path, smartChatRequest(smartRouteErrorContent))
		require.Equal(t, http.StatusOK, status, "request %d must still be served via fallback, body: %s", i, body)
	}

	assert.Greater(t, low.Hits(), 0, "fallback round-robin must reach the low upstream")
	assert.Greater(t, high.Hits(), 0, "fallback round-robin must reach the high upstream")
	assert.Equal(t, total, low.Hits()+high.Hits(), "every request must reach exactly one upstream")
}

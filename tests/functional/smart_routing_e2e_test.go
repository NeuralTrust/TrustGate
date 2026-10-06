//go:build functional

package functional_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupSmartRoute wires a gateway with two OpenAI-compatible upstreams and a
// consumer whose load balancer uses the smart-routing algorithm. The tiers map
// score >= 0.0 to the low upstream and score >= 0.45 to the high upstream. Each
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
				{"registry_id": lowID, "model": lowModel},
				{"registry_id": highID, "model": highModel},
			},
			"smart_routing": map[string]any{
				"sr1": map[string]any{"cache_ttl_seconds": 300, "escape_hatch_enabled": false},
				"tiers": []map[string]any{
					{"min_score": 0.0, "registry_id": lowID, "model": lowModel},
					{"min_score": 0.45, "registry_id": highID, "model": highModel},
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

func TestSmartRoutingE2E_SelectsStrongestOnScoreError(t *testing.T) {
	defer Track(t, "SmartRoutingE2E")()

	low := newJSONUpstream(t, "served-by-low")
	high := newJSONUpstream(t, "served-by-high")
	apiKey, path := setupSmartRoute(t, low, high, "model-low-tier", "model-high-tier")

	const total = 6
	for i := 0; i < total; i++ {
		status, _, body := proxyPost(t, apiKey, path, smartChatRequest(smartRouteErrorContent))
		require.Equal(t, http.StatusOK, status, "request %d must still be served via fallback, body: %s", i, body)
	}

	assert.Equal(t, 0, low.Hits(), "a scorer failure must not select the weaker rung")
	assert.Equal(t, total, high.Hits(), "a scorer failure selects the strongest available rung")
	assert.Equal(t, total, low.Hits()+high.Hits(), "every request must reach exactly one upstream")
}

// newSplitUsageUpstream answers with a chat completion whose usage block splits
// prompt and completion tokens. The shared newUsageUpstream always reports zero
// completion tokens, which would leave the output leg of both cost and savings
// at zero and make the comparison vacuous.
func newSplitUsageUpstream(t *testing.T, marker string, promptTokens, completionTokens int) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w,
			`{"id":"chatcmpl-test","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}],"usage":{"prompt_tokens":%d,"completion_tokens":%d,"total_tokens":%d}}`,
			marker, promptTokens, completionTokens, promptTokens+completionTokens,
		)
	}))
	t.Cleanup(u.server.Close)
	return u
}

// pricedBackendPayload declares an explicit per-token override so cost resolves
// from the registry alone, without depending on the models.dev catalog being
// synced in the test environment.
func pricedBackendPayload(name, baseURL, model string, input, output float64) map[string]any {
	payload := openaiBackendPayload(name, baseURL)
	payload["pricing"] = map[string]any{
		"overrides": map[string]any{
			model: map[string]any{"input": input, "output": output},
		},
	}
	return payload
}

// setupSmartRouteSavings mirrors setupSmartRoute but prices both registries and
// exposes the playground identifiers, so a test can read the emitted event back
// and assert on its savings block.
func setupSmartRouteSavings(
	t *testing.T,
	low, high *fakeUpstream,
	lowModel, highModel string,
) (gatewaySlug, consumerSlug, path string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("smart-sav-gw")})
	host, ok := gatewayHosts.Load(gatewayID)
	require.True(t, ok, "gateway host missing for %s", gatewayID)
	gatewaySlug = strings.TrimSuffix(host.(string), "."+gatewayBaseDomain())
	require.NotEmpty(t, gatewaySlug)

	lowID := CreateRegistry(t, gatewayID,
		pricedBackendPayload(uniqueName("be-low"), low.URL(), lowModel, 0.000001, 0.000002))
	highID := CreateRegistry(t, gatewayID,
		pricedBackendPayload(uniqueName("be-high"), high.URL(), highModel, 0.00001, 0.00002))

	coID := CreateConsumer(t, gatewayID, map[string]any{
		"name": uniqueName("smart-sav-cons"),
		"registries": []map[string]any{
			{"id": lowID, "model_policies": map[string]any{"allowed": []string{lowModel}, "default": lowModel}},
			{"id": highID, "model_policies": map[string]any{"allowed": []string{highModel}, "default": highModel}},
		},
		"lb_config": map[string]any{
			"enabled":   true,
			"algorithm": "smart-routing",
			"members": []map[string]any{
				{"registry_id": lowID, "model": lowModel},
				{"registry_id": highID, "model": highModel},
			},
			"smart_routing": map[string]any{
				"sr1": map[string]any{"cache_ttl_seconds": 300, "escape_hatch_enabled": false},
				"tiers": []map[string]any{
					{"min_score": 0.0, "registry_id": lowID, "model": lowModel},
					{"min_score": 0.45, "registry_id": highID, "model": highModel},
				},
			},
		},
	})
	return gatewaySlug, ConsumerSlug(t, coID), chatCompletionsPath(t, coID)
}

type savingsTraceEvent struct {
	Cost *struct {
		PromptUsd     float64  `json:"prompt_usd"`
		CompletionUsd float64  `json:"completion_usd"`
		TotalUsd      float64  `json:"total_usd"`
		SavingsUsd    *float64 `json:"savings_usd"`
	} `json:"cost"`
}

func smartRoutingTraceFor(t *testing.T, gatewaySlug, consumerSlug, path, content string) savingsTraceEvent {
	t.Helper()
	token := mintPlaygroundToken(t, consumerSlug)
	status, headers, body := playgroundPost(t, gatewaySlug, token, path, smartChatRequest(content))
	require.Equal(t, http.StatusOK, status, "body: %s", body)

	traceID := headers.Get(traceIDHeader)
	require.NotEmpty(t, traceID)

	var evt savingsTraceEvent
	raw := pollPlaygroundTrace(t, traceID)
	require.NoError(t, json.Unmarshal(raw, &evt), "trace body: %s", raw)
	return evt
}

func TestSmartRoutingE2E_RecordsSavings(t *testing.T) {
	defer Track(t, "SmartRoutingSavingsE2E")()

	const (
		lowModel  = "model-low-tier"
		highModel = "model-high-tier"
		promptTok = 10
		outputTok = 20
	)
	// The high tier is priced 10x the low tier on both legs.
	lowCost := promptTok*0.000001 + outputTok*0.000002
	baseline := promptTok*0.00001 + outputTok*0.00002

	t.Run("a low-tier pick records what the top tier would have cost", func(t *testing.T) {
		low := newSplitUsageUpstream(t, "served-by-low", promptTok, outputTok)
		high := newSplitUsageUpstream(t, "served-by-high", promptTok, outputTok)
		gatewaySlug, consumerSlug, path := setupSmartRouteSavings(t, low, high, lowModel, highModel)

		evt := smartRoutingTraceFor(t, gatewaySlug, consumerSlug, path, smartRouteLowContent)

		require.NotNil(t, evt.Cost)
		require.NotNil(t, evt.Cost.SavingsUsd, "a tier decision must record savings")
		assert.InDelta(t, lowCost, evt.Cost.TotalUsd, 1e-12,
			"the low tier's own rates must price the served leg")
		assert.InDelta(t, baseline-lowCost, *evt.Cost.SavingsUsd, 1e-12)
	})

	t.Run("a top-tier pick records zero savings, not an absent block", func(t *testing.T) {
		low := newSplitUsageUpstream(t, "served-by-low", promptTok, outputTok)
		high := newSplitUsageUpstream(t, "served-by-high", promptTok, outputTok)
		gatewaySlug, consumerSlug, path := setupSmartRouteSavings(t, low, high, lowModel, highModel)

		evt := smartRoutingTraceFor(t, gatewaySlug, consumerSlug, path, smartRouteHighContent)

		require.NotNil(t, evt.Cost)
		require.NotNil(t, evt.Cost.SavingsUsd)
		assert.InDelta(t, baseline, evt.Cost.TotalUsd, 1e-12)
		assert.InDelta(t, 0, *evt.Cost.SavingsUsd, 1e-12)
	})

	// A scorer failure is not a scored tier decision and receives no savings credit.
	t.Run("a scorer error falls back and records no savings", func(t *testing.T) {
		low := newSplitUsageUpstream(t, "served-by-low", promptTok, outputTok)
		high := newSplitUsageUpstream(t, "served-by-high", promptTok, outputTok)
		gatewaySlug, consumerSlug, path := setupSmartRouteSavings(t, low, high, lowModel, highModel)

		evt := smartRoutingTraceFor(t, gatewaySlug, consumerSlug, path, smartRouteErrorContent)

		require.NotNil(t, evt.Cost, "a fail-open request is still costed")
		assert.Nil(t, evt.Cost.SavingsUsd, "a strongest-rung failure fallback must not report savings")
	})
}

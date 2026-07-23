//go:build functional

package functional_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func setupIntentRoute(t *testing.T, up *fakeUpstream, allowed []string, defaultModel string) (string, string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("intent-gw")})
	backendID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be"), up.URL()))
	policy := map[string]any{"allowed": allowed}
	if defaultModel != "" {
		policy["default"] = defaultModel
	}
	coID := CreateConsumer(t, gatewayID, map[string]any{
		"name": uniqueName("cons"),
		"registries": []map[string]any{
			{"id": backendID, "model_policies": policy},
		},
	})
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	return apiKey, chatCompletionsPath(t, coID)
}

func TestRoutingIntent_QualifiedModel(t *testing.T) {
	defer Track(t, "RoutingIntent")()

	t.Run("allowed @provider/model is rewritten to the native model", func(t *testing.T) {
		up := newJSONUpstream(t, "qualified-served")
		apiKey, path := setupIntentRoute(t, up, []string{"gpt-4o-mini"}, "")

		status, _, body := proxyPost(t, apiKey, path, chatRequestModel("@openai/gpt-4o-mini"))

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(body), "qualified-served")
		assert.Equal(t, 1, up.Hits())
		assert.Contains(t, string(up.LastBody()), `"model":"gpt-4o-mini"`,
			"the provider prefix must be stripped before reaching the upstream")
	})

	t.Run("denied model returns 403 and never reaches upstream", func(t *testing.T) {
		up := newJSONUpstream(t, "must-not-serve")
		apiKey, path := setupIntentRoute(t, up, []string{"gpt-4o-mini"}, "")

		status, _, body := proxyPost(t, apiKey, path, chatRequestModel("@openai/gpt-4-forbidden"))

		assert.Equal(t, http.StatusForbidden, status, "body: %s", body)
		assert.Contains(t, string(body), "model_not_allowed")
		assert.Equal(t, 0, up.Hits())
	})

	t.Run("unknown provider returns 403", func(t *testing.T) {
		up := newJSONUpstream(t, "must-not-serve")
		apiKey, path := setupIntentRoute(t, up, []string{"gpt-4o-mini"}, "")

		status, _, body := proxyPost(t, apiKey, path, chatRequestModel("@anthropic/claude-4"))

		assert.Equal(t, http.StatusForbidden, status, "body: %s", body)
		assert.Contains(t, string(body), "model_not_allowed")
		assert.Equal(t, 0, up.Hits())
	})

	t.Run("malformed model ref returns 400", func(t *testing.T) {
		up := newJSONUpstream(t, "must-not-serve")
		apiKey, path := setupIntentRoute(t, up, []string{"gpt-4o-mini"}, "")

		status, _, body := proxyPost(t, apiKey, path, chatRequestModel("@openai/"))

		assert.Equal(t, http.StatusBadRequest, status, "body: %s", body)
		assert.Contains(t, string(body), "invalid_model")
		assert.Equal(t, 0, up.Hits())
	})
}

func TestRoutingIntent_PoolAlias(t *testing.T) {
	defer Track(t, "RoutingIntent")()

	setupPoolRoute := func(t *testing.T, memberA, memberB, outside *fakeUpstream) (string, string) {
		t.Helper()
		gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("pool-gw")})
		memberAID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be-a"), memberA.URL()))
		memberBID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be-b"), memberB.URL()))
		outsideID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be-out"), outside.URL()))
		coID := CreateConsumer(t, gatewayID, map[string]any{
			"name": uniqueName("cons"),
			"registries": []map[string]any{
				{"id": memberAID, "model_policies": map[string]any{"allowed": []string{"gpt-4o-mini"}, "default": "gpt-4o-mini"}},
				{"id": memberBID, "model_policies": map[string]any{"allowed": []string{"gpt-4o-mini"}, "default": "gpt-4o-mini"}},
				{"id": outsideID, "model_policies": map[string]any{"allowed": []string{"gpt-4o"}, "default": "gpt-4o"}},
			},
			"lb_config": map[string]any{
				"enabled":    true,
				"algorithm":  "round-robin",
				"pool_alias": "fast-chat",
				"members": []map[string]any{
					{"registry_id": memberAID},
					{"registry_id": memberBID},
				},
			},
		})
		apiKey := createAndAttachAPIKey(t, gatewayID, coID)
		return apiKey, chatCompletionsPath(t, coID)
	}

	t.Run("valid alias balances across members only", func(t *testing.T) {
		memberA := newJSONUpstream(t, "member-A")
		memberB := newJSONUpstream(t, "member-B")
		outside := newJSONUpstream(t, "outside-pool")
		apiKey, path := setupPoolRoute(t, memberA, memberB, outside)

		const total = 4
		for i := 0; i < total; i++ {
			status, _, body := proxyPost(t, apiKey, path, chatRequestModel("pool:fast-chat"))
			assert.Equal(t, http.StatusOK, status, "request %d body: %s", i, body)
		}

		assert.Equal(t, total, memberA.Hits()+memberB.Hits(), "every request must hit a pool member")
		assert.Equal(t, 0, outside.Hits(), "registries outside the pool must never serve pool traffic")
		assert.Contains(t, string(memberA.LastBody()), `"gpt-4o-mini"`,
			"the member default model must replace the pool reference")
	})

	t.Run("unknown alias returns 400", func(t *testing.T) {
		memberA := newJSONUpstream(t, "member-A")
		memberB := newJSONUpstream(t, "member-B")
		outside := newJSONUpstream(t, "outside-pool")
		apiKey, path := setupPoolRoute(t, memberA, memberB, outside)

		status, _, body := proxyPost(t, apiKey, path, chatRequestModel("pool:nonexistent"))

		assert.Equal(t, http.StatusBadRequest, status, "body: %s", body)
		assert.Contains(t, string(body), "invalid_model")
		assert.Equal(t, 0, memberA.Hits()+memberB.Hits()+outside.Hits())
	})

	t.Run("empty alias returns 400", func(t *testing.T) {
		memberA := newJSONUpstream(t, "member-A")
		memberB := newJSONUpstream(t, "member-B")
		outside := newJSONUpstream(t, "outside-pool")
		apiKey, path := setupPoolRoute(t, memberA, memberB, outside)

		status, _, body := proxyPost(t, apiKey, path, chatRequestModel("pool:"))

		assert.Equal(t, http.StatusBadRequest, status, "body: %s", body)
		assert.Contains(t, string(body), "invalid_model")
	})
}

func TestRoutingIntent_FallbackAuthorization(t *testing.T) {
	defer Track(t, "RoutingIntent")()

	setupCrossProviderFallback := func(t *testing.T, primary, fallback *fakeUpstream) (string, string) {
		t.Helper()
		gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("fbauth-gw")})
		primaryID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be-primary"), primary.URL()))
		fallbackID := CreateRegistry(t, gatewayID, openaiCompatibleBackendPayload(uniqueName("be-fallback"), fallback.URL()))
		coID := CreateConsumer(t, gatewayID, map[string]any{
			"name": uniqueName("cons"),
			"registries": []map[string]any{
				{"id": primaryID, "model_policies": map[string]any{"allowed": []string{"gpt-4o-mini"}, "default": "gpt-4o-mini"}},
				{"id": fallbackID, "model_policies": map[string]any{"allowed": []string{"compat-model"}, "default": "compat-model"}},
			},
			"fallback": map[string]any{
				"enabled":  true,
				"triggers": []string{"http_5xx"},
				"chain":    []string{fallbackID},
			},
		})
		apiKey := createAndAttachAPIKey(t, gatewayID, coID)
		return apiKey, chatCompletionsPath(t, coID)
	}

	t.Run("multi-provider chain rescues a request without intent", func(t *testing.T) {
		primary := newFailingUpstream(t, http.StatusInternalServerError)
		fallback := newJSONUpstream(t, "fallback-served")
		apiKey, path := setupCrossProviderFallback(t, primary, fallback)

		status, _, body := proxyPost(t, apiKey, path, chatRequestNoModel())

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(body), "fallback-served")
		assert.Equal(t, expectedAttempts(), primary.Hits(), "primary must exhaust its retry budget before failover")
		assert.Equal(t, 1, fallback.Hits(), "the cross-provider fallback must serve exactly once")
	})

	t.Run("qualified intent excludes other-provider fallback and relays the error", func(t *testing.T) {
		primary := newFailingUpstream(t, http.StatusInternalServerError)
		fallback := newJSONUpstream(t, "must-not-serve")
		apiKey, path := setupCrossProviderFallback(t, primary, fallback)

		status, _, body := proxyPost(t, apiKey, path, chatRequestModel("@openai/gpt-4o-mini"))

		assert.Equal(t, http.StatusInternalServerError, status, "body: %s", body)
		assert.Equal(t, expectedAttempts(), primary.Hits(), "the authorized candidate must be fully retried")
		assert.Equal(t, 0, fallback.Hits(), "a fallback outside the requested provider must never serve")
	})
}

func TestRoutingIntent_PinVersusLB(t *testing.T) {
	defer Track(t, "RoutingIntent")()

	t.Run("qualified pin bypasses an enabled load balancer", func(t *testing.T) {
		pinned := newJSONUpstream(t, "pinned-served")
		other := newJSONUpstream(t, "lb-member-served")
		gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("pinlb-gw")})
		pinnedID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be-oai"), pinned.URL()))
		otherID := CreateRegistry(t, gatewayID, openaiCompatibleBackendPayload(uniqueName("be-compat"), other.URL()))
		coID := CreateConsumer(t, gatewayID, map[string]any{
			"name": uniqueName("cons"),
			"registries": []map[string]any{
				{"id": pinnedID, "model_policies": map[string]any{"allowed": []string{"gpt-4o-mini"}, "default": "gpt-4o-mini"}},
				{"id": otherID, "model_policies": map[string]any{"allowed": []string{"compat-model"}, "default": "compat-model"}},
			},
			"lb_config": map[string]any{
				"enabled":   true,
				"algorithm": "round-robin",
				"members": []map[string]any{
					{"registry_id": pinnedID},
					{"registry_id": otherID},
				},
			},
		})
		apiKey := createAndAttachAPIKey(t, gatewayID, coID)
		path := chatCompletionsPath(t, coID)

		const total = 4
		for i := 0; i < total; i++ {
			status, _, body := proxyPost(t, apiKey, path, chatRequestModel("@openai/gpt-4o-mini"))
			assert.Equal(t, http.StatusOK, status, "request %d body: %s", i, body)
			assert.Contains(t, string(body), "pinned-served",
				"request %d must be served by the pinned provider", i)
		}

		assert.Equal(t, total, pinned.Hits(), "every pinned request must hit the pinned provider")
		assert.Equal(t, 0, other.Hits(), "the load balancer must never route a pinned request")
	})

	t.Run("auto uses the load balancer and each backend default model", func(t *testing.T) {
		openai := newJSONUpstream(t, "openai-served")
		compat := newJSONUpstream(t, "compat-served")
		gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("autolb-gw")})
		openaiID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be-oai"), openai.URL()))
		compatID := CreateRegistry(t, gatewayID, openaiCompatibleBackendPayload(uniqueName("be-compat"), compat.URL()))
		coID := CreateConsumer(t, gatewayID, map[string]any{
			"name": uniqueName("cons"),
			"registries": []map[string]any{
				{"id": openaiID, "model_policies": map[string]any{"allowed": []string{"gpt-4o-mini"}, "default": "gpt-4o-mini"}},
				{"id": compatID, "model_policies": map[string]any{"allowed": []string{"compat-model"}, "default": "compat-model"}},
			},
			"lb_config": map[string]any{
				"enabled":   true,
				"algorithm": "round-robin",
				"members": []map[string]any{
					{"registry_id": openaiID},
					{"registry_id": compatID},
				},
			},
		})
		apiKey := createAndAttachAPIKey(t, gatewayID, coID)
		path := chatCompletionsPath(t, coID)

		const total = 4
		for i := 0; i < total; i++ {
			status, _, body := proxyPost(t, apiKey, path, chatRequestModel("auto"))
			assert.Equal(t, http.StatusOK, status, "request %d body: %s", i, body)
		}

		assert.Greater(t, openai.Hits(), 0, "the OpenAI backend must receive traffic")
		assert.Greater(t, compat.Hits(), 0, "the compatible backend must receive traffic")
		assert.Equal(t, total, openai.Hits()+compat.Hits())
		assert.Contains(t, string(openai.LastBody()), `"model":"gpt-4o-mini"`)
		assert.Contains(t, string(compat.LastBody()), `"model":"compat-model"`)
		assert.NotContains(t, string(openai.LastBody()), `"model":"auto"`)
		assert.NotContains(t, string(compat.LastBody()), `"model":"auto"`)
	})

	t.Run("qualified pin never fails over, even to a same-provider chain", func(t *testing.T) {
		primary := newFailingUpstream(t, http.StatusInternalServerError)
		chain := newFailingUpstream(t, http.StatusServiceUnavailable)
		gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("pinfb-gw")})
		primaryID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be-primary"), primary.URL()))
		chainID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be-chain"), chain.URL()))
		coID := CreateConsumer(t, gatewayID, map[string]any{
			"name": uniqueName("cons"),
			"registries": []map[string]any{
				{"id": primaryID, "model_policies": map[string]any{"allowed": []string{"gpt-4o-mini"}}},
				{"id": chainID, "model_policies": map[string]any{"allowed": []string{"gpt-4o-mini"}}},
			},
			"fallback": map[string]any{
				"enabled":  true,
				"triggers": []string{"http_5xx"},
				"chain":    []string{chainID},
			},
		})
		apiKey := createAndAttachAPIKey(t, gatewayID, coID)

		status, _, body := proxyPost(t, apiKey, chatCompletionsPath(t, coID),
			chatRequestModel("@openai/gpt-4o-mini"))

		assert.GreaterOrEqual(t, status, http.StatusInternalServerError,
			"the pinned backend error must be relayed, body: %s", body)
		assert.Equal(t, expectedAttempts(), primary.Hits()+chain.Hits(),
			"a pinned request must retry a single backend and never fail over")
		assert.True(t, primary.Hits() == 0 || chain.Hits() == 0,
			"only the pinned candidate may receive traffic (primary=%d chain=%d)", primary.Hits(), chain.Hits())
	})
}

func TestRoutingIntent_ShortModel(t *testing.T) {
	defer Track(t, "RoutingIntent")()

	setupTwoProviderRoute := func(t *testing.T, openaiUp, compatUp *fakeUpstream, openaiModels, compatModels []string) (string, string) {
		t.Helper()
		gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("short-gw")})
		openaiID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be-oai"), openaiUp.URL()))
		compatID := CreateRegistry(t, gatewayID, openaiCompatibleBackendPayload(uniqueName("be-compat"), compatUp.URL()))
		coID := CreateConsumer(t, gatewayID, map[string]any{
			"name": uniqueName("cons"),
			"registries": []map[string]any{
				{"id": openaiID, "model_policies": map[string]any{"allowed": openaiModels}},
				{"id": compatID, "model_policies": map[string]any{"allowed": compatModels}},
			},
		})
		apiKey := createAndAttachAPIKey(t, gatewayID, coID)
		return apiKey, chatCompletionsPath(t, coID)
	}

	t.Run("unique short model resolves to its only provider", func(t *testing.T) {
		openaiUp := newJSONUpstream(t, "openai-served")
		compatUp := newJSONUpstream(t, "compat-served")
		apiKey, path := setupTwoProviderRoute(t, openaiUp, compatUp,
			[]string{"gpt-4o-mini"}, []string{"compat-model"})

		status, _, body := proxyPost(t, apiKey, path, chatRequestModel("gpt-4o-mini"))

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(body), "openai-served")
		assert.Equal(t, 1, openaiUp.Hits())
		assert.Equal(t, 0, compatUp.Hits())
	})

	t.Run("short model shared by providers pins the first registry", func(t *testing.T) {
		openaiUp := newJSONUpstream(t, "openai-served")
		compatUp := newJSONUpstream(t, "compat-served")
		apiKey, path := setupTwoProviderRoute(t, openaiUp, compatUp,
			[]string{"shared-model"}, []string{"shared-model"})

		status, _, body := proxyPost(t, apiKey, path, chatRequestModel("shared-model"))

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(body), "openai-served")
		assert.Equal(t, 1, openaiUp.Hits())
		assert.Equal(t, 0, compatUp.Hits())
	})

	t.Run("short model outside every allow-list returns 403", func(t *testing.T) {
		openaiUp := newJSONUpstream(t, "openai-served")
		compatUp := newJSONUpstream(t, "compat-served")
		apiKey, path := setupTwoProviderRoute(t, openaiUp, compatUp,
			[]string{"gpt-4o-mini"}, []string{"compat-model"})

		status, _, body := proxyPost(t, apiKey, path, chatRequestModel("unknown-model"))

		assert.Equal(t, http.StatusForbidden, status, "body: %s", body)
		assert.Contains(t, string(body), "model_not_allowed")
		assert.Equal(t, 0, openaiUp.Hits()+compatUp.Hits())
	})
}

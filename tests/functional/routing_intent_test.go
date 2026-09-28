//go:build functional

package functional_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	t.Run("short model shared by providers is served by the first registry in the chain", func(t *testing.T) {
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

func newModelNotFoundUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.record(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w,
			`{"error":{"message":"The model does not exist or you do not have access to it.",`+
				`"type":"invalid_request_error","code":"model_not_found"}}`)
	}))
	t.Cleanup(u.server.Close)
	return u
}

func openaiCatalogListsModel(t *testing.T, slug string) bool {
	t.Helper()
	url := fmt.Sprintf("%s/v1/models-catalog?provider=openai", AdminURL)
	status, body := sendRequest(t, http.MethodGet, url, nil, nil)
	if status != http.StatusOK {
		return false
	}
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	return strings.Contains(string(raw), slug)
}

func TestRoutingIntent_SequentialChain(t *testing.T) {
	defer Track(t, "RoutingIntent")()

	setupOrderedChain := func(t *testing.T, registries ...map[string]any) (string, string) {
		t.Helper()
		gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("chain-gw")})
		bindings := make([]map[string]any, 0, len(registries))
		for _, payload := range registries {
			bindings = append(bindings, map[string]any{"id": CreateRegistry(t, gatewayID, payload)})
		}
		coID := CreateConsumer(t, gatewayID, map[string]any{
			"name":       uniqueName("cons"),
			"registries": bindings,
		})
		apiKey := createAndAttachAPIKey(t, gatewayID, coID)
		return apiKey, chatCompletionsPath(t, coID)
	}

	t.Run("resolution falls through to the first registry that serves the model", func(t *testing.T) {
		unknown := newModelNotFoundUpstream(t)
		serving := newJSONUpstream(t, "serving-registry")
		apiKey, path := setupOrderedChain(t,
			openaiCompatibleBackendPayload(uniqueName("be-unknown"), unknown.URL()),
			openaiBackendPayload(uniqueName("be-serving"), serving.URL()),
		)

		status, _, body := proxyPost(t, apiKey, path, chatRequestModel("gpt-4o-mini"))

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(body), "serving-registry")
		assert.Equal(t, 1, unknown.Hits(), "the first registry keeps its configured position and is probed")
		assert.Equal(t, 1, serving.Hits(),
			"a model_not_found from the first registry must not end resolution")
	})

	t.Run("a registry whose provider cannot serve the model is skipped without an upstream call", func(t *testing.T) {
		if !openaiCatalogListsModel(t, "gpt-4o-mini") {
			t.Skip("provider catalog is empty in this environment; the in-process verdict cannot be exercised")
		}
		cannotServe := newJSONUpstream(t, "must-not-serve")
		serving := newJSONUpstream(t, "serving-registry")
		apiKey, path := setupOrderedChain(t,
			openaiBackendPayload(uniqueName("be-openai"), cannotServe.URL()),
			openaiCompatibleBackendPayload(uniqueName("be-selfhosted"), serving.URL()),
		)

		status, _, body := proxyPost(t, apiKey, path, chatRequestModel("gemini-3-flash-preview"))

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(body), "serving-registry")
		assert.Equal(t, 0, cannotServe.Hits(),
			"the provider catalog rules the registry out before any request is sent to it")
		assert.Equal(t, 1, serving.Hits())
	})

	t.Run("no registry serves the model", func(t *testing.T) {
		first := newModelNotFoundUpstream(t)
		second := newModelNotFoundUpstream(t)
		apiKey, path := setupOrderedChain(t,
			openaiCompatibleBackendPayload(uniqueName("be-first"), first.URL()),
			openaiCompatibleBackendPayload(uniqueName("be-second"), second.URL()),
		)

		status, _, body := proxyPost(t, apiKey, path, chatRequestModel("nope-9"))

		assert.Equal(t, http.StatusNotFound, status, "body: %s", body)
		assert.Contains(t, string(body), "model_not_supported",
			"the gateway owns the failure instead of relaying one provider's model_not_found")
		assert.Contains(t, string(body), "nope-9")
		assert.Equal(t, 1, first.Hits())
		assert.Equal(t, 1, second.Hits())
	})

	t.Run("a qualified reference still pins its registry", func(t *testing.T) {
		pinned := newModelNotFoundUpstream(t)
		other := newJSONUpstream(t, "must-not-serve")
		apiKey, path := setupOrderedChain(t,
			openaiCompatibleBackendPayload(uniqueName("be-pinned"), pinned.URL()),
			openaiBackendPayload(uniqueName("be-other"), other.URL()),
		)

		status, _, body := proxyPost(t, apiKey, path, chatRequestModel("@openai_compatible/whatever"))

		assert.Equal(t, http.StatusNotFound, status, "body: %s", body)
		assert.Equal(t, 1, pinned.Hits())
		assert.Equal(t, 0, other.Hits(), "a qualified reference must not fall through to another provider")
	})

	t.Run("an unqualified model does not load-balance across registries", func(t *testing.T) {
		first := newJSONUpstream(t, "first-served")
		second := newJSONUpstream(t, "second-served")
		apiKey, path := setupOrderedChain(t,
			openaiCompatibleBackendPayload(uniqueName("be-first"), first.URL()),
			openaiCompatibleBackendPayload(uniqueName("be-second"), second.URL()),
		)

		for i := 0; i < 4; i++ {
			status, _, body := proxyPost(t, apiKey, path, chatRequestModel("some-model"))
			assert.Equal(t, http.StatusOK, status, "body: %s", body)
			assert.Contains(t, string(body), "first-served")
		}

		assert.Equal(t, 4, first.Hits())
		assert.Equal(t, 0, second.Hits(), "the chain walk is deterministic, not round-robin")
	})
}

func TestRoutingIntent_SequentialChainOrder(t *testing.T) {
	defer Track(t, "RoutingIntent")()

	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("order-gw")})
	first := newModelNotFoundUpstream(t)
	second := newJSONUpstream(t, "second-served")
	firstID := CreateRegistry(t, gatewayID, openaiCompatibleBackendPayload(uniqueName("be-a"), first.URL()))
	secondID := CreateRegistry(t, gatewayID, openaiCompatibleBackendPayload(uniqueName("be-b"), second.URL()))

	consumerBound := func(t *testing.T, registryIDs ...string) (string, string) {
		t.Helper()
		bindings := make([]map[string]any, 0, len(registryIDs))
		for _, id := range registryIDs {
			bindings = append(bindings, map[string]any{"id": id})
		}
		coID := CreateConsumer(t, gatewayID, map[string]any{
			"name":       uniqueName("cons"),
			"registries": bindings,
		})
		return createAndAttachAPIKey(t, gatewayID, coID), chatCompletionsPath(t, coID)
	}

	t.Run("the model-not-found registry bound first is probed first", func(t *testing.T) {
		apiKey, path := consumerBound(t, firstID, secondID)

		status, _, body := proxyPost(t, apiKey, path, chatRequestModel("some-model"))

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(body), "second-served")
		assert.Equal(t, 1, first.Hits(), "the registry bound first must be probed before the one bound second")
	})

	t.Run("reversing the binding order flips the winner", func(t *testing.T) {
		before := first.Hits()
		apiKey, path := consumerBound(t, secondID, firstID)

		status, _, body := proxyPost(t, apiKey, path, chatRequestModel("some-model"))

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(body), "second-served")
		assert.Equal(t, before, first.Hits(),
			"bound second, the model-not-found registry must never be reached: order is the consumer's, not the registry id's")
	})
}

func TestRoutingIntent_SequentialChainHardening(t *testing.T) {
	defer Track(t, "RoutingIntent")()

	setupChain := func(t *testing.T, extra map[string]any, registries ...map[string]any) (string, string) {
		t.Helper()
		gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("hard-gw")})
		bindings := make([]map[string]any, 0, len(registries))
		for _, payload := range registries {
			bindings = append(bindings, map[string]any{"id": CreateRegistry(t, gatewayID, payload)})
		}
		body := map[string]any{"name": uniqueName("cons"), "registries": bindings}
		for k, v := range extra {
			body[k] = v
		}
		coID := CreateConsumer(t, gatewayID, body)
		return createAndAttachAPIKey(t, gatewayID, coID), chatCompletionsPath(t, coID)
	}

	t.Run("three registries are walked until one serves the model", func(t *testing.T) {
		a := newModelNotFoundUpstream(t)
		b := newModelNotFoundUpstream(t)
		c := newJSONUpstream(t, "third-served")
		apiKey, path := setupChain(t, nil,
			openaiCompatibleBackendPayload(uniqueName("be-a"), a.URL()),
			openaiCompatibleBackendPayload(uniqueName("be-b"), b.URL()),
			openaiCompatibleBackendPayload(uniqueName("be-c"), c.URL()),
		)

		status, _, body := proxyPost(t, apiKey, path, chatRequestModel("some-model"))

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(body), "third-served")
		assert.Equal(t, 1, a.Hits())
		assert.Equal(t, 1, b.Hits())
		assert.Equal(t, 1, c.Hits())
	})

	t.Run("a low fallback attempt budget does not truncate the walk", func(t *testing.T) {
		a := newModelNotFoundUpstream(t)
		b := newJSONUpstream(t, "second-served")
		rescue := newJSONUpstream(t, "must-not-rescue")
		gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("budget-gw")})
		aID := CreateRegistry(t, gatewayID, openaiCompatibleBackendPayload(uniqueName("be-a"), a.URL()))
		bID := CreateRegistry(t, gatewayID, openaiCompatibleBackendPayload(uniqueName("be-b"), b.URL()))
		rescueID := CreateRegistry(t, gatewayID,
			openaiCompatibleBackendPayload(uniqueName("be-rescue"), rescue.URL()))
		coID := CreateConsumer(t, gatewayID, map[string]any{
			"name":       uniqueName("cons"),
			"registries": []map[string]any{{"id": aID}, {"id": bID}, {"id": rescueID}},
			"fallback": map[string]any{
				"enabled":  true,
				"triggers": []string{"http_5xx"},
				"chain":    []string{rescueID},
				"budget":   map[string]any{"max_attempts": 1},
			},
		})
		apiKey := createAndAttachAPIKey(t, gatewayID, coID)

		status, _, body := proxyPost(t, apiKey, chatCompletionsPath(t, coID), chatRequestModel("some-model"))

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(body), "second-served",
			"the fallback attempt budget bounds failover retries, not registry selection")
		assert.Equal(t, 1, a.Hits())
		assert.Equal(t, 1, b.Hits())
		assert.Equal(t, 0, rescue.Hits(),
			"the walk stops at the registry that serves the model; the fallback chain is never needed")
	})

	t.Run("a streaming request falls through to the registry that serves the model", func(t *testing.T) {
		a := newModelNotFoundUpstream(t)
		b := newStreamUpstream(t, "streamed-by-second")
		apiKey, path := setupChain(t, nil,
			openaiCompatibleBackendPayload(uniqueName("be-a"), a.URL()),
			openaiCompatibleBackendPayload(uniqueName("be-b"), b.URL()),
		)

		body := chatRequestModel("some-model")
		body["stream"] = true
		status, _, raw := proxyPost(t, apiKey, path, body)

		assert.Equal(t, http.StatusOK, status, "body: %s", raw)
		assert.Contains(t, string(raw), "streamed-by-second")
		assert.Equal(t, 1, a.Hits())
		assert.Equal(t, 1, b.Hits())
	})

	t.Run("an allow-list that excludes the model removes its registry from the chain", func(t *testing.T) {
		denied := newJSONUpstream(t, "must-not-serve")
		allowed := newJSONUpstream(t, "allowed-served")
		gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("policy-gw")})
		deniedID := CreateRegistry(t, gatewayID, openaiCompatibleBackendPayload(uniqueName("be-denied"), denied.URL()))
		allowedID := CreateRegistry(t, gatewayID, openaiCompatibleBackendPayload(uniqueName("be-allowed"), allowed.URL()))
		coID := CreateConsumer(t, gatewayID, map[string]any{
			"name": uniqueName("cons"),
			"registries": []map[string]any{
				{"id": deniedID, "model_policies": map[string]any{"allowed": []string{"other-model"}}},
				{"id": allowedID, "model_policies": map[string]any{"allowed": []string{"some-model"}}},
			},
		})
		apiKey := createAndAttachAPIKey(t, gatewayID, coID)

		status, _, body := proxyPost(t, apiKey, chatCompletionsPath(t, coID), chatRequestModel("some-model"))

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(body), "allowed-served")
		assert.Equal(t, 0, denied.Hits(),
			"an explicit allow-list still decides eligibility before any provider is contacted")
		assert.Equal(t, 1, allowed.Hits())
	})

	t.Run("the gateway error carries the provider's own diagnosis", func(t *testing.T) {
		a := newModelNotFoundUpstream(t)
		apiKey, path := setupChain(t, nil,
			openaiCompatibleBackendPayload(uniqueName("be-a"), a.URL()),
		)

		status, _, body := proxyPost(t, apiKey, path, chatRequestModel("nope-9"))

		assert.Equal(t, http.StatusNotFound, status, "body: %s", body)
		assert.Contains(t, string(body), "model_not_supported")
		assert.Contains(t, string(body), "nope-9")
		assert.Contains(t, string(body), "do not have access",
			"the provider's message must survive alongside the gateway's verdict")
	})
}

//go:build functional

package functional_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Sibling routes share a base URL, so the model on the wire is the only evidence of the pick.
type modelSpy struct {
	server      *httptest.Server
	brokenModel string
	mu          sync.Mutex
	models      []string
}

func newModelSpy(t *testing.T, brokenModel string) *modelSpy {
	t.Helper()
	spy := &modelSpy{brokenModel: brokenModel}
	spy.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		model := spy.record(r)
		w.Header().Set("Content-Type", "application/json")
		if model != "" && model == spy.brokenModel {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"error":{"message":"model unavailable","type":"server_error"}}`)
			return
		}
		_, _ = io.WriteString(w,
			`{"id":"chatcmpl-test","object":"chat.completion",`+
				`"choices":[{"index":0,"message":{"role":"assistant","content":"route-served"},"finish_reason":"stop"}]}`)
	}))
	t.Cleanup(spy.server.Close)
	return spy
}

func (s *modelSpy) record(r *http.Request) string {
	body, _ := io.ReadAll(r.Body)
	var parsed struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &parsed)
	s.mu.Lock()
	s.models = append(s.models, parsed.Model)
	s.mu.Unlock()
	return parsed.Model
}

func (s *modelSpy) URL() string { return s.server.URL }

func (s *modelSpy) Models() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.models...)
}

func (s *modelSpy) Count(model string) int {
	n := 0
	for _, seen := range s.Models() {
		if seen == model {
			n++
		}
	}
	return n
}

func setupRouteAwarePool(t *testing.T, spy *modelSpy, algorithm string, members, tiers []map[string]any) (string, string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("routelb-gw")})
	registryID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be"), spy.URL()))

	models := make([]string, 0, len(members))
	withIDs := make([]map[string]any, 0, len(members))
	for _, member := range members {
		copied := map[string]any{"registry_id": registryID}
		for k, v := range member {
			copied[k] = v
		}
		withIDs = append(withIDs, copied)
		if model, ok := member["model"].(string); ok {
			models = append(models, model)
		}
	}
	lb := map[string]any{"enabled": true, "algorithm": algorithm, "members": withIDs}
	if tiers != nil {
		withRegistry := make([]map[string]any, 0, len(tiers))
		for _, tier := range tiers {
			copied := map[string]any{"registry_id": registryID}
			for k, v := range tier {
				copied[k] = v
			}
			withRegistry = append(withRegistry, copied)
		}
		lb["smart_routing"] = map[string]any{"tiers": withRegistry}
	}

	coID := CreateConsumer(t, gatewayID, map[string]any{
		"name": uniqueName("routelb-cons"),
		"registries": []map[string]any{
			{"id": registryID, "model_policies": map[string]any{"allowed": models, "default": models[0]}},
		},
		"lb_config": lb,
	})
	return createAndAttachAPIKey(t, gatewayID, coID), chatCompletionsPath(t, coID)
}

func TestRouteAwareLB_RoundRobinAlternatesModelsOfOneRegistry(t *testing.T) {
	defer Track(t, "RouteAwareLB")()

	const (
		cheap   = "model-cheap"
		premium = "model-premium"
		total   = 4
	)
	spy := newModelSpy(t, "")
	apiKey, path := setupRouteAwarePool(t, spy, "round-robin", []map[string]any{
		{"model": cheap},
		{"model": premium},
	}, nil)

	for i := 0; i < total; i++ {
		status, _, body := proxyPost(t, apiKey, path, chatRequestModel("auto"))
		require.Equal(t, http.StatusOK, status, "request %d body: %s", i, body)
	}

	assert.Equal(t, total/2, spy.Count(cheap), "round robin must send half the traffic to the cheap route")
	assert.Equal(t, total/2, spy.Count(premium), "round robin must send half the traffic to the premium route")
}

func TestRouteAwareLB_WeightedFavoursTheHeavierRouteOfOneRegistry(t *testing.T) {
	defer Track(t, "RouteAwareLB")()

	const (
		heavy = "model-heavy"
		light = "model-light"
		total = 10
	)
	spy := newModelSpy(t, "")
	apiKey, path := setupRouteAwarePool(t, spy, "weighted-round-robin", []map[string]any{
		{"model": heavy, "weight": 4},
		{"model": light, "weight": 1},
	}, nil)

	for i := 0; i < total; i++ {
		status, _, body := proxyPost(t, apiKey, path, chatRequestModel("auto"))
		require.Equal(t, http.StatusOK, status, "request %d body: %s", i, body)
	}

	assert.Equal(t, total, spy.Count(heavy)+spy.Count(light), "every request must take one of the two routes")
	assert.Greater(t, spy.Count(heavy), spy.Count(light), "the heavier route must serve more traffic")
	assert.Greater(t, spy.Count(light), 0, "the lighter route must still serve some traffic")
}

func TestRouteAwareLB_SmartRoutingPicksTheTierModelOfOneRegistry(t *testing.T) {
	defer Track(t, "RouteAwareLB")()

	const (
		cheap   = "model-cheap"
		premium = "model-premium"
	)
	members := []map[string]any{{"model": cheap}, {"model": premium}}
	tiers := []map[string]any{
		{"min_score": 0.0, "model": cheap},
		{"min_score": 0.5, "model": premium},
	}

	t.Run("a low score takes the cheap route", func(t *testing.T) {
		spy := newModelSpy(t, "")
		apiKey, path := setupRouteAwarePool(t, spy, "smart-routing", members, tiers)

		status, _, body := proxyPost(t, apiKey, path, smartChatRequest(smartRouteLowContent))

		require.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Equal(t, 1, spy.Count(cheap))
		assert.Equal(t, 0, spy.Count(premium))
	})

	t.Run("a high score takes the premium route of the same registry", func(t *testing.T) {
		spy := newModelSpy(t, "")
		apiKey, path := setupRouteAwarePool(t, spy, "smart-routing", members, tiers)

		status, _, body := proxyPost(t, apiKey, path, smartChatRequest(smartRouteHighContent))

		require.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Equal(t, 1, spy.Count(premium))
		assert.Equal(t, 0, spy.Count(cheap))
	})
}

func TestRouteAwareLB_FailoverRetriesTheSameRegistryWithAnotherModel(t *testing.T) {
	defer Track(t, "RouteAwareLB")()

	const (
		broken = "model-broken"
		good   = "model-good"
	)
	spy := newModelSpy(t, broken)
	apiKey, path := setupRouteAwarePool(t, spy, "round-robin", []map[string]any{
		{"model": broken},
		{"model": good},
	}, nil)

	status, _, body := proxyPost(t, apiKey, path, chatRequestModel("auto"))

	require.Equal(t, http.StatusOK, status, "the healthy route of the same registry must rescue the request, body: %s", body)
	assert.Equal(t, expectedAttempts(), spy.Count(broken), "the broken route must exhaust its retry budget first")
	assert.Equal(t, 1, spy.Count(good), "failover must retry the same registry with the other model")
}

func TestRouteAwareLB_MembersWithoutModelKeepBalancingPerRegistry(t *testing.T) {
	defer Track(t, "RouteAwareLB")()

	openai := newJSONUpstream(t, "openai-served")
	compat := newJSONUpstream(t, "compat-served")
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("legacylb-gw")})
	openaiID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be-oai"), openai.URL()))
	compatID := CreateRegistry(t, gatewayID, openaiCompatibleBackendPayload(uniqueName("be-compat"), compat.URL()))
	coID := CreateConsumer(t, gatewayID, map[string]any{
		"name": uniqueName("legacylb-cons"),
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
		require.Equal(t, http.StatusOK, status, "request %d body: %s", i, body)
	}

	assert.Equal(t, total/2, openai.Hits(), "a pool without models must still rotate per registry")
	assert.Equal(t, total/2, compat.Hits())
	assert.Contains(t, string(openai.LastBody()), `"model":"gpt-4o-mini"`)
	assert.Contains(t, string(compat.LastBody()), `"model":"compat-model"`)
}

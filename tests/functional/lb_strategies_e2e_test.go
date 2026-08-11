//go:build functional

package functional_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupStrategyPool(
	t *testing.T,
	algorithm string,
	first, second *fakeUpstream,
	members []map[string]any,
	extra map[string]any,
) (string, string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("lbstrat-gw")})
	firstID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be-first"), first.URL()))
	secondID := CreateRegistry(t, gatewayID, openaiCompatibleBackendPayload(uniqueName("be-second"), second.URL()))

	ids := []string{firstID, secondID}
	poolMembers := make([]map[string]any, 0, len(ids))
	for i, id := range ids {
		member := map[string]any{"registry_id": id}
		if i < len(members) {
			for k, v := range members[i] {
				member[k] = v
			}
		}
		poolMembers = append(poolMembers, member)
	}

	lb := map[string]any{"enabled": true, "algorithm": algorithm, "members": poolMembers}
	for k, v := range extra {
		lb[k] = v
	}

	coID := CreateConsumer(t, gatewayID, map[string]any{
		"name": uniqueName("lbstrat-cons"),
		"registries": []map[string]any{
			{"id": firstID, "model_policies": map[string]any{"allowed": []string{firstPoolModel}, "default": firstPoolModel}},
			{"id": secondID, "model_policies": map[string]any{"allowed": []string{secondPoolModel}, "default": secondPoolModel}},
		},
		"lb_config": lb,
	})
	return createAndAttachAPIKey(t, gatewayID, coID), chatCompletionsPath(t, coID)
}

const (
	firstPoolModel  = "model-first"
	secondPoolModel = "model-second"
)

func drivePool(t *testing.T, apiKey, path string, first, second *fakeUpstream, total int) (int, int) {
	t.Helper()
	for i := 0; i < total; i++ {
		status, _, body := proxyPost(t, apiKey, path, chatRequestModel("auto"))
		require.Equal(t, http.StatusOK, status, "request %d body: %s", i, body)
	}
	return first.Hits(), second.Hits()
}

func TestLBStrategy_RoundRobinRotatesEvenly(t *testing.T) {
	defer Track(t, "LBStrategies")()

	const total = 4
	first := newJSONUpstream(t, "first-served")
	second := newJSONUpstream(t, "second-served")
	apiKey, path := setupStrategyPool(t, "round-robin", first, second, nil, nil)

	firstHits, secondHits := drivePool(t, apiKey, path, first, second, total)

	assert.Equal(t, total/2, firstHits, "round robin must split the traffic evenly")
	assert.Equal(t, total/2, secondHits)
	assert.Contains(t, string(first.LastBody()), `"model":"`+firstPoolModel+`"`,
		"each member must receive its own default model")
	assert.Contains(t, string(second.LastBody()), `"model":"`+secondPoolModel+`"`)
}

func TestLBStrategy_RandomSpreadsOverEveryMember(t *testing.T) {
	defer Track(t, "LBStrategies")()

	// With a uniform pick over two members, the odds of starving one across 20 requests are 2^-19.
	const total = 20
	first := newJSONUpstream(t, "first-served")
	second := newJSONUpstream(t, "second-served")
	apiKey, path := setupStrategyPool(t, "random", first, second, nil, nil)

	firstHits, secondHits := drivePool(t, apiKey, path, first, second, total)

	assert.Equal(t, total, firstHits+secondHits, "every request must reach exactly one member")
	assert.Greater(t, firstHits, 0, "a random pick must be able to select the first member")
	assert.Greater(t, secondHits, 0, "a random pick must be able to select the second member")
}

func TestLBStrategy_WeightedFavoursTheHeavierMember(t *testing.T) {
	defer Track(t, "LBStrategies")()

	const total = 10
	first := newJSONUpstream(t, "first-served")
	second := newJSONUpstream(t, "second-served")
	apiKey, path := setupStrategyPool(t, "weighted-round-robin", first, second, []map[string]any{
		{"weight": 4},
		{"weight": 1},
	}, nil)

	firstHits, secondHits := drivePool(t, apiKey, path, first, second, total)

	assert.Equal(t, total, firstHits+secondHits, "every request must reach exactly one member")
	assert.Greater(t, firstHits, secondHits, "the heavier member must serve more traffic")
	assert.Greater(t, secondHits, 0, "the lighter member must still serve some traffic")
}

func TestLBStrategy_LeastConnectionsSpreadsWhenNothingIsInFlight(t *testing.T) {
	defer Track(t, "LBStrategies")()

	// Sequential traffic leaves both members at zero in-flight, so this pins the tie-break.
	const total = 4
	first := newJSONUpstream(t, "first-served")
	second := newJSONUpstream(t, "second-served")
	apiKey, path := setupStrategyPool(t, "least-connections", first, second, nil, nil)

	firstHits, secondHits := drivePool(t, apiKey, path, first, second, total)

	assert.Equal(t, total, firstHits+secondHits, "every request must reach exactly one member")
	assert.Greater(t, firstHits, 0)
	assert.Greater(t, secondHits, 0)
}

func TestLBStrategy_SemanticKeepsServingWhenEmbeddingsAreUnavailable(t *testing.T) {
	defer Track(t, "LBStrategies")()

	// An unregistered provider stands in for an embedding API that is down.
	const total = 3
	first := newJSONUpstream(t, "first-served")
	second := newJSONUpstream(t, "second-served")
	apiKey, path := setupStrategyPool(t, "semantic", first, second, nil, map[string]any{
		"embedding_config": map[string]any{
			"provider": "unavailable-provider",
			"model":    "text-embedding-3-small",
			"auth":     map[string]any{"api_key": "sk-test"},
		},
	})

	firstHits, secondHits := drivePool(t, apiKey, path, first, second, total)

	assert.Equal(t, total, firstHits, "semantic must fall back to the first member when it cannot embed")
	assert.Equal(t, 0, secondHits)
}

func TestLBStrategy_SmartRoutingPicksTheTierMember(t *testing.T) {
	defer Track(t, "LBStrategies")()

	first := newJSONUpstream(t, "first-served")
	second := newJSONUpstream(t, "second-served")
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("lbsmart-gw")})
	firstID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be-first"), first.URL()))
	secondID := CreateRegistry(t, gatewayID, openaiCompatibleBackendPayload(uniqueName("be-second"), second.URL()))
	coID := CreateConsumer(t, gatewayID, map[string]any{
		"name": uniqueName("lbsmart-cons"),
		"registries": []map[string]any{
			{"id": firstID, "model_policies": map[string]any{"allowed": []string{firstPoolModel}, "default": firstPoolModel}},
			{"id": secondID, "model_policies": map[string]any{"allowed": []string{secondPoolModel}, "default": secondPoolModel}},
		},
		"lb_config": map[string]any{
			"enabled":   true,
			"algorithm": "smart-routing",
			"members": []map[string]any{
				{"registry_id": firstID},
				{"registry_id": secondID},
			},
			"smart_routing": map[string]any{
				"tiers": []map[string]any{
					{"min_score": 0.0, "registry_id": firstID},
					{"min_score": 0.5, "registry_id": secondID},
				},
			},
		},
	})
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	path := chatCompletionsPath(t, coID)

	status, _, body := proxyPost(t, apiKey, path, smartChatRequest(smartRouteHighContent))

	require.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, 1, second.Hits(), "a high score must select the upper tier")
	assert.Equal(t, 0, first.Hits())
}

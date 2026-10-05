//go:build functional

package functional_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLLMStore_WorkedExample(t *testing.T) {
	defer Track(t, "LLMStore")()
	receiver := newOTLPReceiver(t)
	f := setupStoreFixture(t, map[string]any{
		"slug": uniqueName("store-gw"),
		"telemetry": map[string]any{"exporters": []map[string]any{{
			"name": "store-collector", "type": "otlp",
			"settings": map[string]any{"endpoint": receiver.server.URL, "protocol": "http/protobuf", "insecure": true, "compression": "none"},
		}}},
	})

	status, key := GetLLMKey(t, f.gatewayID, f.owner)
	require.Equal(t, http.StatusOK, status, "body=%v", key)
	assert.ElementsMatch(t, []any{f.consumers["A"], f.consumers["B"], f.consumers["C"], f.consumers["D"]}, key["consumer_ids"])

	assertWorkedExample(t, ProxyURL, f)

	require.Eventually(t, func() bool {
		return otlpRecordWith(receiver,
			otlpStringAttr("trustgate.auth.id", f.keyID),
			otlpStringAttr("trustgate.principal.subject", f.owner),
			otlpStringAttr("trustgate.consumer.id", f.consumers["D"]))
	}, 30*time.Second, 250*time.Millisecond, "the usage event names the key, its owner and the consumer that served it")
}

func TestLLMStore_FallbackAndFreshness(t *testing.T) {
	defer Track(t, "LLMStore")()
	f := setupStoreFixture(t, map[string]any{"slug": uniqueName("store-fresh")})
	eventuallyStore(t, storeServes(t, ProxyURL, f, "gpt6", http.StatusOK, "store-d-openai"), "the proxy never served the store")

	oldKey := f.key
	status, rotated := RotateLLMKey(t, f.gatewayID, f.owner, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", rotated)
	f.key = fmt.Sprint(rotated["key"])
	eventuallyStore(t, func() bool { return storeModelsStatus(t, ProxyURL, f.gatewayID, oldKey) == http.StatusUnauthorized },
		"the rotated secret kept resolving on the proxy")
	assert.Equal(t, http.StatusOK, storeModelsStatus(t, ProxyURL, f.gatewayID, f.key))

	UpdateConsumer(t, f.gatewayID, f.consumers["C"], map[string]any{"active": false})
	eventuallyStore(t, storeServes(t, ProxyURL, f, "opus-5.5", http.StatusForbidden, storeGuard("B")), "an inactive consumer is still selected")
	UpdateConsumer(t, f.gatewayID, f.consumers["C"], map[string]any{"active": true})
	eventuallyStore(t, storeServes(t, ProxyURL, f, "opus-5.5", http.StatusForbidden, storeGuard("C")), "the literal allow-list entry wins at equal priority")
	AttachAuthLink(t, f.gatewayID, f.consumers["B"], f.keyID, "group", 0, time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC))
	eventuallyStore(t, storeServes(t, ProxyURL, f, "opus-5.5", http.StatusForbidden, storeGuard("B")), "priority comes before specificity")

	DetachAuth(t, f.gatewayID, f.consumers["D"], f.keyID)
	eventuallyStore(t, func() bool { _, listed := storeModels(t, ProxyURL, f.gatewayID, f.key)["gpt6"]; return !listed },
		"the detach never reached the proxy's listing")
	cards := storeModels(t, ProxyURL, f.gatewayID, f.key)
	for id, owner := range cards {
		assert.Contains(t, []string{"openai", "anthropic"}, owner, "the DeepSeek fallback never lists: %s", id)
	}
	openaiListed := openaiCatalogListsModel(t, "gpt-4.1")
	if openaiListed {
		assert.Equal(t, "openai", cards["gpt-4.1"], "without D, A's OpenAI is no longer substituted")
	}
	status, body := storeChat(t, ProxyURL, f.gatewayID, f.key, "gpt-4.1")
	assert.Equal(t, http.StatusOK, status, body)
	assert.Contains(t, body, "store-a-openai")

	f.openaiA.failing.Store(true)
	before := f.openaiA.Hits()
	status, body = storeChat(t, ProxyURL, f.gatewayID, f.key, "gpt-4.1")
	f.openaiA.failing.Store(false)
	assert.Equal(t, http.StatusOK, status, body)
	assert.Contains(t, body, "store-a-deepseek", "A's own fallback serves the request it was selected for")
	assert.Equal(t, expectedAttempts(), f.openaiA.Hits()-before)
	for _, model := range []string{"@openai_compatible/deepseek-chat", "deepseek-chat"} {
		if model == "deepseek-chat" && !openaiListed {
			continue
		}
		status, body = storeChat(t, ProxyURL, f.gatewayID, f.key, model)
		assert.Equal(t, http.StatusForbidden, status, "%s: %s", model, body)
		assert.Contains(t, body, `"error":"model_not_allowed"`, model)
	}
	assert.Equal(t, 1, f.deepseekA.Hits(), "a fallback registry never admits a request")

	status, _ = sendRequest(t, http.MethodDelete, fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, f.gatewayID, f.consumers["B"]), nil, nil)
	require.Equal(t, http.StatusNoContent, status)
	status, key := GetLLMKey(t, f.gatewayID, f.owner)
	require.Equal(t, http.StatusOK, status, "body=%v", key)
	assert.Equal(t, f.keyID, key["id"], "deleting a personal consumer keeps the key")
	assert.ElementsMatch(t, []any{f.consumers["A"], f.consumers["C"]}, key["consumer_ids"])
	eventuallyStore(t, func() bool { _, listed := storeModels(t, ProxyURL, f.gatewayID, f.key)["opus-4.8"]; return !listed },
		"the deleted consumer kept listing")

	DetachAuth(t, f.gatewayID, f.consumers["A"], f.keyID)
	eventuallyStore(t, func() bool {
		cards := storeModels(t, ProxyURL, f.gatewayID, f.key)
		return len(cards) == 1 && cards["opus-5.5"] == "anthropic"
	}, "after detaching one of two links the listing holds only C's model")
	DetachAuth(t, f.gatewayID, f.consumers["C"], f.keyID)
	eventuallyStore(t, func() bool { return len(storeModels(t, ProxyURL, f.gatewayID, f.key)) == 0 }, "a key without links still lists models")
	status, body = storeChat(t, ProxyURL, f.gatewayID, f.key, "opus-5.5")
	assert.Equal(t, http.StatusForbidden, status, body)
	assert.Contains(t, body, `"error":"model_not_allowed"`)
	_, key = GetLLMKey(t, f.gatewayID, f.owner)
	assert.Equal(t, []any{}, key["consumer_ids"])
}

func TestLLMStore_KeyIsolation(t *testing.T) {
	defer Track(t, "LLMStore")()
	f := setupStoreFixture(t, map[string]any{"slug": uniqueName("store-iso")})
	eventuallyStore(t, storeServes(t, ProxyURL, f, "gpt6", http.StatusOK, "store-d-openai"), "the proxy never served the store")
	unknownKey := "ag_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	appUp := newJSONUpstream(t, "store-app")
	appID := CreateConsumerWithRegistries(t, f.gatewayID, uniqueName("store-app"),
		CreateRegistry(t, f.gatewayID, openaiBackendPayload(uniqueName("store-app-be"), appUp.URL())))
	appKey := createAndAttachAPIKey(t, f.gatewayID, appID)

	for path, want := range map[string]int{
		chatCompletionsPath(t, appID):                                    http.StatusUnauthorized,
		"/" + ConsumerSlug(t, f.consumers["D"]) + "/v1/chat/completions": http.StatusNotFound,
	} {
		status, body := gatewayCall(t, ProxyURL, f.gatewayID, f.key, http.MethodPost, path, chatRequest(false))
		unknownStatus, unknownBody := gatewayCall(t, ProxyURL, f.gatewayID, unknownKey, http.MethodPost, path, chatRequest(false))
		assert.Equal(t, want, status, "%s: %s", path, body)
		assert.Equal(t, unknownStatus, status, path)
		assert.Equal(t, string(unknownBody), string(body), "a personal key on %s answers as an unknown key", path)
	}
	assert.Zero(t, appUp.Hits())
	mcpID, _ := createMCPConsumer(t, f.gatewayID, nil, nil, "")
	mcpStatus, mcpBody := mcpRPC(t, f.gatewayID, mcpID, apiKeyHeaders(f.key), "tools/list", nil)
	unknownStatus, unknownBody := mcpRPC(t, f.gatewayID, mcpID, apiKeyHeaders(unknownKey), "tools/list", nil)
	assert.Equal(t, http.StatusUnauthorized, mcpStatus, "%v", mcpBody)
	assert.Equal(t, unknownStatus, mcpStatus)
	assert.Equal(t, unknownBody, mcpBody, "a personal key on MCP answers as an unknown key")

	otherGW := CreateGateway(t, map[string]any{"slug": uniqueName("store-other")})
	status, other := CreateLLMKey(t, otherGW, f.owner, llmKeyExpiry(llmKeyDay))
	require.Equal(t, http.StatusCreated, status, "body=%v", other)
	for name, key := range map[string]string{"no key": "", "unknown key": unknownKey, "application key": appKey, "another gateway's key": fmt.Sprint(other["key"])} {
		assert.Equal(t, http.StatusUnauthorized, storeModelsStatus(t, ProxyURL, f.gatewayID, key), name)
	}

	bob, carol := uniqueName("bob"), uniqueName("carol")
	status, expiring := CreateLLMKey(t, f.gatewayID, bob, map[string]any{"expires_at": time.Now().Add(4 * time.Second).UTC().Format(time.RFC3339)})
	require.Equal(t, http.StatusCreated, status, "body=%v", expiring)
	status, revoked := CreateLLMKey(t, f.gatewayID, carol, llmKeyExpiry(llmKeyDay))
	require.Equal(t, http.StatusCreated, status, "body=%v", revoked)
	bobKey, carolKey := fmt.Sprint(expiring["key"]), fmt.Sprint(revoked["key"])
	assert.Empty(t, storeModels(t, ProxyURL, f.gatewayID, bobKey), "a key without links authenticates and lists nothing")
	status, body := storeChat(t, ProxyURL, f.gatewayID, bobKey, "gpt6")
	assert.Equal(t, http.StatusForbidden, status, body)
	assert.Contains(t, body, `"error":"model_not_allowed"`)
	assert.Equal(t, http.StatusOK, storeModelsStatus(t, ProxyURL, f.gatewayID, carolKey))
	require.Equal(t, http.StatusNoContent, RevokeLLMKey(t, f.gatewayID, carol))
	eventuallyStore(t, func() bool { return storeModelsStatus(t, ProxyURL, f.gatewayID, carolKey) == http.StatusUnauthorized }, "a revoked key")
	eventuallyStore(t, func() bool { return storeModelsStatus(t, ProxyURL, f.gatewayID, bobKey) == http.StatusUnauthorized }, "an expired key")

	ossGW := CreateGateway(t, map[string]any{"slug": uniqueName("store-oss")})
	ossApp := CreateConsumerWithRegistries(t, ossGW, uniqueName("oss-app"),
		CreateRegistry(t, ossGW, openaiBackendPayload(uniqueName("oss-be"), appUp.URL())))
	ossKey := createAndAttachAPIKey(t, ossGW, ossApp)
	_, unknownSlug := gatewayCall(t, ProxyURL, ossGW, ossKey, http.MethodGet, "/zz9zz9zz/v1/models", nil)
	for _, key := range []string{"", unknownKey, ossKey} {
		status, body := gatewayCall(t, ProxyURL, ossGW, key, http.MethodGet, "/store/v1/models", nil)
		assert.Equal(t, http.StatusNotFound, status, "body: %s", body)
		assert.Equal(t, string(unknownSlug), string(body), "a gateway without personal consumers answers before any key lookup")
	}
}

func TestLLMStore_KeyBudget(t *testing.T) {
	defer Track(t, "LLMStore")()
	up := newUsageUpstream(t, "store-budget", 8)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("store-budget")})
	registryID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("store-budget-be"), up.URL()))
	consumers := []string{
		CreatePersonalConsumer(t, gatewayID, storeRegistry(registryID, []string{"gpt-4o-mini"}, "gpt-4o-mini")),
		CreatePersonalConsumer(t, gatewayID, storeRegistry(registryID, []string{"gpt-4o"}, "gpt-4o")),
	}
	policyID := CreatePolicy(t, gatewayID, map[string]any{
		"name": uniqueName("store-budget"), "slug": "token_rate_limiter", "enabled": true,
		"settings": map[string]any{"partition": "key", "aggregate": map[string]any{"max": 5, "time_window": "1m"}},
	})
	SetPolicyGlobal(t, gatewayID, policyID)
	ana, bob := uniqueName("ana"), uniqueName("bob")
	keys := map[string]string{}
	for _, owner := range []string{ana, bob} {
		status, created := CreateLLMKey(t, gatewayID, owner, llmKeyExpiry(llmKeyDay))
		require.Equal(t, http.StatusCreated, status, "body=%v", created)
		keys[owner] = fmt.Sprint(created["key"])
		for _, consumerID := range consumers {
			AttachAuthLink(t, gatewayID, consumerID, fmt.Sprint(created["id"]), "group", 1, time.Now())
		}
	}
	chat := func(key, model string) int {
		status, _ := storeChat(t, ProxyURL, gatewayID, key, model)
		return status
	}

	require.Equal(t, http.StatusOK, chat(keys[ana], "gpt-4o-mini"))
	eventuallyStore(t, func() bool { return chat(keys[ana], "gpt-4o") == http.StatusTooManyRequests },
		"one owner spends one budget across the consumers that serve her")
	counters, err := redisDB.Keys(context.Background(), fmt.Sprintf("trl:%s:key:*", policyID)).Result()
	require.NoError(t, err)
	assert.Equal(t, []string{fmt.Sprintf("trl:%s:key:owner:%s", policyID, ana)}, counters, "the counter is keyed by the owner")
	assert.Equal(t, http.StatusOK, chat(keys[bob], "gpt-4o"), "another owner has a budget of his own")

	status, rotated := RotateLLMKey(t, gatewayID, ana, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", rotated)
	eventuallyStore(t, func() bool { return chat(fmt.Sprint(rotated["key"]), "gpt-4o-mini") == http.StatusTooManyRequests },
		"the owner's counter survives a rotation")
}

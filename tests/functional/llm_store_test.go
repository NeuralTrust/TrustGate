//go:build functional

package functional_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var storeOpenAIModels = []string{"gpt-4.1", "gpt6"}

func seedStoreOpenAICatalog(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	seeded, err := seedCatalogModels(ctx, "openai", "OpenAI", storeOpenAIModels)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		assert.NoError(t, unseedCatalogModels(ctx, seeded))
	})
}

func startStoreProxyPlane(t *testing.T) string {
	t.Helper()
	port := GlobalConfig.Server.ProxyPort + 104
	requireFreePorts([]int{port})
	cmd := exec.Command(gatewayBinaryPath, "proxy") //nolint:gosec // controlled binary path
	cmd.Env = append(os.Environ(), "SERVER_PROXY_PORT="+strconv.Itoa(port), "PROVIDER_ALLOW_PRIVATE_NETWORKS=true")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	prefix := fmt.Sprintf("[STORE PROXY:%d] ", port)
	cmd.Stdout = &prefixWriter{prefix: prefix, w: os.Stdout}
	cmd.Stderr = &prefixWriter{prefix: prefix + "ERR ", w: os.Stderr}
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) })
	base := fmt.Sprintf("http://localhost:%d", port)
	waitForDBLessLiveness(t, base)
	return base
}

func createLinkedLLMKey(t *testing.T, gatewayID, owner string, consumerIDs ...string) string {
	t.Helper()
	status, created := CreateLLMKey(t, gatewayID, owner, llmKeyExpiry(llmKeyDay))
	require.Equal(t, http.StatusCreated, status, "body=%v", created)
	for _, consumerID := range consumerIDs {
		AttachAuthLink(t, gatewayID, consumerID, fmt.Sprint(created["id"]), "group", 1, time.Now())
	}
	return fmt.Sprint(created["api_key"])
}

func ownerCounter(t *testing.T, policyID, owner string) int64 {
	t.Helper()
	spent, err := redisDB.Get(context.Background(), fmt.Sprintf("trl:%s:key:owner:%s", policyID, owner)).Int64()
	if errors.Is(err, redis.Nil) {
		return 0
	}
	require.NoError(t, err)
	return spent
}

func waitForOwnerSpend(t *testing.T, policyID, owner string, spent int64) {
	t.Helper()
	require.Eventually(t, func() bool { return ownerCounter(t, policyID, owner) == spent }, 10*time.Second, 50*time.Millisecond,
		"the owner's counter never reached %d", spent)
}

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
	seedStoreOpenAICatalog(t)
	base := startStoreProxyPlane(t)
	f := setupStoreFixture(t, map[string]any{"slug": uniqueName("store-fresh")})
	eventuallyStore(t, storeServes(t, base, f, "gpt6", http.StatusOK, "store-d-openai"), "the proxy never served the store")

	oldKey := f.key
	status, rotated := RotateLLMKey(t, f.gatewayID, f.owner, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", rotated)
	f.key = fmt.Sprint(rotated["api_key"])
	eventuallyStore(t, func() bool { return storeModelsStatus(t, base, f.gatewayID, oldKey) == http.StatusUnauthorized },
		"the rotated secret kept resolving on the proxy")
	assert.Equal(t, http.StatusOK, storeModelsStatus(t, base, f.gatewayID, f.key))

	UpdateConsumer(t, f.gatewayID, f.consumers["C"], map[string]any{"active": false})
	eventuallyStore(t, storeServes(t, base, f, "opus-5.5", http.StatusForbidden, storeGuard("B")), "an inactive consumer is still selected")
	UpdateConsumer(t, f.gatewayID, f.consumers["C"], map[string]any{"active": true})
	eventuallyStore(t, storeServes(t, base, f, "opus-5.5", http.StatusForbidden, storeGuard("C")), "the literal allow-list entry wins at equal priority")
	AttachAuthLink(t, f.gatewayID, f.consumers["B"], f.keyID, "group", 0, time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC))
	eventuallyStore(t, storeServes(t, base, f, "opus-5.5", http.StatusForbidden, storeGuard("B")), "priority comes before specificity")

	DetachAuth(t, f.gatewayID, f.consumers["D"], f.keyID)
	eventuallyStore(t, func() bool { return storeModels(t, base, f.gatewayID, f.key)["gpt-4.1"] == "openai" },
		"the detach never reached the proxy's listing: without D, A's OpenAI is no longer substituted")
	cards := storeModels(t, base, f.gatewayID, f.key)
	for id, owner := range cards {
		assert.Contains(t, []string{"openai", "anthropic"}, owner, "the DeepSeek fallback never lists: %s", id)
	}
	for _, model := range storeOpenAIModels {
		assert.Equal(t, "openai", cards[model], "A's open registry lists its provider's catalog: %s", model)
		status, body := storeChat(t, base, f.gatewayID, f.key, model)
		assert.Equal(t, http.StatusOK, status, body)
		assert.Contains(t, body, "store-a-openai", model)
	}
	assert.Equal(t, 1, f.openaiD.Hits(), "without its link D serves nothing more")

	f.openaiA.failing.Store(true)
	before := f.openaiA.Hits()
	status, body := storeChat(t, base, f.gatewayID, f.key, "gpt-4.1")
	f.openaiA.failing.Store(false)
	assert.Equal(t, http.StatusOK, status, body)
	assert.Contains(t, body, "store-a-deepseek", "A's own fallback serves the request it was selected for")
	assert.Equal(t, expectedAttempts(), f.openaiA.Hits()-before)
	for _, model := range []string{"@openai_compatible/deepseek-chat", "deepseek-chat"} {
		status, body = storeChat(t, base, f.gatewayID, f.key, model)
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
	eventuallyStore(t, func() bool { _, listed := storeModels(t, base, f.gatewayID, f.key)["opus-4.8"]; return !listed },
		"the deleted consumer kept listing")

	DetachAuth(t, f.gatewayID, f.consumers["A"], f.keyID)
	eventuallyStore(t, func() bool {
		cards := storeModels(t, base, f.gatewayID, f.key)
		return len(cards) == 1 && cards["opus-5.5"] == "anthropic"
	}, "after detaching one of two links the listing holds only C's model")
	DetachAuth(t, f.gatewayID, f.consumers["C"], f.keyID)
	eventuallyStore(t, func() bool { return len(storeModels(t, base, f.gatewayID, f.key)) == 0 }, "a key without links still lists models")
	status, body = storeChat(t, base, f.gatewayID, f.key, "opus-5.5")
	assert.Equal(t, http.StatusForbidden, status, body)
	assert.Contains(t, body, `"error":"no_model_access"`, "a key without links is told it has no model access")
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
	for name, key := range map[string]string{"no key": "", "unknown key": unknownKey, "application key": appKey, "another gateway's key": fmt.Sprint(other["api_key"])} {
		assert.Equal(t, http.StatusUnauthorized, storeModelsStatus(t, ProxyURL, f.gatewayID, key), name)
	}

	bob, carol, dave := uniqueName("bob"), uniqueName("carol"), uniqueName("dave")
	expiresAt := time.Now().Add(15 * time.Second).UTC().Truncate(time.Second)
	status, expiring := CreateLLMKey(t, f.gatewayID, dave, map[string]any{"expires_at": expiresAt.Format(time.RFC3339)})
	require.Equal(t, http.StatusCreated, status, "body=%v", expiring)
	daveKey := fmt.Sprint(expiring["api_key"])
	require.Equal(t, http.StatusOK, storeModelsStatus(t, ProxyURL, f.gatewayID, daveKey), "the key works before its expiry")
	status, linkless := CreateLLMKey(t, f.gatewayID, bob, llmKeyExpiry(llmKeyDay))
	require.Equal(t, http.StatusCreated, status, "body=%v", linkless)
	status, revoked := CreateLLMKey(t, f.gatewayID, carol, llmKeyExpiry(llmKeyDay))
	require.Equal(t, http.StatusCreated, status, "body=%v", revoked)
	bobKey, carolKey := fmt.Sprint(linkless["api_key"]), fmt.Sprint(revoked["api_key"])
	assert.Empty(t, storeModels(t, ProxyURL, f.gatewayID, bobKey), "a key without links authenticates and lists nothing")
	status, body := storeChat(t, ProxyURL, f.gatewayID, bobKey, "gpt6")
	assert.Equal(t, http.StatusForbidden, status, body)
	assert.Contains(t, body, `"error":"no_model_access"`, "a key its owner can no longer use says why")
	assert.Equal(t, http.StatusOK, storeModelsStatus(t, ProxyURL, f.gatewayID, carolKey))
	require.Equal(t, http.StatusNoContent, RevokeLLMKey(t, f.gatewayID, carol))
	eventuallyStore(t, func() bool { return storeModelsStatus(t, ProxyURL, f.gatewayID, carolKey) == http.StatusUnauthorized }, "a revoked key")
	require.Eventually(t, func() bool { return storeModelsStatus(t, ProxyURL, f.gatewayID, daveKey) == http.StatusUnauthorized },
		time.Until(expiresAt)+20*time.Second, 200*time.Millisecond, "an expired key")

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
		"settings": map[string]any{"partition": "key", "aggregate": map[string]any{"max": 5, "time_window": "1h"}},
	})
	SetPolicyGlobal(t, gatewayID, policyID)
	ana, bob := uniqueName("ana"), uniqueName("bob")
	anaKey := createLinkedLLMKey(t, gatewayID, ana, consumers...)
	bobKey := createLinkedLLMKey(t, gatewayID, bob, consumers...)
	chat := func(key, model string) int {
		status, _ := storeChat(t, ProxyURL, gatewayID, key, model)
		return status
	}

	require.Equal(t, http.StatusOK, chat(anaKey, "gpt-4o-mini"))
	waitForOwnerSpend(t, policyID, ana, 8)
	require.Equal(t, http.StatusTooManyRequests, chat(anaKey, "gpt-4o"), "one owner spends one budget across the consumers that serve her")
	counters, err := redisDB.Keys(context.Background(), fmt.Sprintf("trl:%s:key:*", policyID)).Result()
	require.NoError(t, err)
	assert.Equal(t, []string{fmt.Sprintf("trl:%s:key:owner:%s", policyID, ana)}, counters, "the counter is keyed by the owner")
	require.Equal(t, http.StatusOK, chat(bobKey, "gpt-4o"), "another owner has a budget of his own")

	status, rotated := RotateLLMKey(t, gatewayID, ana, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", rotated)
	eventuallyStore(t, func() bool { return storeModelsStatus(t, ProxyURL, gatewayID, anaKey) == http.StatusUnauthorized },
		"the rotation never reached the proxy")
	rotatedKey := fmt.Sprint(rotated["api_key"])
	require.Equal(t, http.StatusTooManyRequests, chat(rotatedKey, "gpt-4o-mini"), "the owner's counter survives a rotation")

	require.Equal(t, http.StatusNoContent, RevokeLLMKey(t, gatewayID, ana))
	eventuallyStore(t, func() bool { return storeModelsStatus(t, ProxyURL, gatewayID, rotatedKey) == http.StatusUnauthorized },
		"the revocation never reached the proxy")
	recreatedKey := createLinkedLLMKey(t, gatewayID, ana, consumers...)
	eventuallyStore(t, func() bool {
		status, raw := gatewayCall(t, ProxyURL, gatewayID, recreatedKey, http.MethodGet, "/store/v1/models", nil)
		return status == http.StatusOK && len(decodeModelsList(t, raw).Data) == 2
	}, "the re-created key's links never reached the proxy")
	require.Equal(t, http.StatusTooManyRequests, chat(recreatedKey, "gpt-4o-mini"), "the owner's counter survives a revoke and re-create")
	assert.Equal(t, int64(8), ownerCounter(t, policyID, ana), "a refused request is not charged")
	assert.Equal(t, 2, up.Hits(), "a refused request never reaches the upstream")
}

func TestLLMStore_DollarKeyBudgetPricesTheServedModel(t *testing.T) {
	defer Track(t, "LLMStore")()
	up := newUsageUpstream(t, "store-dollars", 8)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("store-dollars")})
	registryID := CreateRegistry(t, gatewayID, pricedBackendPayload(uniqueName("store-dollars-be"), up.URL(), "gpt-4o-mini", 0.0001, 0))
	consumerID := CreatePersonalConsumer(t, gatewayID, storeRegistry(registryID, []string{"gpt-4o-mini"}, "gpt-4o-mini"))
	policyID := CreatePolicy(t, gatewayID, map[string]any{
		"name": uniqueName("store-dollars"), "slug": "token_rate_limiter", "enabled": true, "mode": "enforce",
		"settings": map[string]any{"partition": "key", "unit": "dollars", "aggregate": map[string]any{"max": 0.0005, "time_window": "1h"}},
	})
	SetPolicyGlobal(t, gatewayID, policyID)
	owner := uniqueName("ana")
	key := createLinkedLLMKey(t, gatewayID, owner, consumerID)

	status, body := storeChat(t, ProxyURL, gatewayID, key, "")
	require.Equal(t, http.StatusOK, status, "a request without a model is priced at the default it is served with: %s", body)
	assert.Contains(t, string(up.LastBody()), `"gpt-4o-mini"`)
	waitForOwnerSpend(t, policyID, owner, 800)
	status, body = storeChat(t, ProxyURL, gatewayID, key, "")
	require.Equal(t, http.StatusTooManyRequests, status, "the 800 micro-USD charged exceed the 500 budget: %s", body)
	assert.Equal(t, 1, up.Hits())
}

func TestLLMStore_PerKeyBudgetReplacesTheAggregate(t *testing.T) {
	defer Track(t, "LLMStore")()
	up := newUsageUpstream(t, "store-key-budget", 8)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("store-key-budget")})
	registryID := CreateRegistry(t, gatewayID, pricedBackendPayload(uniqueName("store-key-budget-be"), up.URL(), "gpt-4o-mini", 0.0001, 0))
	consumerID := CreatePersonalConsumer(t, gatewayID, storeRegistry(registryID, []string{"gpt-4o-mini"}, "gpt-4o-mini"))
	policyID := CreatePolicy(t, gatewayID, map[string]any{
		"name": uniqueName("store-key-budget"), "slug": "token_rate_limiter", "enabled": true, "mode": "enforce",
		"settings": map[string]any{"partition": "key", "key_budgets": true, "unit": "dollars"},
	})
	SetPolicyGlobal(t, gatewayID, policyID)
	ana, bob := uniqueName("ana"), uniqueName("bob")
	anaKey, bobKey := createLinkedLLMKey(t, gatewayID, ana, consumerID), createLinkedLLMKey(t, gatewayID, bob, consumerID)
	anaID := ownedKeyID(t, gatewayID, ana)
	chat := func(key string) int {
		status, _ := storeChat(t, ProxyURL, gatewayID, key, "gpt-4o-mini")
		return status
	}
	monthCounter := func(owner string) string {
		return fmt.Sprintf("trl:%s:key:owner:%s:p:%s", policyID, owner, time.Now().UTC().Format("2006-01"))
	}
	spent := func(key string) int64 {
		v, err := redisDB.Get(context.Background(), key).Int64()
		if errors.Is(err, redis.Nil) {
			return 0
		}
		require.NoError(t, err)
		return v
	}

	status, body := SetKeyBudget(t, gatewayID, anaID, monthlyBudget(0.0005))
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	eventuallyStore(t, func() bool { return chat(anaKey) == http.StatusTooManyRequests },
		"ana's budget never held her: 800 micro-USD per call against 500")
	charged := spent(monthCounter(ana))
	assert.True(t, charged >= 800 && charged%800 == 0, "the budget counts in the policy's unit on the budget's window, got %d", charged)
	require.Equal(t, http.StatusTooManyRequests, chat(anaKey))

	for range 3 {
		require.Equal(t, http.StatusOK, chat(bobKey), "a key without a budget is not held by a policy without aggregate")
	}
	counters, err := redisDB.Keys(context.Background(), fmt.Sprintf("trl:%s:key:owner:%s*", policyID, bob)).Result()
	require.NoError(t, err)
	assert.Empty(t, counters, "nor counted")

	status, body = SetKeyBudget(t, gatewayID, anaID, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	eventuallyStore(t, func() bool { return chat(anaKey) == http.StatusOK }, "clearing ana's budget never reached the proxy")
}

func ownedKeyID(t *testing.T, gatewayID, owner string) string {
	t.Helper()
	status, list := sendRequest(t, http.MethodGet, fmt.Sprintf("%s/v1/gateways/%s/auths?owner_id=%s", AdminURL, gatewayID, owner), nil, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", list)
	items, _ := list["items"].([]any)
	require.Len(t, items, 1)
	return fmt.Sprint(items[0].(map[string]any)["id"])
}

// The last personal consumer of a gateway goes away (its owner's access set to
// None), the owner's key stays: that key is told it has no model access, while
// every other caller still gets the 404 of a gateway without a store.
func TestLLMStore_KeyWithoutModelAccessIsForbidden(t *testing.T) {
	defer Track(t, "LLMStore")()
	up := newJSONUpstream(t, "store-no-access")
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("store-no-access")})
	registryID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("store-no-access-be"), up.URL()))
	consumerID := CreatePersonalConsumer(t, gatewayID, storeRegistry(registryID, []string{"gpt-4o-mini"}, "gpt-4o-mini"))
	key := createLinkedLLMKey(t, gatewayID, uniqueName("ana"), consumerID)
	status, body := storeChat(t, ProxyURL, gatewayID, key, "gpt-4o-mini")
	require.Equal(t, http.StatusOK, status, body)

	status, _ = sendRequest(t, http.MethodDelete, fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gatewayID, consumerID), nil, nil)
	require.Equal(t, http.StatusNoContent, status)
	eventuallyStore(t, func() bool {
		status, body = storeChat(t, ProxyURL, gatewayID, key, "gpt-4o-mini")
		return status == http.StatusForbidden
	}, "the key kept reaching a model")
	assert.Contains(t, body, `"error":"no_model_access"`)
	assert.Equal(t, http.StatusOK, storeModelsStatus(t, ProxyURL, gatewayID, key), "listing models still answers, with nothing in it")

	unknownKey := "ag_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	_, unknownSlug := gatewayCall(t, ProxyURL, gatewayID, unknownKey, http.MethodGet, "/zz9zz9zz/v1/models", nil)
	for _, other := range []string{"", unknownKey} {
		status, body := gatewayCall(t, ProxyURL, gatewayID, other, http.MethodPost, "/store/v1/chat/completions", chatRequest(false))
		assert.Equal(t, http.StatusNotFound, status, "body: %s", body)
		assert.Equal(t, string(unknownSlug), string(body))
	}
}

func TestLLMStore_FilesAreNotAStoreRoute(t *testing.T) {
	defer Track(t, "LLMStore")()
	up := newJSONUpstream(t, "store-files")
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("store-files")})
	registryID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("store-files-be"), up.URL()))
	consumerID := CreatePersonalConsumer(t, gatewayID, storeRegistry(registryID, []string{"gpt-4o-mini"}, "gpt-4o-mini"))
	key := createLinkedLLMKey(t, gatewayID, uniqueName("ana"), consumerID)
	status, body := storeChat(t, ProxyURL, gatewayID, key, "gpt-4o-mini")
	require.Equal(t, http.StatusOK, status, body)

	unknownStatus, unknown := gatewayCall(t, ProxyURL, gatewayID, key, http.MethodGet, "/store/v1/zz-unknown", nil)
	require.Equal(t, http.StatusNotFound, unknownStatus, "body: %s", unknown)
	unauthenticatedStatus, unauthenticated := gatewayCall(t, ProxyURL, gatewayID, "", http.MethodPost, "/store/v1/chat/completions", chatRequest(false))
	require.Equal(t, http.StatusUnauthorized, unauthenticatedStatus, "body: %s", unauthenticated)
	for _, call := range []struct{ method, path string }{
		{http.MethodGet, "/store/v1/files"},
		{http.MethodPost, "/store/v1/files"},
		{http.MethodGet, "/store/v1/files/file-abc123"},
		{http.MethodDelete, "/store/v1/files/file-abc123"},
		{http.MethodGet, "/store/v1/files/file-abc123/content"},
	} {
		status, raw := gatewayCall(t, ProxyURL, gatewayID, key, call.method, call.path, nil)
		assert.Equal(t, unknownStatus, status, "%s %s", call.method, call.path)
		assert.Equal(t, string(unknown), string(raw), "%s %s answers as an unknown store route", call.method, call.path)
		status, raw = gatewayCall(t, ProxyURL, gatewayID, "", call.method, call.path, nil)
		assert.Equal(t, unauthenticatedStatus, status, "%s %s without a key", call.method, call.path)
		assert.Equal(t, string(unauthenticated), string(raw), "%s %s without a key answers as any store route", call.method, call.path)
	}
	assert.Equal(t, 1, up.Hits(), "no file operation reaches the upstream")
}

func TestLLMStore_SessionsAreScopedByOwner(t *testing.T) {
	defer Track(t, "LLMStore")()
	prefix := uniqueName("store-session")
	up := newResponsesUpstream(t, prefix)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("store-session")})
	registryID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("store-session-be"), up.URL()))
	consumerID := CreatePersonalConsumer(t, gatewayID, storeRegistry(registryID, []string{"gpt-4o-mini"}, "gpt-4o-mini"))
	anaKey := createLinkedLLMKey(t, gatewayID, uniqueName("ana"), consumerID)
	bobKey := createLinkedLLMKey(t, gatewayID, uniqueName("bob"), consumerID)
	session := map[string]string{sessionHeader: uniqueName("shared-session")}
	turn := func(key string) []byte {
		t.Helper()
		status, raw := gatewayCallWithHeaders(t, ProxyURL, gatewayID, key, http.MethodPost, "/store/v1/responses",
			map[string]any{"model": "gpt-4o-mini", "input": "hi"}, session)
		require.Equal(t, http.StatusOK, status, "body: %s", raw)
		return up.LastBody()
	}

	assert.NotContains(t, string(turn(anaKey)), "previous_response_id", "the first turn continues nothing")
	assert.NotContains(t, string(turn(bobKey)), "previous_response_id", "another owner's session id names a conversation of his own")
	assert.Contains(t, string(turn(anaKey)), fmt.Sprintf(`"previous_response_id":"resp_%s_1"`, prefix), "the owner continues her own last turn")
	assert.Contains(t, string(turn(bobKey)), fmt.Sprintf(`"previous_response_id":"resp_%s_2"`, prefix), "and so does the other owner")
}

func TestLLMStore_EndUserIsTheKeyOwner(t *testing.T) {
	defer Track(t, "LLMStore")()
	receiver := newOTLPReceiver(t)
	up := newJSONUpstream(t, "store-end-user")
	gatewayID := CreateGateway(t, map[string]any{
		"slug": uniqueName("store-end-user"),
		"telemetry": map[string]any{"exporters": []map[string]any{{
			"name": "store-collector", "type": "otlp",
			"settings": map[string]any{"endpoint": receiver.server.URL, "protocol": "http/protobuf", "insecure": true, "compression": "none"},
		}}},
	})
	registryID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("store-end-user-be"), up.URL()))
	consumerID := CreatePersonalConsumer(t, gatewayID, storeRegistry(registryID, []string{"gpt-4o-mini"}, "gpt-4o-mini"))
	owner := uniqueName("ana")
	status, created := CreateLLMKey(t, gatewayID, owner, llmKeyExpiry(llmKeyDay))
	require.Equal(t, http.StatusCreated, status, "body=%v", created)
	keyID, key := fmt.Sprint(created["id"]), fmt.Sprint(created["api_key"])
	AttachAuthLink(t, gatewayID, consumerID, keyID, "user", 1, time.Now())

	spoofed, sessionID := uniqueName("mallory"), uniqueName("end-user-session")
	body := chatRequestModel("gpt-4o-mini")
	body["user"] = spoofed
	status, raw := gatewayCallWithHeaders(t, ProxyURL, gatewayID, key, http.MethodPost, "/store/v1/chat/completions", body, map[string]string{
		"X-NeuralTrust-End-User": spoofed,
		"X-AG-End-User":          spoofed,
		"X-TG-User-Id":           spoofed,
		"X-TG-User-Email":        spoofed + "@example.com",
		"X-OpenWebUI-User-Id":    spoofed,
		sessionHeader:            sessionID,
	})
	require.Equal(t, http.StatusOK, status, "the end-user headers are ignored, not refused: %s", raw)

	require.Eventually(t, func() bool {
		return otlpRecordWith(receiver,
			otlpStringAttr("trustgate.session_id", sessionID),
			otlpStringAttr("trustgate.auth.id", keyID),
			otlpStringAttr("trustgate.end_user.id", owner))
	}, 30*time.Second, 250*time.Millisecond, "the usage event names the key owner as the end user")
	assert.False(t, otlpRecordWith(receiver, otlpStringAttr("trustgate.end_user.id", spoofed)), "no header or body field names another end user")
	assert.False(t, otlpRecordWith(receiver, otlpStringAttr("trustgate.end_user.email", spoofed+"@example.com")))
}

func TestLLMStore_PersonalConsumerCreateIgnoresAuths(t *testing.T) {
	defer Track(t, "LLMStore")()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("store-auths")})
	registryID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("store-auths-be"), "https://api.openai.com/v1"))
	appAuthID, _ := CreateAPIKeyAuth(t, gatewayID, uniqueName("store-auths-app"))
	owner := uniqueName("ana")
	status, owned := CreateLLMKey(t, gatewayID, owner, llmKeyExpiry(llmKeyDay))
	require.Equal(t, http.StatusCreated, status, "body=%v", owned)

	payload := storeRegistry(registryID, []string{"gpt-4o-mini"}, "gpt-4o-mini")
	payload["name"], payload["audience"] = uniqueName("personal"), "personal"
	payload["auths"] = []string{appAuthID, fmt.Sprint(owned["id"])}
	status, created := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gatewayID), nil, payload)
	require.Equal(t, http.StatusCreated, status, "body=%v", created)
	consumerID := fmt.Sprint(created["id"])
	assert.Equal(t, []any{}, created["auth_ids"])
	assert.Equal(t, []any{}, getConsumer(t, gatewayID, consumerID)["auth_ids"])
	assert.Zero(t, consumerAuthRows(t, consumerID), "create never writes a consumer_auth row")
	_, key := GetLLMKey(t, gatewayID, owner)
	assert.Equal(t, []any{}, key["consumer_ids"])
}

func consumerAuthRows(t *testing.T, consumerID string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgxConnect(ctx, dbName)
	require.NoError(t, err)
	defer func() { _ = conn.Close(ctx) }()
	var rows int
	require.NoError(t, conn.QueryRow(ctx, `SELECT count(*) FROM consumer_auth WHERE consumer_id = $1::uuid`, consumerID).Scan(&rows))
	return rows
}

//go:build functional

package functional_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func keyGroupsURL(gatewayID string) string {
	return fmt.Sprintf("%s/v1/gateways/%s/key-groups", AdminURL, gatewayID)
}

func setGroupBudget(t *testing.T, gatewayID, groupID string, budget map[string]any) (int, map[string]any) {
	t.Helper()
	return sendRequest(t, http.MethodPut, keyGroupsURL(gatewayID)+"/"+groupID+"/budget", nil, budget)
}

func TestKeyGroupBudget_AdminRoutes(t *testing.T) {
	defer Track(t, "KeyGroupBudget")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("kgb-admin")})
	list := func() []any {
		t.Helper()
		status, body := sendRequest(t, http.MethodGet, keyGroupsURL(gwID)+"/budgets", nil, nil)
		require.Equal(t, http.StatusOK, status, "body=%v", body)
		items, ok := body["items"].([]any)
		require.True(t, ok, "items is a list, even an empty one: %v", body)
		return items
	}
	assert.Empty(t, list())

	status, set := setGroupBudget(t, gwID, "g-eng", map[string]any{
		"monthly_limit_usd": 100, "member_monthly_limit_usd": 20, "member_overrides": map[string]any{"alice": 50}, "action": "block",
	})
	require.Equal(t, http.StatusOK, status, "body=%v", set)
	assert.Equal(t, "g-eng", set["group_id"])
	assert.Equal(t, 100.0, set["monthly_limit_usd"])
	assert.Equal(t, 20.0, set["member_monthly_limit_usd"])
	assert.Equal(t, map[string]any{"alice": 50.0}, set["member_overrides"])
	assert.Equal(t, "block", set["action"])
	created := set["created_at"]
	require.NotEmpty(t, created)

	status, replaced := setGroupBudget(t, gwID, "g-eng", map[string]any{"member_monthly_limit_usd": 30, "action": "alert"})
	require.Equal(t, http.StatusOK, status, "body=%v", replaced)
	assert.Contains(t, replaced, "monthly_limit_usd")
	assert.Nil(t, replaced["monthly_limit_usd"], "a PUT replaces the whole budget")
	assert.Equal(t, map[string]any{}, replaced["member_overrides"])
	assert.Equal(t, "alert", replaced["action"])
	assert.Equal(t, created, replaced["created_at"], "a replaced budget keeps its creation time")

	for name, body := range map[string]map[string]any{
		"no limit":          {"action": "block"},
		"a negative limit":  {"monthly_limit_usd": -1, "action": "block"},
		"no action":         {"monthly_limit_usd": 1},
		"an unknown action": {"monthly_limit_usd": 1, "action": "throttle"},
	} {
		status, resp := setGroupBudget(t, gwID, "g-sre", body)
		assert.Equal(t, http.StatusUnprocessableEntity, status, "%s: %v", name, resp)
		assert.Equal(t, "validation_failed", resp["error"], name)
	}
	require.Len(t, list(), 1)

	status, _ = sendRequest(t, http.MethodDelete, keyGroupsURL(gwID)+"/g-eng/budget", nil, nil)
	assert.Equal(t, http.StatusNoContent, status)
	status, resp := sendRequest(t, http.MethodDelete, keyGroupsURL(gwID)+"/g-eng/budget", nil, nil)
	assert.Equal(t, http.StatusNotFound, status, "body=%v", resp)
	assert.Empty(t, list())
}

// consoleEvents is the console's events endpoint: it keeps what it is sent,
// once its signature checks out.
type consoleEvents struct {
	server *httptest.Server
	mu     sync.Mutex
	got    []map[string]any
	forged int
}

func newConsoleEvents(t *testing.T) *consoleEvents {
	t.Helper()
	c := &consoleEvents{}
	c.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mac := hmac.New(sha256.New, []byte(GlobalConfig.Server.SecretKey))
		mac.Write([]byte("trustgate.console-events.v1." + r.Header.Get("X-TrustGate-Timestamp") + "."))
		mac.Write(raw)
		c.mu.Lock()
		defer c.mu.Unlock()
		if r.Header.Get("X-TrustGate-Signature") != "v1="+hex.EncodeToString(mac.Sum(nil)) {
			c.forged++
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var event map[string]any
		_ = json.Unmarshal(raw, &event)
		c.got = append(c.got, event)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(c.server.Close)
	return c
}

func (c *consoleEvents) events() []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]map[string]any(nil), c.got...)
}

func issueGroupKey(t *testing.T, gatewayID, owner, groupID, consumerID string) string {
	t.Helper()
	url := fmt.Sprintf("%s/v1/gateways/%s/store/users/%s/llm-key", AdminURL, gatewayID, owner)
	status, created := sendRequest(t, http.MethodPost, url, map[string]string{"Authorization": "Bearer " + userToken(t, functionalTenantID, uniqueName("admin"))},
		map[string]any{"group_id": groupID, "group_name": "engineering"})
	require.Equal(t, http.StatusCreated, status, "body=%v", created)
	AttachAuthLink(t, gatewayID, consumerID, fmt.Sprint(created["id"]), "group", 1, time.Now())
	return fmt.Sprint(created["api_key"])
}

func groupCounter(t *testing.T, gatewayID, groupID, owner string) int64 {
	t.Helper()
	key := "kgb:" + gatewayID + ":" + groupID
	if owner != "" {
		key += ":owner:" + owner
	}
	spent, err := redisDB.Get(context.Background(), key+":p:"+time.Now().UTC().Format("2006-01")).Int64()
	if errors.Is(err, redis.Nil) {
		return 0
	}
	require.NoError(t, err)
	return spent
}

func waitForGroupSpend(t *testing.T, gatewayID, groupID, owner string, spent int64) {
	t.Helper()
	require.Eventually(t, func() bool { return groupCounter(t, gatewayID, groupID, owner) == spent }, 10*time.Second, 50*time.Millisecond,
		"the counter of %q never reached %d", owner, spent)
}

// A group key is held to its group's budget on /store/v1, on a full proxy
// plane and on one with no database; the console hears once of each limit
// reached; the owner's personal key is not held to it.
func TestKeyGroupBudget_HoldsAGroupKeyOnTheStore(t *testing.T) {
	defer Track(t, "KeyGroupBudget")()
	console := newConsoleEvents(t)
	base := startStoreProxyPlaneAt(t, GlobalConfig.Server.ProxyPort+105, "CONSOLE_EVENTS_URL="+console.server.URL)
	// Each answer is 8 tokens at $0.0001: 800 micro-dollars.
	up := newUsageUpstream(t, "kgb-served", 8)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("kgb")})
	registryID := CreateRegistry(t, gatewayID, pricedBackendPayload(uniqueName("kgb-be"), up.URL(), "gpt-4o-mini", 0.0001, 0))
	consumerID := CreatePersonalConsumer(t, gatewayID, storeRegistry(registryID, []string{"gpt-4o-mini"}, "gpt-4o-mini"))
	group, alice, bob := uniqueName("g"), uniqueName("alice"), uniqueName("bob")
	status, set := setGroupBudget(t, gatewayID, group, map[string]any{
		"monthly_limit_usd": 0.0012, "member_monthly_limit_usd": 0.0005, "member_overrides": map[string]any{bob: 0.01}, "action": "block",
	})
	require.Equal(t, http.StatusOK, status, "body=%v", set)
	aliceKey := issueGroupKey(t, gatewayID, alice, group, consumerID)
	bobKey := issueGroupKey(t, gatewayID, bob, group, consumerID)
	personalKey := createLinkedLLMKey(t, gatewayID, alice, consumerID)
	serves := func(key string) func() bool {
		return func() bool {
			status, _ := storeChat(t, base, gatewayID, key, "")
			return status == http.StatusOK
		}
	}

	eventuallyStore(t, serves(aliceKey), "alice's group key never reached the proxy")
	waitForGroupSpend(t, gatewayID, group, alice, 800)
	waitForGroupSpend(t, gatewayID, group, "", 800)
	status, body := storeChat(t, base, gatewayID, aliceKey, "")
	require.Equal(t, http.StatusTooManyRequests, status, "alice's $0.0005 share is spent: %s", body)
	assert.Contains(t, body, `"type":"budget_exceeded"`)
	assert.Contains(t, body, `"scope":"member"`)
	assert.Contains(t, body, "Your monthly budget in this key's group is spent")
	eventuallyStore(t, serves(personalKey), "alice's personal key is not held to her group's budget")

	eventuallyStore(t, serves(bobKey), "bob's override lets him spend past the member default")
	waitForGroupSpend(t, gatewayID, group, "", 1600)
	status, body = storeChat(t, base, gatewayID, bobKey, "")
	require.Equal(t, http.StatusTooManyRequests, status, "the group's $0.0012 is spent: %s", body)
	assert.Contains(t, body, `"scope":"group"`)
	assert.Equal(t, 3, up.Hits(), "a refused request never reaches the upstream")
	assert.Equal(t, int64(1600), groupCounter(t, gatewayID, group, ""), "a refused request is not charged")

	require.Eventually(t, func() bool { return len(console.events()) == 2 }, 10*time.Second, 100*time.Millisecond,
		"the console hears of alice's share and of the group's total")
	events := console.events()
	period := time.Now().UTC().Format("2006-01")
	assert.Equal(t, map[string]any{
		"event": "key_group_budget_reached", "source": "budget", "team_id": functionalTenantID, "gateway_id": gatewayID,
		"group_id": group, "scope": "member", "user_id": alice, "limit_usd": 0.0005, "spent_usd": 0.0008,
		"period": period, "action": "block",
	}, events[0])
	assert.Equal(t, map[string]any{
		"event": "key_group_budget_reached", "source": "budget", "team_id": functionalTenantID, "gateway_id": gatewayID,
		"group_id": group, "scope": "group", "limit_usd": 0.0012, "spent_usd": 0.0016,
		"period": period, "action": "block",
	}, events[1])
	status, _ = storeChat(t, base, gatewayID, aliceKey, "")
	require.Equal(t, http.StatusTooManyRequests, status)
	assert.Never(t, func() bool { return len(console.events()) > 2 }, time.Second, 100*time.Millisecond, "each limit is announced once a month")
	assert.Zero(t, console.forged)

	// The budget rides the config snapshot: a plane with no database holds the
	// group to it too, on the counters every plane shares.
	port := GlobalConfig.Server.ProxyPort + 106
	dbless, _ := startDBLessProxyPlane(t, port, dblessOverrides(filepath.Join(t.TempDir(), "snapshot.lkg"), dblessConfigSyncToken, uniqueName("dbless-kgb"), port))
	require.True(t, pollDBLessReady(dbless, 30*time.Second), "db-less plane never became ready")
	eventuallyStore(t, func() bool {
		status, body := storeChat(t, dbless, gatewayID, aliceKey, "")
		return status == http.StatusTooManyRequests && strings.Contains(body, "budget_exceeded")
	}, "the group's budget never reached the db-less plane")

	status, _ = sendRequest(t, http.MethodDelete, keyGroupsURL(gatewayID)+"/"+group+"/budget", nil, nil)
	require.Equal(t, http.StatusNoContent, status)
	eventuallyStore(t, serves(aliceKey), "clearing the budget never reached the proxy")
	eventuallyStore(t, func() bool {
		status, _ := storeChat(t, dbless, gatewayID, aliceKey, "")
		return status == http.StatusOK
	}, "clearing the budget never reached the db-less plane")
}

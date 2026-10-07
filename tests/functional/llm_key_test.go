//go:build functional

package functional_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const llmKeyDay = 24 * time.Hour

func llmKeyExpiry(in time.Duration) map[string]any {
	return map[string]any{"expires_at": time.Now().Add(in).UTC().Format(time.RFC3339)}
}

func TestLLMKey_SelfFlows(t *testing.T) {
	defer Track(t, "LLMKey")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("llm-key")})
	alice, bob := uniqueName("alice"), uniqueName("bob")

	status, _ := CreateLLMKey(t, gwID, alice, llmKeyExpiry(90*llmKeyDay+time.Hour))
	assert.Equal(t, http.StatusUnprocessableEntity, status, "the expiry is capped at 90 days")
	body := llmKeyExpiry(30 * llmKeyDay)
	body["principal_sub"], body["owner_id"], body["consumer_id"] = bob, bob, CreateConsumer(t, gwID, validConsumerPayload(uniqueName("llm-key-cons")))
	status, created := CreateLLMKey(t, gwID, alice, body)
	require.Equal(t, http.StatusCreated, status, "body=%v", created)
	keyID := fmt.Sprint(created["id"])
	assert.True(t, strings.HasPrefix(fmt.Sprint(created["api_key"]), "ag_"), "create returns the secret once: %v", created)
	assert.Equal(t, []any{}, created["consumer_ids"])

	status, got := GetLLMKey(t, gwID, alice)
	require.Equal(t, http.StatusOK, status, "body=%v", got)
	assert.Equal(t, keyID, got["id"])
	assert.Equal(t, []any{}, got["consumer_ids"])
	assert.NotContains(t, got, "key", "the secret is never read back")

	status, _ = CreateLLMKey(t, gwID, alice, llmKeyExpiry(llmKeyDay))
	assert.Equal(t, http.StatusConflict, status, "one key per user per gateway")

	status, rotated := RotateLLMKey(t, gwID, alice, llmKeyExpiry(89*llmKeyDay))
	require.Equal(t, http.StatusOK, status, "body=%v", rotated)
	assert.Equal(t, keyID, rotated["id"], "rotate keeps the auth id")
	assert.NotEqual(t, created["api_key"], rotated["api_key"])
	assert.NotEqual(t, created["expires_at"], rotated["expires_at"])

	status, _ = GetLLMKey(t, gwID, bob)
	assert.Equal(t, http.StatusNotFound, status, "the body owner was ignored")
	status, _ = RotateLLMKey(t, gwID, bob, nil)
	assert.Equal(t, http.StatusNotFound, status)
	status, _ = RotateLLMKey(t, gwID, bob, llmKeyExpiry(91*llmKeyDay))
	assert.Equal(t, http.StatusUnprocessableEntity, status, "the expiry is judged before the lookup")
	assert.Equal(t, http.StatusNotFound, RevokeLLMKey(t, gwID, bob))

	assert.Equal(t, http.StatusNoContent, RevokeLLMKey(t, gwID, alice))
	status, _ = GetLLMKey(t, gwID, alice)
	assert.Equal(t, http.StatusNotFound, status)
	status, recreated := CreateLLMKey(t, gwID, alice, llmKeyExpiry(llmKeyDay))
	require.Equal(t, http.StatusCreated, status, "body=%v", recreated)
	assert.NotEqual(t, keyID, recreated["id"])

	otherGW := CreateGateway(t, map[string]any{"slug": uniqueName("llm-key-other")})
	status, _ = CreateLLMKey(t, otherGW, alice, llmKeyExpiry(llmKeyDay))
	assert.Equal(t, http.StatusCreated, status, "one key on each gateway")

	status, _ = llmKeyRequest(t, http.MethodGet, gwID, userToken(t, "another-tenant", alice), "", nil)
	assert.Equal(t, http.StatusNotFound, status, "a user of another tenant does not see the gateway")
	status, _ = llmKeyRequest(t, http.MethodGet, gwID, AdminToken, "", nil)
	assert.Equal(t, http.StatusForbidden, status, "a token without a user holds no key")
}

func TestLLMKey_AdminPlaneOnAnOwnedKey(t *testing.T) {
	defer Track(t, "LLMKey")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("llm-key-admin")})
	owner := uniqueName("dave")
	status, created := CreateLLMKey(t, gwID, owner, llmKeyExpiry(llmKeyDay))
	require.Equal(t, http.StatusCreated, status, "body=%v", created)
	keyID := fmt.Sprint(created["id"])
	authsURL := fmt.Sprintf("%s/v1/gateways/%s/auths", AdminURL, gwID)

	status, list := sendRequest(t, http.MethodGet, authsURL, nil, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", list)
	assert.NotContains(t, fmt.Sprint(list["items"]), keyID, "GET /auths hides personal keys")
	status, list = sendRequest(t, http.MethodGet, authsURL+"?owner_id="+owner, nil, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", list)
	assert.Contains(t, fmt.Sprint(list["items"]), keyID)
	status, got := sendRequest(t, http.MethodGet, authsURL+"/"+keyID, nil, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", got)
	assert.Equal(t, owner, got["owner_id"])

	status, resp := sendRequest(t, http.MethodPut, authsURL+"/"+keyID, nil, validAuthPayload("renamed"))
	assert.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", resp)
	assert.Equal(t, "owned_key", resp["error"])
	status, resp = sendRequest(t, http.MethodPost, authsURL+"/"+keyID+"/rotate", nil, nil)
	assert.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", resp)
	assert.Equal(t, "owned_key", resp["error"])

	status, _ = sendRequest(t, http.MethodDelete, authsURL+"/"+keyID, nil, nil)
	assert.Equal(t, http.StatusNoContent, status)
	status, _ = GetLLMKey(t, gwID, owner)
	assert.Equal(t, http.StatusNotFound, status, "the admin revocation removes the owner's key")
}

func TestLLMKey_AdminBudgetAndOwnedList(t *testing.T) {
	defer Track(t, "LLMKey")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("llm-key-budget")})
	alice, bob := uniqueName("alice"), uniqueName("bob")
	status, aliceKey := CreateLLMKey(t, gwID, alice, llmKeyExpiry(llmKeyDay))
	require.Equal(t, http.StatusCreated, status, "body=%v", aliceKey)
	status, bobKey := CreateLLMKey(t, gwID, bob, llmKeyExpiry(llmKeyDay))
	require.Equal(t, http.StatusCreated, status, "body=%v", bobKey)
	aliceID, bobID := fmt.Sprint(aliceKey["id"]), fmt.Sprint(bobKey["id"])
	appID, _ := CreateAPIKeyAuth(t, gwID, uniqueName("app-key"))
	authsURL := fmt.Sprintf("%s/v1/gateways/%s/auths", AdminURL, gwID)

	status, set := SetKeyBudget(t, gwID, aliceID, monthlyBudget(50))
	require.Equal(t, http.StatusOK, status, "body=%v", set)
	assert.Equal(t, map[string]any{"max": float64(50), "unit": "dollars", "time_window": "calendar_month"}, set["budget"])
	assert.Equal(t, alice, set["owner_id"])
	assert.NotContains(t, set, "api_key", "the secret is never returned")
	createdExpiry, err := time.Parse(time.RFC3339Nano, fmt.Sprint(aliceKey["expires_at"]))
	require.NoError(t, err)
	budgetExpiry, err := time.Parse(time.RFC3339Nano, fmt.Sprint(set["expires_at"]))
	require.NoError(t, err)
	assert.True(t, createdExpiry.Equal(budgetExpiry), "the expiry is untouched: %v, %v", createdExpiry, budgetExpiry)

	status, list := sendRequest(t, http.MethodGet, authsURL+"?owned=true", nil, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", list)
	assert.Equal(t, float64(2), list["total"])
	byID := map[string]map[string]any{}
	for _, item := range list["items"].([]any) {
		entry := item.(map[string]any)
		byID[fmt.Sprint(entry["id"])] = entry
	}
	require.Contains(t, byID, aliceID)
	require.Contains(t, byID, bobID)
	assert.NotContains(t, byID, appID, "owned=true lists no application key")
	assert.Equal(t, alice, byID[aliceID]["owner_id"])
	assert.Equal(t, set["budget"], byID[aliceID]["budget"])
	assert.Equal(t, bob, byID[bobID]["owner_id"])
	assert.NotContains(t, byID[bobID], "budget")
	status, list = sendRequest(t, http.MethodGet, authsURL+"?owned=true&size=1&page=2", nil, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", list)
	assert.Equal(t, float64(2), list["total"])
	assert.Len(t, list["items"], 1)
	status, list = sendRequest(t, http.MethodGet, authsURL, nil, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", list)
	assert.Contains(t, fmt.Sprint(list["items"]), appID)
	assert.NotContains(t, fmt.Sprint(list["items"]), aliceID, "without owned, personal keys stay hidden")
	status, resp := sendRequest(t, http.MethodGet, authsURL+"?owned=true&owner_id="+alice, nil, nil)
	assert.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", resp)
	assert.Equal(t, "invalid_filter", resp["error"])

	status, resp = SetKeyBudget(t, gwID, appID, monthlyBudget(50))
	assert.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", resp)
	assert.Equal(t, "application_key", resp["error"])
	status, resp = SetKeyBudget(t, gwID, uuid.NewString(), monthlyBudget(50))
	assert.Equal(t, http.StatusNotFound, status, "body=%v", resp)
	otherGW := CreateGateway(t, map[string]any{"slug": uniqueName("llm-key-budget-other")})
	status, resp = SetKeyBudget(t, otherGW, aliceID, monthlyBudget(50))
	assert.Equal(t, http.StatusNotFound, status, "body=%v", resp)
	for _, body := range []any{
		map[string]any{"max": 0, "unit": "dollars", "time_window": "calendar_month"},
		map[string]any{"max": 50, "unit": "dollars", "time_window": "1h"},
		map[string]any{"max": 50, "time_window": "calendar_month"},
		map[string]any{"max": 0.5, "unit": "tokens", "time_window": "calendar_month"},
		map[string]any{"max": 50},
		map[string]any{},
	} {
		status, resp = SetKeyBudget(t, gwID, aliceID, body)
		assert.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", resp)
		assert.Equal(t, "validation_failed", resp["error"], "%v", body)
	}

	status, rotated := RotateLLMKey(t, gwID, alice, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", rotated)
	status, got := sendRequest(t, http.MethodGet, authsURL+"/"+aliceID, nil, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", got)
	assert.Equal(t, set["budget"], got["budget"], "a rotation keeps the budget")
	status, resp = sendRequest(t, http.MethodPut, authsURL+"/"+aliceID, nil, validAuthPayload("renamed"))
	assert.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", resp)
	assert.Equal(t, "owned_key", resp["error"], "the budget route does not open the admin update to owned keys")

	status, cleared := SetKeyBudget(t, gwID, aliceID, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", cleared)
	assert.NotContains(t, cleared, "budget")
	status, got = sendRequest(t, http.MethodGet, authsURL+"/"+aliceID, nil, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", got)
	assert.NotContains(t, got, "budget")
}

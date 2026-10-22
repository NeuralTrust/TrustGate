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

	status, _ := CreateLLMKey(t, gwID, alice, llmKeyExpiry(366*llmKeyDay+time.Hour))
	assert.Equal(t, http.StatusUnprocessableEntity, status, "the expiry is capped at 366 days")
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
	status, _ = RotateLLMKey(t, gwID, bob, llmKeyExpiry(367*llmKeyDay))
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

	status, renewed := RotateLLMKey(t, gwID, alice, map[string]any{"never_expires": true})
	require.Equal(t, http.StatusOK, status, "body=%v", renewed)
	assert.Nil(t, renewed["expires_at"], "never_expires renews the key with no expiry")
	status, kept := RotateLLMKey(t, gwID, alice, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", kept)
	assert.Nil(t, kept["expires_at"], "a key that never expires stays so")
	status, _ = RotateLLMKey(t, gwID, alice, map[string]any{"never_expires": true, "expires_at": time.Now().Add(llmKeyDay).UTC().Format(time.RFC3339)})
	assert.Equal(t, http.StatusUnprocessableEntity, status, "expires_at and never_expires cannot be combined")
	status, yearLong := RotateLLMKey(t, gwID, alice, llmKeyExpiry(365*llmKeyDay))
	require.Equal(t, http.StatusOK, status, "body=%v", yearLong)
	assert.NotNil(t, yearLong["expires_at"])

	thirdGW := CreateGateway(t, map[string]any{"slug": uniqueName("llm-key-forever")})
	status, forever := CreateLLMKey(t, thirdGW, alice, map[string]any{})
	require.Equal(t, http.StatusCreated, status, "body=%v", forever)
	assert.Nil(t, forever["expires_at"], "without expires_at the key never expires")

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

// A key is shown under the person who holds it: it records the email their
// Portal sign-in carries, the console's reconcile fills it in on a key made
// before, and a rotation keeps it.
func TestLLMKey_RecordsItsOwnersEmail(t *testing.T) {
	defer Track(t, "LLMKey")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("llm-key-email")})
	owner := uniqueName("erin")
	status, created := llmKeyRequest(t, http.MethodPost, gwID, userTokenWithEmail(t, functionalTenantID, owner, "erin@acme.test"), "", llmKeyExpiry(llmKeyDay))
	require.Equal(t, http.StatusCreated, status, "body=%v", created)
	keyURL := fmt.Sprintf("%s/v1/gateways/%s/auths/%s", AdminURL, gwID, created["id"])

	status, got := sendRequest(t, http.MethodGet, keyURL, nil, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", got)
	assert.Equal(t, "erin@acme.test", got["owner_email"])

	status, set := sendRequest(t, http.MethodPut, keyURL+"/groups", nil, map[string]any{"groups": []string{"eng"}, "email": "erin@new.acme.test"})
	require.Equal(t, http.StatusOK, status, "body=%v", set)
	assert.Equal(t, "erin@new.acme.test", set["owner_email"])
	status, set = sendRequest(t, http.MethodPut, keyURL+"/groups", nil, map[string]any{"groups": []string{"eng", "sre"}})
	require.Equal(t, http.StatusOK, status, "body=%v", set)
	assert.Equal(t, "erin@new.acme.test", set["owner_email"], "a body without an email leaves it")
	status, set = sendRequest(t, http.MethodPut, keyURL+"/groups", nil, map[string]any{"groups": []string{"eng"}, "email": "erin"})
	assert.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", set)

	status, rotated := RotateLLMKey(t, gwID, owner, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", rotated)
	status, got = sendRequest(t, http.MethodGet, keyURL, nil, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", got)
	assert.Equal(t, "erin@new.acme.test", got["owner_email"], "a rotation keeps it")
	assert.Equal(t, []any{"eng", "sre"}, got["owner_groups"])
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

func llmKeysRequest(t *testing.T, method, gatewayID, userID, suffix string, body any) (int, map[string]any) {
	t.Helper()
	url := fmt.Sprintf("%s/v1/gateways/%s/store/principal/llm-keys%s", AdminURL, gatewayID, suffix)
	return sendRequest(t, method, url, map[string]string{"Authorization": "Bearer " + userToken(t, functionalTenantID, userID)}, body)
}

func itemIDs(t *testing.T, list map[string]any) []string {
	t.Helper()
	items, ok := list["items"].([]any)
	require.True(t, ok, "items: %v", list)
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, fmt.Sprint(item.(map[string]any)["id"]))
	}
	return out
}

// A user holds their personal key and one key per directory group: an admin
// issues the group keys, the user lists them and rotates or revokes each by
// id, and the routes for the personal key never touch a group key.
func TestLLMKey_GroupKeys(t *testing.T) {
	defer Track(t, "LLMKey")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("llm-key-groups")})
	alice, bob, admin := uniqueName("alice"), uniqueName("bob"), uniqueName("admin")
	issue := func(owner string, body map[string]any) (int, map[string]any) {
		t.Helper()
		url := fmt.Sprintf("%s/v1/gateways/%s/store/users/%s/llm-key", AdminURL, gwID, owner)
		return sendRequest(t, http.MethodPost, url, map[string]string{"Authorization": "Bearer " + userToken(t, functionalTenantID, admin)}, body)
	}

	status, personal := CreateLLMKey(t, gwID, alice, map[string]any{})
	require.Equal(t, http.StatusCreated, status, "body=%v", personal)
	assert.NotContains(t, personal, "group_id")
	status, eng := issue(alice, map[string]any{"group_id": "g-eng", "group_name": " engineering ", "expires_at": time.Now().Add(30 * llmKeyDay).UTC().Format(time.RFC3339)})
	require.Equal(t, http.StatusCreated, status, "body=%v", eng)
	assert.Equal(t, "g-eng", eng["group_id"])
	assert.Equal(t, "engineering", eng["group_name"])
	assert.True(t, strings.HasPrefix(fmt.Sprint(eng["api_key"]), "ag_"))
	status, sre := issue(alice, map[string]any{"group_id": "g-sre", "group_name": "sre"})
	require.Equal(t, http.StatusCreated, status, "body=%v", sre)
	assert.Nil(t, sre["expires_at"])
	status, _ = issue(bob, map[string]any{"group_id": "g-eng", "group_name": "engineering"})
	assert.Equal(t, http.StatusCreated, status, "another user holds their own key for the group")

	status, resp := issue(alice, map[string]any{"group_id": "g-eng", "group_name": "engineering"})
	assert.Equal(t, http.StatusConflict, status, "one key per user and group: %v", resp)
	status, resp = issue(alice, map[string]any{})
	assert.Equal(t, http.StatusConflict, status, "and one personal key: %v", resp)
	status, resp = issue(alice, map[string]any{"group_id": "g-ops"})
	assert.Equal(t, http.StatusUnprocessableEntity, status, "a group needs its name: %v", resp)
	status, resp = issue(alice, map[string]any{"group_name": "ops"})
	assert.Equal(t, http.StatusUnprocessableEntity, status, "a name needs its group: %v", resp)

	personalID, engID, sreID := fmt.Sprint(personal["id"]), fmt.Sprint(eng["id"]), fmt.Sprint(sre["id"])
	status, list := llmKeysRequest(t, http.MethodGet, gwID, alice, "", nil)
	require.Equal(t, http.StatusOK, status, "body=%v", list)
	assert.Equal(t, []string{sreID, engID, personalID}, itemIDs(t, list), "every key of the caller, newest first")
	assert.NotContains(t, fmt.Sprint(list), "api_key", "the secrets are never read back")
	status, got := GetLLMKey(t, gwID, alice)
	require.Equal(t, http.StatusOK, status, "body=%v", got)
	assert.Equal(t, personalID, got["id"], "the personal key route reads the personal key")

	authsURL := fmt.Sprintf("%s/v1/gateways/%s/auths", AdminURL, gwID)
	status, owned := sendRequest(t, http.MethodGet, authsURL+"?owner_id="+alice, nil, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", owned)
	assert.Equal(t, float64(3), owned["total"], "owner_id lists every key of the owner")
	assert.Contains(t, fmt.Sprint(owned["items"]), "group_name:engineering")

	status, rotated := llmKeysRequest(t, http.MethodPost, gwID, alice, "/"+engID+"/rotate", map[string]any{"never_expires": true})
	require.Equal(t, http.StatusOK, status, "body=%v", rotated)
	assert.Equal(t, engID, rotated["id"])
	assert.Equal(t, "g-eng", rotated["group_id"], "a rotation keeps the group")
	assert.Nil(t, rotated["expires_at"])
	assert.NotEqual(t, eng["api_key"], rotated["api_key"])
	status, _ = llmKeysRequest(t, http.MethodPost, gwID, bob, "/"+engID+"/rotate", nil)
	assert.Equal(t, http.StatusNotFound, status, "another user's key is not found")
	assert.Equal(t, http.StatusNotFound, func() int { s, _ := llmKeysRequest(t, http.MethodDelete, gwID, bob, "/"+engID, nil); return s }())
	appID, _ := CreateAPIKeyAuth(t, gwID, uniqueName("app-key"))
	status, _ = llmKeysRequest(t, http.MethodDelete, gwID, alice, "/"+appID, nil)
	assert.Equal(t, http.StatusNotFound, status, "an application key is nobody's")

	keyURL := authsURL + "/" + engID + "/groups"
	status, renamed := sendRequest(t, http.MethodPut, keyURL, nil, map[string]any{"groups": []string{"platform engineering", "sre"}, "group_name": "platform engineering"})
	require.Equal(t, http.StatusOK, status, "body=%v", renamed)
	assert.Equal(t, "g-eng", renamed["group_id"])
	assert.Equal(t, "platform engineering", renamed["group_name"])
	status, resp = sendRequest(t, http.MethodPut, authsURL+"/"+personalID+"/groups", nil, map[string]any{"groups": []string{"sre"}, "group_name": "sre"})
	assert.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", resp)
	assert.Equal(t, "personal_key", resp["error"])

	status, _ = llmKeysRequest(t, http.MethodDelete, gwID, alice, "/"+engID, nil)
	assert.Equal(t, http.StatusNoContent, status)
	assert.Equal(t, http.StatusNoContent, RevokeLLMKey(t, gwID, alice), "the personal key route revokes the personal key")
	status, list = llmKeysRequest(t, http.MethodGet, gwID, alice, "", nil)
	require.Equal(t, http.StatusOK, status, "body=%v", list)
	assert.Equal(t, []string{sreID}, itemIDs(t, list), "the other group key stays")
	status, _ = GetLLMKey(t, gwID, alice)
	assert.Equal(t, http.StatusNotFound, status, "no personal key, though a group key remains")
}

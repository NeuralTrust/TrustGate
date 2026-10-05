//go:build functional

package functional_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

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
	assert.True(t, strings.HasPrefix(fmt.Sprint(created["key"]), "ag_"), "create returns the secret once: %v", created)
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
	assert.NotEqual(t, created["key"], rotated["key"])
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

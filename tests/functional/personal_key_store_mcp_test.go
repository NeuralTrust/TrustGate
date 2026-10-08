//go:build functional

package functional_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// storeMCP posts one JSON-RPC call to the gateway's MCP Store with apiKey.
func storeMCP(t *testing.T, gatewayID, apiKey, method string) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": map[string]any{}})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, MCPURL+"/store/mcp", strings.NewReader(string(raw)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-AG-API-Key", apiKey)
	host, ok := gatewayHosts.Load(gatewayID)
	require.True(t, ok, "gateway host missing for %s", gatewayID)
	req.Host = host.(string)
	return doJSONRequest(t, req)
}

func whoAmIOnGateway(t *testing.T, gatewayID, apiKey string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, MCPURL+"/whoami", nil)
	require.NoError(t, err)
	req.Header.Set("X-AG-API-Key", apiKey)
	host, ok := gatewayHosts.Load(gatewayID)
	require.True(t, ok, "gateway host missing for %s", gatewayID)
	req.Host = host.(string)
	return doJSONRequest(t, req)
}

func doJSONRequest(t *testing.T, req *http.Request) (int, map[string]any) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	out := map[string]any{}
	if len(body) > 0 && json.Unmarshal(body, &out) != nil {
		out = map[string]any{"_raw": string(body)}
	}
	return resp.StatusCode, out
}

// The Portal's personal key opens its owner's MCP Store, with the groups the
// platform recorded on it, and describes itself as a person's key.
func TestPersonalKey_OpensTheMCPStoreAsItsOwner(t *testing.T) {
	defer Track(t, "LLMKey")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("personal-mcp")})
	alice := uniqueName("alice")
	status, issued := CreateLLMKey(t, gwID, alice, llmKeyExpiry(llmKeyDay))
	require.Equal(t, http.StatusCreated, status, "body=%v", issued)
	keyID, rawKey := fmt.Sprint(issued["id"]), fmt.Sprint(issued["api_key"])

	groupsURL := fmt.Sprintf("%s/v1/gateways/%s/auths/%s/groups", AdminURL, gwID, keyID)
	status, set := sendRequest(t, http.MethodPut, groupsURL, nil, map[string]any{"groups": []string{"sre", " engineering", "sre"}})
	require.Equal(t, http.StatusOK, status, "body=%v", set)
	assert.Equal(t, []any{"engineering", "sre"}, set["owner_groups"])
	assert.Equal(t, alice, set["owner_id"])
	assert.NotContains(t, set, "api_key", "the secret is never returned")

	status, listed := storeMCP(t, gwID, rawKey, "tools/list")
	require.Equal(t, http.StatusOK, status, "body=%v", listed)
	require.NotContains(t, listed, "error", "the Store answers its owner: %v", listed)
	require.Contains(t, listed, "result")

	status, described := whoAmIOnGateway(t, gwID, rawKey)
	require.Equal(t, http.StatusOK, status, "body=%v", described)
	key, _ := described["key"].(map[string]any)
	assert.Equal(t, true, key["personal"])
	consumers, _ := described["consumers"].([]any)
	require.NotEmpty(t, consumers)
	store, _ := consumers[0].(map[string]any)
	assert.Equal(t, "store", store["slug"])
	assert.Equal(t, "MCP", store["type"])
	assert.True(t, strings.HasSuffix(fmt.Sprint(store["url"]), "/store/mcp"), "url=%v", store["url"])

	_, appKey := CreateAPIKeyAuth(t, gwID, uniqueName("app-key"))
	status, refused := storeMCP(t, gwID, appKey, "tools/list")
	assert.Equal(t, http.StatusUnauthorized, status, "an application key stays off the Store: %v", refused)

	appID, _ := CreateAPIKeyAuth(t, gwID, uniqueName("app-key"))
	status, resp := sendRequest(t, http.MethodPut, fmt.Sprintf("%s/v1/gateways/%s/auths/%s/groups", AdminURL, gwID, appID), nil, map[string]any{"groups": []string{"sre"}})
	assert.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", resp)
	assert.Equal(t, "application_key", resp["error"])

	status = RevokeLLMKey(t, gwID, alice)
	require.Equal(t, http.StatusNoContent, status)
	status, refused = storeMCP(t, gwID, rawKey, "tools/list")
	assert.Equal(t, http.StatusUnauthorized, status, "a revoked key opens nothing: %v", refused)
}

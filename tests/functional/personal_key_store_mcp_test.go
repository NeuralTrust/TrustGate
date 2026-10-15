//go:build functional

package functional_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// storeMCP posts one JSON-RPC call to the gateway's MCP Store with apiKey.
func storeMCP(t *testing.T, gatewayID, apiKey, method string) (int, map[string]any) {
	t.Helper()
	return storeMCPWith(t, gatewayID, apiKey, method, map[string]any{})
}

// storeMCPWith is storeMCP with the call's params.
func storeMCPWith(t *testing.T, gatewayID, apiKey, method string, params map[string]any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
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

// A person who installed a server that signs in with their own account, and
// has not connected it, connects it the way every Store client does: by
// installing it again, which hands back the link to that server's connect
// page. The Store lists no trustgate_connect_* tool, so there is one way in.
func TestPersonalKey_StoreConnectsAnInstalledServerThroughInstall(t *testing.T) {
	defer Track(t, "LLMKey")()
	idp := newOAuthProviderStub(t)
	upstream, _ := startCapturingMCPUpstream(t, func(s *sdk.Server) { addTool(s, "echo") })
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("personal-connect")})
	provider := uniqueName("linear")
	regID := CreateRegistry(t, gwID, mcpForwardedRegistryPayload(uniqueName("Linear"), upstream.URL, provider, idp))
	parsed, err := ids.Parse[ids.RegistryKind](regID)
	require.NoError(t, err)
	code := registrydomain.CustomStoreCode(parsed)
	alice := uniqueName("alice")

	status, granted := sendRequest(t, http.MethodPut, fmt.Sprintf("%s/v1/gateways/%s/store/grants", AdminURL, gwID), nil,
		map[string]any{"catalog_code": code, "users": []string{alice}})
	require.Equal(t, http.StatusOK, status, "body=%v", granted)
	status, installed := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/v1/gateways/%s/store/principal/installs", AdminURL, gwID), nil,
		map[string]any{"principal_sub": alice, "code": code})
	require.Equal(t, http.StatusOK, status, "body=%v", installed)
	require.Equal(t, "installed", installed["status"], "body=%v", installed)

	status, issued := CreateLLMKey(t, gwID, alice, llmKeyExpiry(llmKeyDay))
	require.Equal(t, http.StatusCreated, status, "body=%v", issued)
	rawKey := fmt.Sprint(issued["api_key"])

	names := storeToolNames(t, gwID, rawKey)
	assert.Contains(t, names, "trustgate_store_install")
	for _, name := range names {
		assert.False(t, strings.HasPrefix(name, "trustgate_connect_"), "the Store lists no connect tool: %v", names)
	}

	server := storeInventoryServer(t, gwID, rawKey)
	require.Equal(t, "needs_connect", server["state"], "server=%v", server)
	require.Equal(t, "trustgate_store_install", server["connect_tool"], "server=%v", server)
	require.Equal(t, code, server["code"], "server=%v", server)

	status, called := storeMCPWith(t, gwID, rawKey, "tools/call", map[string]any{
		"name": "trustgate_store_install", "arguments": map[string]any{"code": code},
	})
	result := requireRPCSucceeded(t, status, called)
	structured, _ := result["structuredContent"].(map[string]any)
	assert.Equal(t, true, structured["already_installed"], "body=%v", called)
	link, err := url.Parse(fmt.Sprint(structured["connect_url"]))
	require.NoError(t, err, "body=%v", called)
	require.Equal(t, "/store/mcp/connect", link.Path, "body=%v", called)
	ticket := link.Query().Get("ticket")
	require.NotEmpty(t, ticket)

	// The ticket names the server, so the provider's consent goes through it.
	driveProviderConsent(t, idp, provider, ticket)
	assert.Equal(t, "ready", storeInventoryServer(t, gwID, rawKey)["state"], "a connected server serves")
}

// storeToolNames is what tools/list on the Store offers the key's owner.
func storeToolNames(t *testing.T, gatewayID, apiKey string) []string {
	t.Helper()
	status, listed := storeMCP(t, gatewayID, apiKey, "tools/list")
	result := requireRPCSucceeded(t, status, listed)
	tools, _ := result["tools"].([]any)
	names := make([]string, 0, len(tools))
	for _, raw := range tools {
		tool, _ := raw.(map[string]any)
		names = append(names, fmt.Sprint(tool["name"]))
	}
	return names
}

// storeInventoryServer is the one server trustgate_list_tools reports.
func storeInventoryServer(t *testing.T, gatewayID, apiKey string) map[string]any {
	t.Helper()
	status, called := storeMCPWith(t, gatewayID, apiKey, "tools/call", map[string]any{
		"name": "trustgate_list_tools", "arguments": map[string]any{},
	})
	result := requireRPCSucceeded(t, status, called)
	structured, _ := result["structuredContent"].(map[string]any)
	servers, _ := structured["servers"].([]any)
	require.Len(t, servers, 1, "body=%v", called)
	server, _ := servers[0].(map[string]any)
	return server
}

// The Store hands its owner a link to the personal key page, on this gateway's
// host. The link alone opens nothing: a browser that has not signed in as its
// owner is sent to sign in, and on a gateway with no sign-in to send it to the
// page says so — it never shows a key.
func TestPersonalKey_StoreLinksThePersonalKeyPage(t *testing.T) {
	defer Track(t, "LLMKey")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("personal-page")})
	alice := uniqueName("alice")
	status, issued := CreateLLMKey(t, gwID, alice, llmKeyExpiry(llmKeyDay))
	require.Equal(t, http.StatusCreated, status, "body=%v", issued)
	rawKey := fmt.Sprint(issued["api_key"])

	assert.Contains(t, storeToolNames(t, gwID, rawKey), "trustgate_store_personal_key")

	status, called := storeMCPWith(t, gwID, rawKey, "tools/call", map[string]any{
		"name": "trustgate_store_personal_key", "arguments": map[string]any{},
	})
	result := requireRPCSucceeded(t, status, called)
	structured, _ := result["structuredContent"].(map[string]any)
	link, err := url.Parse(fmt.Sprint(structured["personal_key_url"]))
	require.NoError(t, err, "body=%v", called)
	require.Equal(t, "/store/mcp/personal-key", link.Path)
	host, _ := gatewayHosts.Load(gwID)
	require.Equal(t, host, link.Host, "the page is on the gateway the link was minted for")
	require.NotEmpty(t, link.Query().Get("ticket"))
	text := fmt.Sprint(result["content"])
	assert.NotContains(t, text, rawKey, "the model never sees a key")

	req, err := http.NewRequest(http.MethodGet, MCPURL+link.RequestURI(), nil)
	require.NoError(t, err)
	req.Host = link.Host
	resp, err := noRedirectClient().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	assert.NotEqual(t, http.StatusOK, resp.StatusCode, "a browser that has not signed in sees no page: %s", body)
	assert.NotContains(t, string(body), "ag_", "no key is shown before the browser signs in")
}

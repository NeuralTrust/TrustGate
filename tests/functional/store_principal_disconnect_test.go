//go:build functional

package functional_test

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

// principalConnection is the Portal's view of one user's account on one
// instance.
func principalConnection(t *testing.T, gatewayID, sub, registryID string) map[string]any {
	t.Helper()
	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/store/principal?sub=%s", AdminURL, gatewayID, url.QueryEscape(sub)), nil, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	connections, _ := body["connections"].([]any)
	for _, raw := range connections {
		conn, _ := raw.(map[string]any)
		if conn["registry_id"] == registryID {
			return conn
		}
	}
	t.Fatalf("no connection for %s: %v", registryID, body)
	return nil
}

func disconnectAs(t *testing.T, gatewayID, registryID, token string) (int, map[string]any) {
	t.Helper()
	return sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s/store/principal/connections/%s", AdminURL, gatewayID, registryID),
		map[string]string{"Authorization": "Bearer " + token}, nil)
}

// A user revokes the account they linked from the Portal: the credential is
// gone, the server asks them to connect again, and nobody else's account and
// no shared one can be revoked that way.
func TestStorePrincipal_DisconnectRevokesTheCallersOwnAccount(t *testing.T) {
	defer Track(t, "StorePrincipal")()
	idp := newOAuthProviderStub(t)
	upstream, _ := startCapturingMCPUpstream(t, func(s *sdk.Server) { addTool(s, "echo") })
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("portal-disconnect")})
	provider := uniqueName("linear")
	regID := CreateRegistry(t, gwID, mcpForwardedRegistryPayload(uniqueName("Linear"), upstream.URL, provider, idp))
	parsed, err := ids.Parse[ids.RegistryKind](regID)
	require.NoError(t, err)
	code := registrydomain.CustomStoreCode(parsed)
	alice, bob := uniqueName("alice"), uniqueName("bob")

	status, granted := sendRequest(t, http.MethodPut, fmt.Sprintf("%s/v1/gateways/%s/store/grants", AdminURL, gwID), nil,
		map[string]any{"catalog_code": code, "users": []string{alice}})
	require.Equal(t, http.StatusOK, status, "body=%v", granted)
	status, installed := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/v1/gateways/%s/store/principal/installs", AdminURL, gwID), nil,
		map[string]any{"principal_sub": alice, "code": code})
	require.Equal(t, http.StatusOK, status, "body=%v", installed)
	status, issued := CreateLLMKey(t, gwID, alice, llmKeyExpiry(llmKeyDay))
	require.Equal(t, http.StatusCreated, status, "body=%v", issued)
	rawKey := fmt.Sprint(issued["api_key"])

	status, called := storeMCPWith(t, gwID, rawKey, "tools/call", map[string]any{
		"name": "trustgate_store_install", "arguments": map[string]any{"code": code},
	})
	structured, _ := requireRPCSucceeded(t, status, called)["structuredContent"].(map[string]any)
	link, err := url.Parse(fmt.Sprint(structured["connect_url"]))
	require.NoError(t, err, "body=%v", called)
	driveProviderConsent(t, idp, provider, link.Query().Get("ticket"))
	require.Equal(t, true, principalConnection(t, gwID, alice, regID)["linked"])
	require.Equal(t, "ready", storeInventoryServer(t, gwID, rawKey)["state"])

	status, refused := disconnectAs(t, gwID, regID, AdminToken)
	require.Equal(t, http.StatusForbidden, status, "a token without a user revokes nothing: %v", refused)
	status, body := disconnectAs(t, gwID, regID, userToken(t, functionalTenantID, bob))
	require.Equal(t, http.StatusNoContent, status, "body=%v", body)
	require.Equal(t, true, principalConnection(t, gwID, alice, regID)["linked"], "bob holds no account here, and alice's is not his to revoke")

	status, body = disconnectAs(t, gwID, regID, userToken(t, functionalTenantID, alice))
	require.Equal(t, http.StatusNoContent, status, "body=%v", body)
	require.Equal(t, false, principalConnection(t, gwID, alice, regID)["linked"])
	// Her next call is refused at once, with the link to connect again, and the
	// server leaves her tool list for the needs_connect entry.
	tools, _ := storeInventoryServer(t, gwID, rawKey)["tools"].([]any)
	require.NotEmpty(t, tools)
	tool, _ := tools[0].(map[string]any)
	status, refusedCall := storeMCPWith(t, gwID, rawKey, "tools/call", map[string]any{"name": tool["name"], "arguments": map[string]any{"message": "hola"}})
	require.Equal(t, http.StatusOK, status)
	rpcErr, _ := refusedCall["error"].(map[string]any)
	require.Equal(t, float64(-32003), rpcErr["code"], "body=%v", refusedCall)
	data, _ := rpcErr["data"].(map[string]any)
	require.Equal(t, "no_credential", data["cause"], "body=%v", refusedCall)
	require.NotEmpty(t, data["connect_url"], "body=%v", refusedCall)
	require.Equal(t, "needs_connect", storeInventoryServer(t, gwID, rawKey)["state"], "the server asks her to connect again")
	status, body = disconnectAs(t, gwID, regID, userToken(t, functionalTenantID, alice))
	require.Equal(t, http.StatusNoContent, status, "revoking again is already done: %v", body)

	shared := newForwardedFixture(t, true)
	status, body = disconnectAs(t, shared.gatewayID, shared.registryID, userToken(t, functionalTenantID, alice))
	require.Equal(t, http.StatusConflict, status, "a shared account is the administrator's to disconnect: %v", body)
	status, body = disconnectAs(t, gwID, ids.New[ids.RegistryKind]().String(), userToken(t, functionalTenantID, alice))
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
}

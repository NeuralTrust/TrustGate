//go:build functional

package functional_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Everyone grants a server to every group key whose group passes it on: the
// key of an excluded group, and a key whose group is on None, see nothing
// through it. Removing Everyone takes the server away again.
func TestEveryone_GrantsTheStoreToPassingGroupKeys(t *testing.T) {
	defer Track(t, "StoreEveryone")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("store-everyone")})
	alice, admin := uniqueName("alice"), uniqueName("admin")
	upstream := startMCPUpstream(t, func(s *sdk.Server) { addTool(s, "echo") })
	parsed, err := ids.Parse[ids.RegistryKind](CreateRegistry(t, gwID, mcpRegistryPayload(uniqueName("Linear"), upstream.URL)))
	require.NoError(t, err)
	code := registrydomain.CustomStoreCode(parsed)
	grantsURL := fmt.Sprintf("%s/v1/gateways/%s/store/grants", AdminURL, gwID)
	everyoneURL := fmt.Sprintf("%s/v1/gateways/%s/store/everyone", AdminURL, gwID)

	status, granted := sendRequest(t, http.MethodPut, grantsURL, nil, map[string]any{"catalog_code": code, "users": []string{alice}})
	require.Equal(t, http.StatusOK, status, "body=%v", granted)
	status, installed := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/v1/gateways/%s/store/principal/installs", AdminURL, gwID), nil,
		map[string]any{"principal_sub": alice, "code": code})
	require.Equal(t, http.StatusOK, status, "body=%v", installed)
	status, cleared := sendRequest(t, http.MethodPut, grantsURL, nil, map[string]any{"catalog_code": code})
	require.Equal(t, http.StatusOK, status, "body=%v", cleared)

	issue := func(groupID, groupName string) map[string]any {
		t.Helper()
		url := fmt.Sprintf("%s/v1/gateways/%s/store/users/%s/llm-key", AdminURL, gwID, alice)
		status, issued := sendRequest(t, http.MethodPost, url, map[string]string{"Authorization": "Bearer " + userToken(t, functionalTenantID, admin)},
			map[string]any{"group_id": groupID, "group_name": groupName})
		require.Equal(t, http.StatusCreated, status, "body=%v", issued)
		return issued
	}
	eng, contractors, sales := issue("g-eng", "eng"), issue("g-contractors", "contractors"), issue("g-sales", "sales")
	for _, key := range []map[string]any{eng, contractors, sales} {
		groupsURL := fmt.Sprintf("%s/v1/gateways/%s/auths/%s/groups", AdminURL, gwID, key["id"])
		status, set := sendRequest(t, http.MethodPut, groupsURL, nil, map[string]any{"groups": []string{"eng", "contractors", "sales"}})
		require.Equal(t, http.StatusOK, status, "body=%v", set)
	}
	status, policy := sendRequest(t, http.MethodPut, fmt.Sprintf("%s/v1/gateways/%s/store/access-policies", AdminURL, gwID), nil,
		map[string]any{"principal_type": "group", "principal_id": "sales", "mode": "curated"})
	require.Equal(t, http.StatusOK, status, "body=%v", policy)
	require.Empty(t, storeInventoryCodes(t, gwID, fmt.Sprint(eng["api_key"])), "without Everyone the server is granted to nobody")

	status, body := sendRequest(t, http.MethodPut, everyoneURL, nil, map[string]any{"mode": "none"})
	require.Equal(t, http.StatusUnprocessableEntity, status, "none is refused; body=%v", body)
	status, body = sendRequest(t, http.MethodPut, everyoneURL, nil, map[string]any{"mode": "curated"})
	require.Equal(t, http.StatusUnprocessableEntity, status, "curated without grants is refused; body=%v", body)

	status, saved := sendRequest(t, http.MethodPut, everyoneURL, nil, map[string]any{
		"mode": "curated", "grants": []map[string]any{{"catalog_code": code}}, "excluded_groups": []string{"contractors"},
	})
	require.Equal(t, http.StatusOK, status, "body=%v", saved)
	status, read := sendRequest(t, http.MethodGet, everyoneURL, nil, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", read)
	assert.Equal(t, "curated", read["mode"])
	assert.Equal(t, []any{"contractors"}, read["excluded_groups"])

	assert.Equal(t, []string{code}, storeInventoryCodes(t, gwID, fmt.Sprint(eng["api_key"])), "a group without a policy passes Everyone on")
	assert.Equal(t, []string{code}, storeInventoryCodes(t, gwID, fmt.Sprint(sales["api_key"])), "a curated group passes Everyone on")
	assert.Empty(t, storeInventoryCodes(t, gwID, fmt.Sprint(contractors["api_key"])), "an excluded group's key gets nothing from Everyone")

	status, policy = sendRequest(t, http.MethodPut, fmt.Sprintf("%s/v1/gateways/%s/store/access-policies", AdminURL, gwID), nil,
		map[string]any{"principal_type": "group", "principal_id": "sales", "mode": "none"})
	require.Equal(t, http.StatusOK, status, "body=%v", policy)
	assert.Empty(t, storeInventoryCodes(t, gwID, fmt.Sprint(sales["api_key"])), "a group on None does not pass Everyone on")

	installsURL := fmt.Sprintf("%s/v1/gateways/%s/store/principal/installs", AdminURL, gwID)
	bob, carol := uniqueName("bob"), uniqueName("carol")
	status, viaEveryone := sendRequest(t, http.MethodPost, installsURL, nil, map[string]any{"principal_sub": bob, "code": code, "groups": []string{"eng"}})
	require.Equal(t, http.StatusOK, status, "body=%v", viaEveryone)
	assert.Equal(t, "installed", viaEveryone["status"], "a server only Everyone grants installs without approval; body=%v", viaEveryone)
	status, excluded := sendRequest(t, http.MethodPost, installsURL, nil, map[string]any{"principal_sub": carol, "code": code, "groups": []string{"contractors"}, "reason": "triaging issues"})
	require.Equal(t, http.StatusOK, status, "body=%v", excluded)
	assert.Equal(t, "pending_approval", excluded["status"], "an excluded group still asks; body=%v", excluded)

	status, _ = sendRequest(t, http.MethodPut, everyoneURL, nil, map[string]any{"mode": ""})
	require.Equal(t, http.StatusNoContent, status)
	assert.Empty(t, storeInventoryCodes(t, gwID, fmt.Sprint(eng["api_key"])), "removing Everyone takes the server away")
}

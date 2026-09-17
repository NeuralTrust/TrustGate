//go:build functional

package functional_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdatePolicy_Success(t *testing.T) {
	defer Track(t, "UpdatePolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("polu-gw")})

	original := uniqueName("polu-from")
	id := CreatePolicy(t, gwID, validPolicyPayload(original))

	updated := uniqueName("polu-to")
	url := fmt.Sprintf("%s/v1/gateways/%s/policies/%s", AdminURL, gwID, id)
	status, body := sendRequest(t, http.MethodPut, url, nil, map[string]any{
		"name":    updated,
		"slug":    "request_size_limiter",
		"enabled": false,
		"settings": map[string]any{
			"allowed_payload_size": 1024,
			"size_unit":            "bytes",
		},
	})
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, updated, body["name"])
	assert.Equal(t, "request_size_limiter", body["slug"])
	assert.Equal(t, false, body["enabled"])

	status, body = sendRequest(t, http.MethodGet, url, nil, nil)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, updated, body["name"])
	assert.Equal(t, "request_size_limiter", body["slug"])
}

func TestUpdatePolicy_Partial(t *testing.T) {
	defer Track(t, "UpdatePolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("polu-partial-gw")})
	id := CreatePolicy(t, gwID, validPolicyPayload(uniqueName("polu-partial")))

	renamed := uniqueName("polu-partial-to")
	url := fmt.Sprintf("%s/v1/gateways/%s/policies/%s", AdminURL, gwID, id)
	status, body := sendRequest(t, http.MethodPut, url, nil, map[string]any{"name": renamed})
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, renamed, body["name"])

	status, body = sendRequest(t, http.MethodGet, url, nil, nil)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, renamed, body["name"])
	assert.Equal(t, "rate_limiter", body["slug"], "slug must be preserved on a partial update")
	assert.Equal(t, true, body["enabled"], "enabled must be preserved on a partial update")
	assert.NotNil(t, body["settings"], "settings must be preserved on a partial update")
}

func TestUpdatePolicy_NotFound(t *testing.T) {
	defer Track(t, "UpdatePolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("polu-gw2")})
	missing := uuid.NewString()
	url := fmt.Sprintf("%s/v1/gateways/%s/policies/%s", AdminURL, gwID, missing)
	status, body := sendRequest(t, http.MethodPut, url, nil, validPolicyPayload(uniqueName("polu-missing")))
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestUpdatePolicy_ValidationEmptyName(t *testing.T) {
	defer Track(t, "UpdatePolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("polu-gw3")})
	id := CreatePolicy(t, gwID, validPolicyPayload(uniqueName("polu-val")))

	url := fmt.Sprintf("%s/v1/gateways/%s/policies/%s", AdminURL, gwID, id)
	status, body := sendRequest(t, http.MethodPut, url, nil, map[string]any{"name": ""})
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestUpdatePolicy_NameConflict(t *testing.T) {
	defer Track(t, "UpdatePolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("polu-gw4")})
	a := uniqueName("polu-a")
	b := uniqueName("polu-b")
	_ = CreatePolicy(t, gwID, validPolicyPayload(a))
	bID := CreatePolicy(t, gwID, validPolicyPayload(b))

	url := fmt.Sprintf("%s/v1/gateways/%s/policies/%s", AdminURL, gwID, bID)
	status, body := sendRequest(t, http.MethodPut, url, nil, validPolicyPayload(a))
	require.Equal(t, http.StatusConflict, status, "body=%v", body)
	assert.Equal(t, "already_exists", body["error"])
}

// mcp_scope on PUT is tri-state: omitted keeps the stored scope, an object
// replaces it and null clears it.
func TestUpdatePolicy_MCPScopeTriState(t *testing.T) {
	defer Track(t, "UpdatePolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("polu-scope-gw")})
	first := createMCPRegistry(t, gwID)
	second := createMCPRegistry(t, gwID)
	id := CreatePolicy(t, gwID, scopedPolicyPayload(uniqueName("polu-scope"), map[string]any{
		"registry_ids": []string{first},
	}))
	url := fmt.Sprintf("%s/v1/gateways/%s/policies/%s", AdminURL, gwID, id)

	renamed := uniqueName("polu-scope-renamed")
	status, body := sendRequest(t, http.MethodPut, url, nil, map[string]any{"name": renamed})
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, renamed, body["name"])
	scope, _ := body["mcp_scope"].(map[string]any)
	assert.Equal(t, []any{first}, scope["registry_ids"], "omitted mcp_scope keeps the stored scope")

	status, body = sendRequest(t, http.MethodPut, url, nil, map[string]any{
		"mcp_scope": map[string]any{"tools": []map[string]any{{"registry_id": second, "tool": "run_query"}}},
	})
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	scope, _ = body["mcp_scope"].(map[string]any)
	assert.Nil(t, scope["registry_ids"], "an object replaces the whole scope")
	assert.Equal(t, []any{map[string]any{"registry_id": second, "tool": "run_query"}}, scope["tools"])

	status, body = sendRequest(t, http.MethodPut, url, nil, map[string]any{"mcp_scope": map[string]any{}})
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])

	status, body = sendRequest(t, http.MethodPut, url, nil, map[string]any{"mcp_scope": nil})
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	_, present := body["mcp_scope"]
	assert.False(t, present, "null clears the scope")

	got := getPolicy(t, gwID, id)
	_, present = got["mcp_scope"]
	assert.False(t, present, "the cleared scope is persisted")
	assert.Equal(t, renamed, got["name"])
}

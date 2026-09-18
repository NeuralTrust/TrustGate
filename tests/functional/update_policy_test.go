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

// An update is a write that can move a policy onto an occupied level: the two
// scopes below are two levels of the same consumer until one is rewritten into
// the other's.
func TestUpdatePolicy_ScopeMovingOntoAnOccupiedLevelRejected(t *testing.T) {
	defer Track(t, "UpdatePolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("polu-level-gw")})
	held := createMCPRegistry(t, gwID)
	free := createMCPRegistry(t, gwID)
	coID, _ := createMCPConsumer(t, gwID, []string{held, free}, nil, "")
	occupant := CreatePolicy(t, gwID, scopedPolicyPayload(uniqueName("polu-level-held"), map[string]any{
		"registry_ids": []string{held},
	}))
	mover := CreatePolicy(t, gwID, scopedPolicyPayload(uniqueName("polu-level-mover"), map[string]any{
		"registry_ids": []string{free},
	}))
	AttachPolicy(t, gwID, coID, occupant)
	AttachPolicy(t, gwID, coID, mover)

	url := fmt.Sprintf("%s/v1/gateways/%s/policies/%s", AdminURL, gwID, mover)
	status, body := sendRequest(t, http.MethodPut, url, nil, map[string]any{
		"mcp_scope": map[string]any{"registry_ids": []string{held}},
	})
	require.Equal(t, http.StatusConflict, status, "body=%v", body)
	assert.Equal(t, "conflict", body["error"])
	assert.Contains(t, body["message"], occupant)

	scope, _ := getPolicy(t, gwID, mover)["mcp_scope"].(map[string]any)
	assert.Equal(t, []any{free}, scope["registry_ids"], "the refused update is not stored")
}

// Enabling is the write the rule would be sidestepped by: a disabled policy
// occupies nothing, so it attaches next to a running one and the level is only
// taken when it is switched on. That is where the 409 has to be.
func TestUpdatePolicy_EnablingOntoAnOccupiedLevelRejected(t *testing.T) {
	defer Track(t, "UpdatePolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("polu-enable-gw")})
	coID := CreateConsumer(t, gwID, validConsumerPayload(uniqueName("polu-enable-co")))
	running := CreatePolicy(t, gwID, validPolicyPayload(uniqueName("polu-enable-running")))
	disabled := validPolicyPayload(uniqueName("polu-enable-off"))
	disabled["enabled"] = false
	off := CreatePolicy(t, gwID, disabled)
	AttachPolicy(t, gwID, coID, running)
	AttachPolicy(t, gwID, coID, off)

	url := fmt.Sprintf("%s/v1/gateways/%s/policies/%s", AdminURL, gwID, off)
	status, body := sendRequest(t, http.MethodPut, url, nil, map[string]any{"enabled": true})
	require.Equal(t, http.StatusConflict, status, "body=%v", body)
	assert.Equal(t, "conflict", body["error"])
	assert.Contains(t, body["message"], running)
	assert.Equal(t, false, getPolicy(t, gwID, off)["enabled"], "the refused enable is not stored")
}

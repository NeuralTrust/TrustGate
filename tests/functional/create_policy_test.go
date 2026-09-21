//go:build functional

package functional_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreatePolicy_Success(t *testing.T) {
	defer Track(t, "CreatePolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("pol-gw")})

	name := uniqueName("pol-ok")
	url := fmt.Sprintf("%s/v1/gateways/%s/policies", AdminURL, gwID)
	status, body := sendRequest(t, http.MethodPost, url, nil, validPolicyPayload(name))

	require.Equal(t, http.StatusCreated, status, "body=%v", body)
	assert.Equal(t, name, body["name"])
	assert.Equal(t, gwID, body["gateway_id"])
	assert.NotEmpty(t, body["id"])
	assert.NotEmpty(t, body["created_at"])
	assert.NotEmpty(t, body["updated_at"])

	assert.Equal(t, "rate_limiter", body["slug"])
	assert.Equal(t, true, body["enabled"])
}

func TestCreatePolicy_WithDescription(t *testing.T) {
	defer Track(t, "CreatePolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("pol-gw-desc")})

	name := uniqueName("pol-desc")
	payload := validPolicyPayload(name)
	payload["description"] = "limits requests per minute"

	url := fmt.Sprintf("%s/v1/gateways/%s/policies", AdminURL, gwID)
	status, body := sendRequest(t, http.MethodPost, url, nil, payload)

	require.Equal(t, http.StatusCreated, status, "body=%v", body)
	assert.Equal(t, "limits requests per minute", body["description"])
}

func TestCreatePolicy_ValidationMissingSlug(t *testing.T) {
	defer Track(t, "CreatePolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("pol-gw2")})

	url := fmt.Sprintf("%s/v1/gateways/%s/policies", AdminURL, gwID)
	status, body := sendRequest(t, http.MethodPost, url, nil, map[string]any{
		"name": uniqueName("pol-noslug"),
	})
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreatePolicy_Conflict(t *testing.T) {
	defer Track(t, "CreatePolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("pol-gw3")})
	name := uniqueName("pol-dup")
	_ = CreatePolicy(t, gwID, validPolicyPayload(name))

	url := fmt.Sprintf("%s/v1/gateways/%s/policies", AdminURL, gwID)
	status, body := sendRequest(t, http.MethodPost, url, nil, validPolicyPayload(name))
	require.Equal(t, http.StatusConflict, status, "body=%v", body)
	assert.Equal(t, "already_exists", body["error"])
}

func TestCreatePolicy_AllowsSameNameAcrossGateways(t *testing.T) {
	defer Track(t, "CreatePolicy")()
	gw1 := CreateGateway(t, map[string]any{"slug": uniqueName("pol-gwA")})
	gw2 := CreateGateway(t, map[string]any{"slug": uniqueName("pol-gwB")})

	name := uniqueName("pol-cross")
	_ = CreatePolicy(t, gw1, validPolicyPayload(name))

	url := fmt.Sprintf("%s/v1/gateways/%s/policies", AdminURL, gw2)
	status, _ := sendRequest(t, http.MethodPost, url, nil, validPolicyPayload(name))
	require.Equal(t, http.StatusCreated, status)
}

func TestCreatePolicy_ValidationEmptyName(t *testing.T) {
	defer Track(t, "CreatePolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("pol-gw4")})

	url := fmt.Sprintf("%s/v1/gateways/%s/policies", AdminURL, gwID)
	status, body := sendRequest(t, http.MethodPost, url, nil, map[string]any{"name": ""})
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreatePolicy_ValidationUnknownStage(t *testing.T) {
	defer Track(t, "CreatePolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("pol-gw5")})

	payload := map[string]any{
		"name":   uniqueName("pol-stage"),
		"slug":   "rate_limiter",
		"stages": []string{"bogus_stage"},
	}
	url := fmt.Sprintf("%s/v1/gateways/%s/policies", AdminURL, gwID)
	status, body := sendRequest(t, http.MethodPost, url, nil, payload)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreatePolicy_GatewayNotFound(t *testing.T) {
	defer Track(t, "CreatePolicy")()
	missing := uuid.NewString()
	url := fmt.Sprintf("%s/v1/gateways/%s/policies", AdminURL, missing)
	status, body := sendRequest(t, http.MethodPost, url, nil, validPolicyPayload(uniqueName("pol-orphan")))
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreatePolicy_InvalidGatewayUUID(t *testing.T) {
	defer Track(t, "CreatePolicy")()
	status, body := sendRequest(t, http.MethodPost,
		AdminURL+"/v1/gateways/not-a-uuid/policies", nil,
		validPolicyPayload(uniqueName("pol-bad")),
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}

// scopedPolicyPayload is validPolicyPayload (rate_limiter, which declares the
// MCP protocol) plus the given mcp_scope object.
func scopedPolicyPayload(name string, scope map[string]any) map[string]any {
	payload := validPolicyPayload(name)
	payload["mcp_scope"] = scope
	return payload
}

// warningNaming returns the one warning that mentions needle. A write now
// answers with several warnings at once, so a test that cares about the
// consumer-overlap one has to pick it out rather than index the slice.
func warningNaming(t *testing.T, warnings []any, needle string) string {
	t.Helper()
	var found string
	for _, w := range warnings {
		text, ok := w.(string)
		if ok && strings.Contains(text, needle) {
			require.Empty(t, found, "more than one warning names %s: %v", needle, warnings)
			found = text
		}
	}
	require.NotEmpty(t, found, "no warning names %s: %v", needle, warnings)
	return found
}

// createMCPRegistry provisions an MCP registry whose upstream is never dialled
// by the Admin API paths these tests exercise.
func createMCPRegistry(t *testing.T, gatewayID string) string {
	t.Helper()
	return CreateRegistry(t, gatewayID, mcpRegistryPayload(uniqueName("pol-mcp-reg"), "http://127.0.0.1:1/mcp"))
}

func TestCreatePolicy_WithMCPScope_EchoesStoredScope(t *testing.T) {
	defer Track(t, "CreatePolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("pol-gw-scope")})
	byRegistry := createMCPRegistry(t, gwID)
	byTool := createMCPRegistry(t, gwID)

	url := fmt.Sprintf("%s/v1/gateways/%s/policies", AdminURL, gwID)
	status, body := sendRequest(t, http.MethodPost, url, nil, scopedPolicyPayload(uniqueName("pol-scope"), map[string]any{
		"registry_ids":  []string{byRegistry},
		"tools":         []map[string]any{{"registry_id": byTool, "tool": "run_query"}},
		"groups":        []string{"Finanzas"},
		"except_groups": []string{"Contractors"},
	}))
	require.Equal(t, http.StatusCreated, status, "body=%v", body)
	// There is still nothing to overlap, but the write now says what the scope
	// and the missing consumers cost: the destination dimension keeps the
	// policy on MCP traffic, and a policy nothing routes to runs nowhere.
	assert.ElementsMatch(t, []any{
		"policy scope names a registry or a tool: it runs on MCP traffic only, never on the LLM or A2A plane",
		"policy has no consumers and is not global: it runs nowhere",
	}, body["warnings"], "body=%v", body)

	scope, ok := body["mcp_scope"].(map[string]any)
	require.True(t, ok, "mcp_scope missing: %v", body)
	assert.Equal(t, []any{byRegistry}, scope["registry_ids"])
	assert.Equal(t, []any{map[string]any{"registry_id": byTool, "tool": "run_query"}}, scope["tools"])
	assert.Equal(t, []any{"Finanzas"}, scope["groups"])
	assert.Equal(t, []any{"Contractors"}, scope["except_groups"])

	id, _ := body["id"].(string)
	got := getPolicy(t, gwID, id)
	assert.Equal(t, scope, got["mcp_scope"], "GET echoes the scope as stored")
}

func TestCreatePolicy_WithoutMCPScope_OmitsField(t *testing.T) {
	defer Track(t, "CreatePolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("pol-gw-noscope")})

	url := fmt.Sprintf("%s/v1/gateways/%s/policies", AdminURL, gwID)
	status, body := sendRequest(t, http.MethodPost, url, nil, validPolicyPayload(uniqueName("pol-noscope")))
	require.Equal(t, http.StatusCreated, status, "body=%v", body)
	_, present := body["mcp_scope"]
	assert.False(t, present, "nil scope must not be serialised")
}

func TestCreatePolicy_MCPScopeRejections(t *testing.T) {
	defer Track(t, "CreatePolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("pol-gw-scope-bad")})
	otherGW := CreateGateway(t, map[string]any{"slug": uniqueName("pol-gw-scope-other")})
	ownMCP := createMCPRegistry(t, gwID)
	foreignMCP := createMCPRegistry(t, otherGW)
	ownLLM := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("pol-llm-reg")))

	tests := []struct {
		name  string
		scope map[string]any
	}{
		{name: "empty scope", scope: map[string]any{}},
		{name: "registry of another gateway", scope: map[string]any{"registry_ids": []string{foreignMCP}}},
		{name: "llm registry", scope: map[string]any{"registry_ids": []string{ownLLM}}},
		{name: "unknown registry", scope: map[string]any{"registry_ids": []string{uuid.NewString()}}},
		{name: "registry id is not a uuid", scope: map[string]any{"registry_ids": []string{"not-a-uuid"}}},
		{name: "registry in both lists", scope: map[string]any{
			"registry_ids": []string{ownMCP},
			"tools":        []map[string]any{{"registry_id": ownMCP, "tool": "run_query"}},
		}},
		{name: "tool without name", scope: map[string]any{"tools": []map[string]any{{"registry_id": ownMCP, "tool": ""}}}},
		{name: "duplicate group", scope: map[string]any{"groups": []string{"Finanzas", "Finanzas"}}},
		{name: "empty group", scope: map[string]any{"groups": []string{""}}},
		{name: "retired users dimension", scope: map[string]any{"users": []string{"ana@acme.com"}}},
		{name: "retired except_users dimension", scope: map[string]any{
			"groups":       []string{"Finanzas"},
			"except_users": []string{"ana@acme.com"},
		}},
	}
	url := fmt.Sprintf("%s/v1/gateways/%s/policies", AdminURL, gwID)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, body := sendRequest(t, http.MethodPost, url, nil, scopedPolicyPayload(uniqueName("pol-scope-bad"), tt.scope))
			require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
			assert.Equal(t, "validation_failed", body["error"])
		})
	}
}

func TestCreatePolicy_MCPScopeNotAnObjectRejected(t *testing.T) {
	defer Track(t, "CreatePolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("pol-gw-scope-type")})

	payload := validPolicyPayload(uniqueName("pol-scope-type"))
	payload["mcp_scope"] = "everything"
	url := fmt.Sprintf("%s/v1/gateways/%s/policies", AdminURL, gwID)
	status, body := sendRequest(t, http.MethodPost, url, nil, payload)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

// A global trustguard with scope is additive to a consumer's unscoped
// trustguard, so both run there; the API accepts it and says so.
func TestPolicyGlobalWithMCPScope_WarnsAboutUnscopedTrustGuard(t *testing.T) {
	defer Track(t, "CreatePolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("pol-gw-scope-warn")})
	registryID := createMCPRegistry(t, gwID)
	withUnscoped, _ := createMCPConsumer(t, gwID, []string{registryID}, nil, "")
	clean, _ := createMCPConsumer(t, gwID, []string{registryID}, nil, "")
	attachTrustGuardMCPPolicyWithSettings(t, gwID, withUnscoped, map[string]any{"direction": "request_response"})

	url := fmt.Sprintf("%s/v1/gateways/%s/policies", AdminURL, gwID)
	status, body := sendRequest(t, http.MethodPost, url, nil, map[string]any{
		"name":      uniqueName("pol-scope-warn"),
		"slug":      "trustguard",
		"enabled":   true,
		"settings":  map[string]any{"collector_id": trustGuardFunctionalCollectorID, "direction": "request_response"},
		"mcp_scope": map[string]any{"registry_ids": []string{registryID}},
	})
	require.Equal(t, http.StatusCreated, status, "body=%v", body)
	// Nothing is attached yet, so the create warns about the policy itself,
	// never about a consumer.
	assert.ElementsMatch(t, []any{
		"policy scope names a registry or a tool: it runs on MCP traffic only, never on the LLM or A2A plane",
		"policy has no consumers and is not global: it runs nowhere",
	}, body["warnings"], "body=%v", body)
	scopedID, _ := body["id"].(string)

	status, body = sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/policies/%s/global", AdminURL, gwID, scopedID), nil, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, true, body["global"])
	// The promotion is what makes the policy run, so the "runs nowhere"
	// warning is gone and the overlap one appears. The scope-bound warning
	// stays: promoting is not what lets a destination scope leave MCP.
	warnings, _ := body["warnings"].([]any)
	require.Len(t, warnings, 2, "body=%v", body)
	assert.NotContains(t, warnings, "policy has no consumers and is not global: it runs nowhere")
	overlap := warningNaming(t, warnings, withUnscoped)
	assert.Contains(t, overlap, "trustguard")
	assert.NotContains(t, overlap, clean)

	status, body = sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/policies?registry_id=%s", AdminURL, gwID, registryID), nil, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	items, _ := body["items"].([]any)
	require.Len(t, items, 1)
	item, _ := items[0].(map[string]any)
	assert.Equal(t, scopedID, item["id"])
}

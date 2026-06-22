//go:build functional

package functional_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func toolTransformChatRequest(toolName string) map[string]any {
	return map[string]any{
		"model":    "gpt-4o-mini",
		"messages": []map[string]string{{"role": "user", "content": "Hello"}},
		"tools": []map[string]any{
			{
				"type": "function",
				"function": map[string]any{
					"name":        toolName,
					"description": "original description",
					"parameters": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"query":         map[string]any{"type": "string"},
							"internal_only": map[string]any{"type": "boolean"},
						},
					},
				},
			},
		},
	}
}

type forwardedTool struct {
	Function struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Parameters  map[string]any `json:"parameters"`
	} `json:"function"`
}

func forwardedTools(t *testing.T, raw []byte) []forwardedTool {
	t.Helper()
	var parsed struct {
		Tools []forwardedTool `json:"tools"`
	}
	require.NoError(t, json.Unmarshal(raw, &parsed), "upstream body: %s", raw)
	return parsed.Tools
}

func findForwardedTool(tools []forwardedTool, name string) (forwardedTool, bool) {
	for _, tl := range tools {
		if tl.Function.Name == name {
			return tl, true
		}
	}
	return forwardedTool{}, false
}

func TestPluginE2E_ToolDefinitionTransformation_PatchAndInject(t *testing.T) {
	defer Track(t, "PluginToolDefinitionTransformation")()

	up := newJSONUpstream(t, "ok")
	settings := map[string]any{
		"transform_tools": []any{
			map[string]any{
				"tool": "search_*",
				"schema_patch": map[string]any{
					"properties": map[string]any{"internal_only": nil},
					"required":   []any{"query"},
				},
				"description_override": "patched description",
			},
		},
		"inject_tools": []any{
			map[string]any{
				"type": "function",
				"function": map[string]any{
					"name":        "safety_check",
					"description": "injected by gateway",
					"parameters":  map[string]any{"type": "object"},
				},
			},
		},
	}
	apiKey, path := setupPolicyRoute(t, up, policyPlugin("tool_definition_transformation", settings))

	status, _, raw := proxyPost(t, apiKey, path, toolTransformChatRequest("search_docs"))
	require.Equal(t, http.StatusOK, status, "body: %s", raw)

	tools := forwardedTools(t, up.LastBody())

	transformed, ok := findForwardedTool(tools, "search_docs")
	require.Truef(t, ok, "transformed tool missing from forwarded body: %s", up.LastBody())
	assert.Equal(t, "patched description", transformed.Function.Description)

	properties, ok := transformed.Function.Parameters["properties"].(map[string]any)
	require.Truef(t, ok, "transformed parameters missing properties: %#v", transformed.Function.Parameters)
	_, hasInternalOnly := properties["internal_only"]
	assert.False(t, hasInternalOnly, "schema_patch null must delete internal_only")
	_, hasQuery := properties["query"]
	assert.True(t, hasQuery, "schema_patch must preserve sibling query property")
	assert.Equal(t, []any{"query"}, transformed.Function.Parameters["required"])

	_, injected := findForwardedTool(tools, "safety_check")
	assert.Truef(t, injected, "injected tool missing from forwarded body: %s", up.LastBody())
}

func TestPluginE2E_ToolDefinitionTransformation_RejectCollision(t *testing.T) {
	defer Track(t, "PluginToolDefinitionTransformation")()

	up := newJSONUpstream(t, "ok")
	settings := map[string]any{
		"on_conflict": "reject",
		"inject_tools": []any{
			map[string]any{
				"type": "function",
				"function": map[string]any{
					"name":       "search_docs",
					"parameters": map[string]any{"type": "object"},
				},
			},
		},
	}
	apiKey, path := setupPolicyRoute(t, up, policyPlugin("tool_definition_transformation", settings))

	status, _, raw := proxyPost(t, apiKey, path, toolTransformChatRequest("search_docs"))
	require.Equal(t, http.StatusBadRequest, status, "body: %s", raw)

	var decoded struct {
		Error struct {
			Type string `json:"type"`
			Name string `json:"name"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(raw, &decoded), "reject body: %s", raw)
	assert.Equal(t, "tool_name_reserved", decoded.Error.Type)
	assert.Equal(t, "search_docs", decoded.Error.Name)
	assert.Equal(t, 0, up.Hits(), "rejected request must not reach the upstream")
}

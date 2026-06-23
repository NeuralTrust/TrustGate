//go:build functional

package functional_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func anthropicChatRequestWithTools(model string, tools ...string) map[string]any {
	specs := make([]map[string]any, 0, len(tools))
	for _, name := range tools {
		specs = append(specs, map[string]any{
			"name":         name,
			"description":  name,
			"input_schema": map[string]any{"type": "object", "properties": map[string]any{}},
		})
	}
	return map[string]any{
		"model":      model,
		"max_tokens": 128,
		"messages":   []map[string]string{{"role": "user", "content": "Hello"}},
		"tools":      specs,
	}
}

func chatRequestWithToolsAndChoice(tools ...string) map[string]any {
	body := chatRequestWithTools(tools...)
	body["tool_choice"] = "auto"
	body["parallel_tool_calls"] = true
	return body
}

func anthropicMessagesPath(chatPath string) string {
	return strings.TrimSuffix(chatPath, "/v1/chat/completions") + "/v1/messages"
}

func TestPluginE2E_ToolAllowlist_AllowFiltersForwardedTools(t *testing.T) {
	defer Track(t, "PluginToolAllowlist")()

	up := newJSONUpstream(t, "allow-upstream")
	apiKey, path := setupPolicyRoute(t, up,
		policyPlugin("tool_allowlist", map[string]any{
			"allow_tools": []string{"search_*", "calculate"},
		}),
	)

	body := mustJSON(t, chatRequestWithTools("search_web", "calculate", "delete_db"))

	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	require.Equal(t, http.StatusOK, status, "body: %s", raw)
	assert.ElementsMatch(t, []string{"search_web", "calculate"}, forwardedToolNames(t, up.LastBody()),
		"only the allow-listed tools must reach the upstream")
}

func TestPluginE2E_ToolAllowlist_DenyRemovesForwardedTools(t *testing.T) {
	defer Track(t, "PluginToolAllowlist")()

	up := newJSONUpstream(t, "deny-upstream")
	apiKey, path := setupPolicyRoute(t, up,
		policyPlugin("tool_allowlist", map[string]any{
			"deny_tools": []string{"delete_*"},
		}),
	)

	body := mustJSON(t, chatRequestWithTools("search_web", "delete_db", "delete_file"))

	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	require.Equal(t, http.StatusOK, status, "body: %s", raw)
	assert.Equal(t, []string{"search_web"}, forwardedToolNames(t, up.LastBody()),
		"denied tools must be stripped before reaching the upstream")
}

func TestPluginE2E_ToolAllowlist_RejectOnEmptyAfterFilter(t *testing.T) {
	defer Track(t, "PluginToolAllowlist")()

	up := newJSONUpstream(t, "reject-upstream")
	apiKey, path := setupPolicyRoute(t, up,
		policyPlugin("tool_allowlist", map[string]any{
			"allow_tools":           []string{"search_*"},
			"on_empty_after_filter": "reject",
		}),
	)

	body := mustJSON(t, chatRequestWithTools("delete_db", "calculate"))

	hitsBefore := up.Hits()
	status, header, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, "application/json", header.Get("Content-Type"))
	assert.JSONEq(t,
		`{"error":{"type":"no_tools_allowed","requested":["delete_db","calculate"],"allowed_after_filter":[]}}`,
		string(raw),
	)
	assert.Equal(t, hitsBefore, up.Hits(), "a rejected request must not reach the upstream")
}

func TestPluginE2E_ToolAllowlist_StripFieldOnEmptyAfterFilter(t *testing.T) {
	defer Track(t, "PluginToolAllowlist")()

	up := newJSONUpstream(t, "strip-upstream")
	apiKey, path := setupPolicyRoute(t, up,
		policyPlugin("tool_allowlist", map[string]any{
			"allow_tools":           []string{"calculate"},
			"on_empty_after_filter": "strip_tools_field",
		}),
	)

	body := mustJSON(t, chatRequestWithToolsAndChoice("search_web"))

	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	require.Equal(t, http.StatusOK, status, "body: %s", raw)
	assert.Equal(t, 1, up.Hits(), "strip_tools_field must still forward the request upstream")
	assert.Empty(t, forwardedToolNames(t, up.LastBody()), "no tools must survive the filter")
	forwarded := string(up.LastBody())
	assert.NotContains(t, forwarded, `"tools"`, "the tools field must be removed entirely")
	assert.NotContains(t, forwarded, `"tool_choice"`, "the dangling tool_choice must be removed")
	assert.NotContains(t, forwarded, `"parallel_tool_calls"`, "the dangling parallel_tool_calls must be removed")
}

func TestPluginE2E_ToolAllowlist_PassThroughEmptyAfterFilter(t *testing.T) {
	defer Track(t, "PluginToolAllowlist")()

	up := newJSONUpstream(t, "passthrough-upstream")
	apiKey, path := setupPolicyRoute(t, up,
		policyPlugin("tool_allowlist", map[string]any{
			"allow_tools":           []string{"calculate"},
			"on_empty_after_filter": "pass_through_empty",
		}),
	)

	body := mustJSON(t, chatRequestWithToolsAndChoice("search_web"))

	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	require.Equal(t, http.StatusOK, status, "body: %s", raw)
	assert.Equal(t, 1, up.Hits(), "pass_through_empty must still forward the request upstream")
	assert.Empty(t, forwardedToolNames(t, up.LastBody()), "no tools must survive the filter")
	forwarded := string(up.LastBody())
	assert.Contains(t, forwarded, `"tools":[]`, "pass_through_empty must forward an empty tools array")
	assert.NotContains(t, forwarded, `"tool_choice"`, "the dangling tool_choice must be removed")
	assert.NotContains(t, forwarded, `"parallel_tool_calls"`, "the dangling parallel_tool_calls must be removed")
}

func TestPluginE2E_ToolAllowlist_AnthropicAllowFilters(t *testing.T) {
	defer Track(t, "PluginToolAllowlist")()

	up := newJSONUpstream(t, "anthropic-upstream")
	apiKey, chatPath := setupPolicyRoute(t, up,
		policyPlugin("tool_allowlist", map[string]any{
			"allow_tools": []string{"get_weather"},
		}),
	)

	body := mustJSON(t, anthropicChatRequestWithTools("@openai/gpt-4o-mini", "get_weather", "delete_db"))

	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, anthropicMessagesPath(chatPath), nil, body)
	require.Equal(t, http.StatusOK, status, "body: %s", raw)
	assert.Equal(t, []string{"get_weather"}, forwardedToolNames(t, up.LastBody()),
		"the allow-list must apply to the canonical name across the anthropic source format")
}

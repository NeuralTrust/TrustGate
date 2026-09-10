//go:build functional

package functional_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIngressErrorShape_AnthropicFromOpenAIUpstream(t *testing.T) {
	defer Track(t, "IngressErrorShape")()

	up := newFailingUpstream(t, http.StatusBadRequest)
	apiKey, slug := setupSlugRoute(t, up, []string{"gpt-4o-mini"}, "")

	status, _, body := proxyPost(t, apiKey, "/"+slug+"/v1/messages",
		anthropicChatRequest("gpt-4o-mini"))

	assert.Equal(t, http.StatusBadRequest, status, "body: %s", body)
	assert.Contains(t, string(body), `"type":"error"`)
	assert.Contains(t, string(body), `"invalid_request_error"`)
	assert.Equal(t, 1, up.Hits())
}

func TestContextWindowPreflight_RefusesOversizedToolset(t *testing.T) {
	defer Track(t, "ContextWindowPreflight")()
	if !openaiCatalogListsModel(t, "gpt-4") {
		t.Skip("openai catalog does not list gpt-4")
	}

	up := newJSONUpstream(t, "must-not-serve")
	apiKey, slug := setupSlugRoute(t, up, []string{"gpt-4"}, "")

	tools := make([]map[string]any, 0, 40)
	desc := strings.Repeat("tool schema filler ", 120)
	for i := 0; i < 40; i++ {
		tools = append(tools, map[string]any{
			"name":        "tool_" + strings.Repeat("x", 8),
			"description": desc,
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"q": map[string]any{"type": "string", "description": desc},
				},
			},
		})
	}
	payload := anthropicChatRequest("gpt-4")
	payload["tools"] = tools

	status, _, body := proxyPost(t, apiKey, "/"+slug+"/v1/messages", payload)
	assert.Equal(t, http.StatusBadRequest, status, "body: %s", body)
	assert.Contains(t, string(body), `"type":"error"`)
	assert.Contains(t, string(body), `"invalid_request_error"`)
	assert.Contains(t, string(body), "8192")
	assert.Equal(t, 0, up.Hits())
	assert.Empty(t, up.LastBody())

	small := anthropicChatRequest("gpt-4")
	small["tools"] = []map[string]any{{
		"name":         "lookup",
		"description":  "one tool",
		"input_schema": map[string]any{"type": "object", "properties": map[string]any{}},
	}}
	status, _, body = proxyPost(t, apiKey, "/"+slug+"/v1/messages", small)
	require.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, 1, up.Hits())
}

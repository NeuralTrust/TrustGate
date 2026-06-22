//go:build functional

package functional_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPluginE2E_ModelAllowlist_Reject(t *testing.T) {
	defer Track(t, "PluginModelAllowlist")()

	up := newJSONUpstream(t, "allowlist-upstream")
	apiKey, path := setupPolicyRoute(t, up,
		policyPlugin("model_allowlist", map[string]any{
			"allowed_models":         []string{"gpt-5*"},
			"behavior_on_disallowed": "reject",
		}),
	)

	t.Run("allowed model passes through", func(t *testing.T) {
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil,
			mustJSON(t, chatRequestModel("gpt-5-turbo")),
		)
		assert.Equal(t, http.StatusOK, status, "body: %s", raw)
		assert.Contains(t, string(raw), "allowlist-upstream")
	})

	t.Run("disallowed model returns exact 403 body", func(t *testing.T) {
		hitsBefore := up.Hits()
		status, header, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil,
			mustJSON(t, chatRequestModel("claude-opus-4-5")),
		)
		assert.Equal(t, http.StatusForbidden, status)
		assert.Equal(t, "application/json", header.Get("Content-Type"))
		assert.JSONEq(t,
			`{"error":{"type":"model_not_allowed","model":"claude-opus-4-5","allowed":["gpt-5*"]}}`,
			string(raw),
		)
		assert.Equal(t, hitsBefore, up.Hits(), "a rejected request must not reach the upstream")
	})
}

func TestPluginE2E_ModelAllowlist_Substitute(t *testing.T) {
	defer Track(t, "PluginModelAllowlist")()

	up := newJSONUpstream(t, "substitute-upstream")
	apiKey, path := setupPolicyRoute(t, up,
		policyPlugin("model_allowlist", map[string]any{
			"allowed_models":         []string{"gpt-5*"},
			"behavior_on_disallowed": "substitute",
			"substitute_with":        "gpt-5",
		}),
	)

	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil,
		mustJSON(t, chatRequestModel("claude-opus-4-5")),
	)
	assert.Equal(t, http.StatusOK, status, "body: %s", raw)
	assert.Equal(t, 1, up.Hits(), "a substituted request must still reach the upstream")
	assert.Contains(t, string(up.LastBody()), `"model":"gpt-5"`,
		"the disallowed model must be rewritten to substitute_with before reaching the upstream")
	assert.NotContains(t, string(up.LastBody()), "claude-opus-4-5",
		"the original disallowed model must not reach the upstream")
}

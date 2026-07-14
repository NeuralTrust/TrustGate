//go:build functional

package functional_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func regexReplaceSettings(target string, rules []map[string]any) map[string]any {
	return map[string]any{
		"target": target,
		"rules":  rules,
	}
}

func regexReplacePolicy(settings map[string]any, stages ...string) map[string]any {
	entry := policyPlugin("regex_replace", settings)
	entry["stages"] = stages
	return entry
}

func regexReplaceChatRequest(content string) map[string]any {
	return map[string]any{
		"model":    "gpt-4o-mini",
		"messages": []map[string]string{{"role": "user", "content": content}},
	}
}

func TestPluginE2E_RegexReplace_RequestLeg(t *testing.T) {
	defer Track(t, "PluginRegexReplace")()

	up := newJSONUpstream(t, "regex-request-served")
	settings := regexReplaceSettings("request", []map[string]any{
		{"pattern": "secret", "replacement": "[REDACTED]"},
	})
	apiKey, path := setupPolicyRoute(t, up, regexReplacePolicy(settings, "pre_request"))

	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil,
		mustJSON(t, regexReplaceChatRequest("my secret token is 12345")),
	)

	assert.Equal(t, http.StatusOK, status, "body: %s", raw)
	assert.GreaterOrEqual(t, up.Hits(), 1, "a rewritten request is still forwarded")
	assert.Contains(t, string(up.LastBody()), "[REDACTED]", "the masked text must reach the upstream")
	assert.NotContains(t, string(up.LastBody()), "secret", "the raw text must not reach the upstream")
}

func TestPluginE2E_RegexReplace_ResponseLeg(t *testing.T) {
	defer Track(t, "PluginRegexReplace")()

	up := newJSONUpstream(t, "the answer is 42")
	settings := regexReplaceSettings("response", []map[string]any{
		{"pattern": "answer", "replacement": "solution"},
	})
	apiKey, path := setupPolicyRoute(t, up, regexReplacePolicy(settings, "pre_response"))

	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil,
		mustJSON(t, regexReplaceChatRequest("what is the answer?")),
	)

	assert.Equal(t, http.StatusOK, status, "body: %s", raw)
	assert.Equal(t, 1, up.Hits(), "the response rewrite must not trigger a second upstream call")
	assert.Contains(t, string(raw), "solution", "the client must see the rewritten response text")
	assert.NotContains(t, string(raw), "answer", "the original response text must not reach the client")
}

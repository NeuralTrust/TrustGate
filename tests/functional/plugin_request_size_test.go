//go:build functional

package functional_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPluginE2E_RequestSizeLimiter_ByteLimit(t *testing.T) {
	defer Track(t, "PluginRequestSize")()

	up := newJSONUpstream(t, "size-upstream")
	apiKey, path := setupPolicyRoute(t, up,
		policyPlugin("request_size_limiter", map[string]any{
			"allowed_payload_size": 1000,
			"size_unit":            "bytes",
		}),
	)

	t.Run("payload within the limit passes through", func(t *testing.T) {
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil,
			mustJSON(t, chatRequest(false)),
		)
		assert.Equal(t, http.StatusOK, status, "body: %s", raw)
		assert.Contains(t, string(raw), "size-upstream")
	})

	t.Run("payload over the byte limit is rejected", func(t *testing.T) {
		oversized := map[string]any{
			"model":    "gpt-4o-mini",
			"messages": []map[string]string{{"role": "user", "content": strings.Repeat("a", 4000)}},
		}
		hitsBefore := up.Hits()
		status, _, _ := proxyRequest(t, http.MethodPost, apiKey, path, nil, mustJSON(t, oversized))
		assert.Equal(t, http.StatusRequestEntityTooLarge, status)
		assert.Equal(t, hitsBefore, up.Hits(), "an oversized request must not reach the upstream")
	})
}

func TestPluginE2E_RequestSizeLimiter_CharLimit(t *testing.T) {
	defer Track(t, "PluginRequestSize")()

	up := newJSONUpstream(t, "char-upstream")
	apiKey, path := setupPolicyRoute(t, up,
		policyPlugin("request_size_limiter", map[string]any{
			"allowed_payload_size":  10,
			"size_unit":             "megabytes",
			"max_chars_per_request": 10,
		}),
	)

	status, _, _ := proxyRequest(t, http.MethodPost, apiKey, path, nil,
		mustJSON(t, chatRequest(false)),
	)
	assert.Equal(t, http.StatusRequestEntityTooLarge, status,
		"a body with more characters than the limit must be rejected")
}

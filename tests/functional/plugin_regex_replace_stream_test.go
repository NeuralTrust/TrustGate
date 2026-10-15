//go:build functional

package functional_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	regexStreamCardPattern = `\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b`
	regexStreamCardNumber  = "4242424242424242"
)

// regexStreamEvents serves a short answer whose card number is split across two
// deltas, so no single chunk carries it whole.
func regexStreamEvents() []string {
	delta := func(text string) string {
		return trustGuardStreamChunk(fmt.Sprintf(`{"content":%q}`, text))
	}
	return []string{
		trustGuardStreamChunk(`{"role":"assistant"}`),
		delta("Your test card is 42424242"),
		delta("42424242 and that is all."),
		trustGuardStreamChunk(`{}`, `"finish_reason":"stop"`),
		"data: [DONE]\n\n",
	}
}

func regexStreamRequest(stream bool) map[string]any {
	req := regexReplaceChatRequest("give me a test card number")
	if stream {
		req["stream"] = true
	}
	return req
}

// ENG-1735: the policy is what the console saves, a target and rules with no
// streaming block. It must mask a streamed response as it masks a buffered one.
func TestPluginE2E_RegexReplace_StreamedResponseIsMaskedByDefault(t *testing.T) {
	defer Track(t, "PluginRegexReplace")()

	settings := regexReplaceSettings("response", []map[string]any{
		{"pattern": regexStreamCardPattern, "replacement": "[CARD]"},
	})
	require.NotContains(t, settings, "streaming", "the point of this case is a policy with no streaming key")

	t.Run("a streamed response is masked", func(t *testing.T) {
		up := newPacedStreamUpstream(t, regexStreamEvents(), 5*time.Millisecond)
		apiKey, path := setupPolicyRoute(t, up, regexReplacePolicy(settings, "pre_response"))

		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, mustJSON(t, regexStreamRequest(true)))

		require.Equal(t, http.StatusOK, status, "body: %s", raw)
		body := string(raw)
		assert.Contains(t, body, "[CARD]", "the card must be masked in the stream")
		assert.NotContains(t, body, regexStreamCardNumber)
		assert.NotContains(t, strings.ReplaceAll(body, "\"", ""), "42424242", "no half of the number may reach the client")
		assert.Contains(t, body, "[DONE]")
	})

	// streaming.enabled cannot turn per-block rewriting off, so a write that
	// sets it to false is refused rather than stored and ignored (RUN-1661).
	t.Run("a new streaming.enabled false is refused", func(t *testing.T) {
		off := regexReplaceSettings("response", []map[string]any{
			{"pattern": regexStreamCardPattern, "replacement": "[CARD]"},
		})
		off["streaming"] = map[string]any{"enabled": false}
		payload := regexReplacePolicy(off, "pre_response")
		payload["name"] = uniqueName("pol")
		gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("plugin-gw")})

		status, body := sendRequest(t, http.MethodPost,
			fmt.Sprintf("%s/v1/gateways/%s/policies", AdminURL, gatewayID), nil, payload)

		require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
		assert.Equal(t, "validation_failed", body["error"])
		assert.Contains(t, body["message"], "streaming.enabled cannot turn it off")
	})

	t.Run("a buffered response is masked as before", func(t *testing.T) {
		up := newJSONUpstream(t, "your card is "+regexStreamCardNumber+" ok")
		apiKey, path := setupPolicyRoute(t, up, regexReplacePolicy(settings, "pre_response"))

		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, mustJSON(t, regexStreamRequest(false)))

		require.Equal(t, http.StatusOK, status, "body: %s", raw)
		assert.Contains(t, string(raw), "[CARD]")
		assert.NotContains(t, string(raw), regexStreamCardNumber)
	})
}

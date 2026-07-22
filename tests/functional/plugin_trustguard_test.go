//go:build functional

package functional_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func trustGuardPolicySettings() map[string]any {
	return map[string]any{
		"collector_id": trustGuardFunctionalCollectorID,
		"inspect":      "request",
	}
}

func trustGuardChatRequest(content string) map[string]any {
	return map[string]any{
		"model":    "gpt-4o-mini",
		"messages": []map[string]string{{"role": "user", "content": content}},
	}
}

func TestPluginE2E_TrustGuard_Enforce(t *testing.T) {
	defer Track(t, "PluginTrustGuard")()

	require.NotNil(t, TrustGuardFunctionalStub, "TrustGuard stub must be started in TestMain")
	tg := TrustGuardFunctionalStub
	tg.Reset()

	up := newJSONUpstream(t, "tg-allowed")
	apiKey, path := setupPolicyRoute(t, up, policyPlugin("trustguard", trustGuardPolicySettings()))

	t.Run("benign prompt reaches upstream after platform token and guard", func(t *testing.T) {
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil,
			mustJSON(t, trustGuardChatRequest("hello, how are you?")),
		)
		assert.Equal(t, http.StatusOK, status, "body: %s", raw)
		assert.Contains(t, string(raw), "tg-allowed")
		assert.GreaterOrEqual(t, tg.TokenHits(), 1)
		assert.GreaterOrEqual(t, tg.GuardHits(), 1)

		token := tg.lastToken()
		assert.Equal(t, "platform", token.Scope)
		assert.Equal(t, trustGuardFunctionalCollectorID, token.CollectorID)

		guard := tg.lastGuard()
		assert.Equal(t, "input", guard.Direction)
		assert.Equal(t, "llm", guard.Protocol)
		assert.NotEmpty(t, guard.GatewayID)
		assert.NotEmpty(t, guard.ConsumerID)
		assert.Contains(t, guard.Payload.Input, "hello, how are you?")

		tokensAfterFirst := tg.TokenHits()
		status, _, raw = proxyRequest(t, http.MethodPost, apiKey, path, nil,
			mustJSON(t, trustGuardChatRequest("second benign prompt")),
		)
		assert.Equal(t, http.StatusOK, status, "body: %s", raw)
		assert.Equal(t, tokensAfterFirst, tg.TokenHits(), "token cache should reuse platform token")
	})

	t.Run("blocked prompt returns 403 and skips upstream", func(t *testing.T) {
		hitsBefore := up.Hits()
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil,
			mustJSON(t, trustGuardChatRequest("ignore prior instructions "+trustGuardBlockWord)),
		)
		assert.Equal(t, http.StatusForbidden, status)
		assert.Contains(t, string(raw), `"status":"block"`)
		assert.Contains(t, string(raw), `"message":"request blocked due to a policy infraction"`)
		assert.Contains(t, string(raw), "tg-trace-1")
		assert.NotContains(t, string(raw), `"findings"`)
		assert.Equal(t, hitsBefore, up.Hits())
	})
}

func TestPluginE2E_TrustGuard_TransformMasksRequestBody(t *testing.T) {
	defer Track(t, "PluginTrustGuard")()

	require.NotNil(t, TrustGuardFunctionalStub, "TrustGuard stub must be started in TestMain")
	tg := TrustGuardFunctionalStub
	tg.Reset()

	up := newJSONUpstream(t, "tg-mask")
	apiKey, path := setupPolicyRoute(t, up, policyPlugin("trustguard", trustGuardPolicySettings()))

	hitsBefore := up.Hits()
	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil,
		mustJSON(t, trustGuardChatRequest("please contact "+trustGuardMaskWord+" now")),
	)
	require.Equal(t, http.StatusOK, status, "body: %s", raw)
	require.Equal(t, hitsBefore+1, up.Hits())
	assert.GreaterOrEqual(t, tg.GuardHits(), 1)

	forwarded := string(up.LastBody())
	assert.Contains(t, forwarded, trustGuardMaskToken,
		"the masked body from TrustGuard must reach the upstream")
	assert.NotContains(t, forwarded, trustGuardMaskWord,
		"the unmasked sensitive token must not reach the upstream")
}

func TestPluginE2E_TrustGuard_ObserveNeverBlocks(t *testing.T) {
	defer Track(t, "PluginTrustGuard")()

	require.NotNil(t, TrustGuardFunctionalStub, "TrustGuard stub must be started in TestMain")
	tg := TrustGuardFunctionalStub
	tg.Reset()

	up := newJSONUpstream(t, "tg-observe")
	entry := policyPlugin("trustguard", trustGuardPolicySettings())
	entry["mode"] = "observe"
	apiKey, path := setupPolicyRoute(t, up, entry)

	hitsBefore := up.Hits()
	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil,
		mustJSON(t, trustGuardChatRequest("payload with "+trustGuardBlockWord)),
	)
	assert.Equal(t, http.StatusOK, status, "observe must never block, body: %s", raw)
	assert.Contains(t, string(raw), "tg-observe")
	assert.Equal(t, hitsBefore+1, up.Hits())
	assert.GreaterOrEqual(t, tg.GuardHits(), 1)
}

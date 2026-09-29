//go:build functional

package functional_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func trustGuardPolicySettings() map[string]any {
	return map[string]any{
		"collector_id": trustGuardFunctionalCollectorID,
		"direction":    "request",
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
		assert.Contains(t, trustGuardInspectText(guard.Payload), "hello, how are you?")

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
		assert.Contains(t, string(raw), `"message":"Request blocked by security policy: prompt_injection."`)
		assert.Contains(t, string(raw), `"reason":"prompt_injection"`)
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

// newTrustGuardRichStreamUpstream emits an OpenAI SSE body with reasoning_content,
// assistant content, and a tool_call so post_response TrustGuard inspect can prove
// the gateway reassembles all three into the evaluate payload.
func newTrustGuardRichStreamUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.record(r)
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		write := func(s string) {
			_, _ = io.WriteString(w, s)
			if flusher != nil {
				flusher.Flush()
			}
		}
		write(": keepalive\n\n")
		write(`data: {"id":"chatcmpl-tg","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","reasoning_content":"plan "}}]}` + "\n\n")
		write(`data: {"id":"chatcmpl-tg","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"reasoning_content":"first"}}]}` + "\n\n")
		write(`data: {"id":"chatcmpl-tg","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"hello "}}]}` + "\n\n")
		write(`data: {"id":"chatcmpl-tg","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"world"}}]}` + "\n\n")
		write(`data: {"id":"chatcmpl-tg","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_tg_1","type":"function","function":{"name":"lookup","arguments":"{\"q\":"}}]}}]}` + "\n\n")
		write(`data: {"id":"chatcmpl-tg","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"x\"}"}}]}}]}` + "\n\n")
		write(`data: {"id":"chatcmpl-tg","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n")
		write("data: [DONE]\n\n")
	}))
	t.Cleanup(u.server.Close)
	return u
}

func TestPluginE2E_TrustGuard_StreamingResponseSendsReasoningAndToolCalls(t *testing.T) {
	defer Track(t, "PluginTrustGuard")()

	require.NotNil(t, TrustGuardFunctionalStub, "TrustGuard stub must be started in TestMain")
	tg := TrustGuardFunctionalStub
	tg.Reset()

	up := newTrustGuardRichStreamUpstream(t)
	// This pins the post-drain pass, which a streamed response only takes when
	// the policy opts out of per-block inspection: since RUN-1712 that is on by
	// default for any policy whose direction includes the response.
	apiKey, path := setupPolicyRoute(t, up, policyPlugin("trustguard", map[string]any{
		"collector_id": trustGuardFunctionalCollectorID,
		"direction":    "response",
		"streaming":    map[string]any{"enabled": false},
	}))

	req := trustGuardChatRequest("stream please")
	req["stream"] = true
	status, headers, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, mustJSON(t, req))
	require.Equal(t, http.StatusOK, status, "body: %s", raw)
	assert.Contains(t, string(raw), "hello ")
	assert.Contains(t, string(raw), "world")
	assert.Contains(t, string(raw), "[DONE]")
	assert.Equal(t, 1, up.Hits())

	// post_response runs asynchronously and carries no stream envelope, so it
	// is correlated by trace id rather than by a stub-wide GuardHits count.
	traceID := headers.Get(traceIDHeader)
	require.NotEmpty(t, traceID, "the proxy must echo the trace id the guard was called with")
	require.Eventually(t, func() bool {
		return tg.BufferedHitsForTrace(traceID) >= 1
	}, 5*time.Second, 50*time.Millisecond, "expected TrustGuard evaluate for streamed output")

	guard, ok := tg.GuardForTrace(traceID)
	require.True(t, ok, "expected a buffered call captured for this request's trace id")
	assert.Equal(t, "output", guard.Direction)
	assert.Equal(t, "llm", guard.Protocol)

	var payload struct {
		Messages []map[string]any `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(guard.Payload, &payload))
	require.Len(t, payload.Messages, 1)
	msg := payload.Messages[0]
	assert.Equal(t, "assistant", msg["role"])
	assert.Equal(t, "hello world", msg["content"])
	assert.Equal(t, "plan first", msg["reasoning_content"])
	calls, ok := msg["tool_calls"].([]any)
	require.True(t, ok, "tool_calls = %#v", msg["tool_calls"])
	require.Len(t, calls, 1)
	call, ok := calls[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "call_tg_1", call["id"])
	fn, ok := call["function"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "lookup", fn["name"])
	assert.Equal(t, `{"q":"x"}`, fn["arguments"])
}

//go:build functional

package functional_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newToolCallUpstream(t *testing.T, toolName string) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&u.hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w,
			`{"id":"chatcmpl-tool","object":"chat.completion",`+
				`"choices":[{"index":0,"message":{"role":"assistant","content":null,`+
				`"tool_calls":[{"id":"call_1","type":"function","function":{"name":%q,"arguments":"{}"}}]},`+
				`"finish_reason":"tool_calls"}],`+
				`"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`,
			toolName,
		)
	}))
	t.Cleanup(u.server.Close)
	return u
}

type perToolChatResponse struct {
	Choices []struct {
		Message struct {
			Content   string `json:"content"`
			ToolCalls []struct {
				Function struct {
					Name string `json:"name"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
}

func decodePerToolResponse(t *testing.T, raw []byte) perToolChatResponse {
	t.Helper()
	var out perToolChatResponse
	require.NoError(t, json.Unmarshal(raw, &out), "response body: %s", raw)
	require.NotEmpty(t, out.Choices, "response must carry a choice, body: %s", raw)
	return out
}

func perToolRule(tool string, maxCalls int, behavior string) map[string]any {
	rule := map[string]any{
		"tool":    tool,
		"windows": []any{map[string]any{"duration": "1m", "max": maxCalls}},
	}
	if behavior != "" {
		rule["behavior"] = behavior
	}
	return rule
}

// A reject_response rule counts tool_calls observed in the model response and,
// once a tool exceeds its window, rejects the call with a 429 and rate-limit
// headers. Counting happens at pre_response, so the upstream is still invoked.
func TestPluginE2E_PerToolRateLimiter_RejectResponse(t *testing.T) {
	defer Track(t, "PluginPerToolRateLimiter")()

	up := newToolCallUpstream(t, "get_weather")
	apiKey, path := setupPolicyRoute(t, up,
		policyPlugin("per_tool_rate_limiter", map[string]any{
			"rules": []any{perToolRule("get_weather", 2, "reject_response")},
		}),
	)

	body := mustJSON(t, chatRequest(false))

	for i := 1; i <= 2; i++ {
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
		require.Equal(t, http.StatusOK, status, "call %d should pass through, body: %s", i, raw)
	}

	status, headers, _ := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	assert.Equal(t, http.StatusTooManyRequests, status, "the tool's window is exhausted, the call must be rejected")
	assert.Equal(t, "get_weather", headers.Get("X-RateLimit-Tool"))
	assert.Equal(t, "2", headers.Get("X-RateLimit-consumer-Limit"))
	assert.Equal(t, "60", headers.Get("Retry-After"))
}

// An inject_error_result rule, once the window is exceeded, strips the offending
// tool_call from the response, appends an assistant rate-limit message and flips
// the finish reason to stop, while still answering 200.
func TestPluginE2E_PerToolRateLimiter_InjectErrorResult(t *testing.T) {
	defer Track(t, "PluginPerToolRateLimiter")()

	up := newToolCallUpstream(t, "get_weather")
	apiKey, path := setupPolicyRoute(t, up,
		policyPlugin("per_tool_rate_limiter", map[string]any{
			"rules": []any{perToolRule("get_weather", 1, "inject_error_result")},
		}),
	)

	body := mustJSON(t, chatRequest(false))

	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	require.Equal(t, http.StatusOK, status, "first call is under the limit, body: %s", raw)
	first := decodePerToolResponse(t, raw)
	require.Len(t, first.Choices[0].Message.ToolCalls, 1, "under-limit response keeps the tool_call, body: %s", raw)
	assert.Equal(t, "get_weather", first.Choices[0].Message.ToolCalls[0].Function.Name)

	status, _, raw = proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	require.Equal(t, http.StatusOK, status, "inject keeps a 200, body: %s", raw)
	second := decodePerToolResponse(t, raw)
	assert.Empty(t, second.Choices[0].Message.ToolCalls, "the rate-limited tool_call must be removed, body: %s", raw)
	assert.Equal(t, "stop", second.Choices[0].FinishReason, "finish reason flips to stop when no tool_calls remain")
	assert.True(t, strings.Contains(second.Choices[0].Message.Content, "get_weather"),
		"the injected assistant message must reference the rate-limited tool, body: %s", raw)
}

// A rule without an explicit behavior falls back to behavior_default, and the
// tool pattern is matched as a glob: get_weather matches get_* and is rejected
// once its window is exhausted.
func TestPluginE2E_PerToolRateLimiter_GlobMatchUsesDefaultBehavior(t *testing.T) {
	defer Track(t, "PluginPerToolRateLimiter")()

	up := newToolCallUpstream(t, "get_weather")
	apiKey, path := setupPolicyRoute(t, up,
		policyPlugin("per_tool_rate_limiter", map[string]any{
			"rules":            []any{perToolRule("get_*", 1, "")},
			"behavior_default": "reject_response",
		}),
	)

	body := mustJSON(t, chatRequest(false))

	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	require.Equal(t, http.StatusOK, status, "first call is under the limit, body: %s", raw)

	status, headers, _ := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	assert.Equal(t, http.StatusTooManyRequests, status, "glob-matched tool must use the default reject behavior")
	assert.Equal(t, "get_weather", headers.Get("X-RateLimit-Tool"))
}

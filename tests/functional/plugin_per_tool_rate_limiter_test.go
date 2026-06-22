//go:build functional

package functional_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newPerToolUpstream(t *testing.T, toolName string) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.record(r)
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

func chatRequestWithTools(tools ...string) map[string]any {
	specs := make([]map[string]any, 0, len(tools))
	for _, name := range tools {
		specs = append(specs, map[string]any{
			"type":     "function",
			"function": map[string]any{"name": name, "parameters": map[string]any{"type": "object"}},
		})
	}
	return map[string]any{
		"model":    "gpt-4o-mini",
		"messages": []map[string]string{{"role": "user", "content": "Hello"}},
		"tools":    specs,
	}
}

func forwardedToolNames(t *testing.T, raw []byte) []string {
	t.Helper()
	var parsed struct {
		Tools []struct {
			Function struct {
				Name string `json:"name"`
			} `json:"function"`
		} `json:"tools"`
	}
	require.NoError(t, json.Unmarshal(raw, &parsed), "upstream body: %s", raw)
	out := make([]string, 0, len(parsed.Tools))
	for _, tl := range parsed.Tools {
		out = append(out, tl.Function.Name)
	}
	return out
}

func TestPluginE2E_PerToolRateLimiter_RejectResponse(t *testing.T) {
	defer Track(t, "PluginPerToolRateLimiter")()

	up := newPerToolUpstream(t, "get_weather")
	apiKey, path := setupPolicyRoute(t, up,
		policyPlugin("per_tool_rate_limiter", map[string]any{
			"rules": []any{perToolRule("get_weather", 1, "reject_response")},
		}),
	)

	body := mustJSON(t, chatRequestWithTools("get_weather"))

	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	require.Equal(t, http.StatusOK, status, "first call is under the limit, body: %s", raw)

	var rlHeaders http.Header
	require.Eventually(t, func() bool {
		s, h, _ := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
		if s == http.StatusTooManyRequests {
			rlHeaders = h
			return true
		}
		return false
	}, 5*time.Second, 100*time.Millisecond,
		"once the tool's window is exhausted the next request must be rejected")

	assert.Equal(t, "get_weather", rlHeaders.Get("X-RateLimit-Tool"))
	assert.Equal(t, "1", rlHeaders.Get("X-RateLimit-consumer-Limit"))
	assert.Equal(t, "60", rlHeaders.Get("Retry-After"))
}

func TestPluginE2E_PerToolRateLimiter_InjectErrorResult(t *testing.T) {
	defer Track(t, "PluginPerToolRateLimiter")()

	up := newPerToolUpstream(t, "get_weather")
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

	var injected perToolChatResponse
	require.Eventually(t, func() bool {
		s, _, r := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
		if s != http.StatusOK {
			return false
		}
		resp := decodePerToolResponse(t, r)
		if len(resp.Choices[0].Message.ToolCalls) == 0 {
			injected = resp
			return true
		}
		return false
	}, 5*time.Second, 100*time.Millisecond,
		"once the window is exhausted the tool_call must be injected away")

	assert.Equal(t, "stop", injected.Choices[0].FinishReason)
	assert.True(t, strings.Contains(injected.Choices[0].Message.Content, "get_weather"),
		"the injected assistant message must reference the rate-limited tool")
}

func TestPluginE2E_PerToolRateLimiter_StripToolFromRequest(t *testing.T) {
	defer Track(t, "PluginPerToolRateLimiter")()

	up := newPerToolUpstream(t, "get_weather")
	apiKey, path := setupPolicyRoute(t, up,
		policyPlugin("per_tool_rate_limiter", map[string]any{
			"rules": []any{perToolRule("get_weather", 1, "strip_tool_from_request")},
		}),
	)

	body := mustJSON(t, chatRequestWithTools("get_weather", "lookup"))

	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	require.Equal(t, http.StatusOK, status, "first call is under the limit, body: %s", raw)

	require.Eventually(t, func() bool {
		_, _, _ = proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
		tools := forwardedToolNames(t, up.LastBody())
		return len(tools) == 1 && tools[0] == "lookup"
	}, 5*time.Second, 100*time.Millisecond,
		"once over budget, get_weather must be stripped from the forwarded tools while lookup remains")
}

func TestPluginE2E_PerToolRateLimiter_GlobMatchUsesDefaultBehavior(t *testing.T) {
	defer Track(t, "PluginPerToolRateLimiter")()

	up := newPerToolUpstream(t, "get_weather")
	apiKey, path := setupPolicyRoute(t, up,
		policyPlugin("per_tool_rate_limiter", map[string]any{
			"rules":            []any{perToolRule("get_*", 1, "")},
			"behavior_default": "reject_response",
		}),
	)

	body := mustJSON(t, chatRequestWithTools("get_weather"))

	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	require.Equal(t, http.StatusOK, status, "first call is under the limit, body: %s", raw)

	var rlHeaders http.Header
	require.Eventually(t, func() bool {
		s, h, _ := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
		if s == http.StatusTooManyRequests {
			rlHeaders = h
			return true
		}
		return false
	}, 5*time.Second, 100*time.Millisecond,
		"glob-matched tool must use the default reject behavior once exhausted")

	assert.Equal(t, "get_weather", rlHeaders.Get("X-RateLimit-Tool"))
}

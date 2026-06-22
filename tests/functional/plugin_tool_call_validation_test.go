//go:build functional

package functional_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newToolCallUpstream answers every request with a 200 chat-completion whose
// assistant message carries a single OpenAI tool_call for toolName with the
// given JSON-string arguments, so the pre_response tool_call_validation plugin
// has tool_calls to inspect.
func newToolCallUpstream(t *testing.T, toolName, argumentsJSON string) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w,
			`{"id":"chatcmpl-test","object":"chat.completion","choices":[{"index":0,`+
				`"message":{"role":"assistant","content":null,"tool_calls":[`+
				`{"id":"call_1","type":"function","function":{"name":%q,"arguments":%q}}]},`+
				`"finish_reason":"tool_calls"}]}`,
			toolName, argumentsJSON,
		)
	}))
	t.Cleanup(u.server.Close)
	return u
}

// toolCallChatRequest builds an OpenAI chat body that advertises the given tools
// so the plugin can decode the request's allowed tool set.
func toolCallChatRequest(toolNames ...string) map[string]any {
	tools := make([]map[string]any, 0, len(toolNames))
	for _, name := range toolNames {
		tools = append(tools, map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        name,
				"description": "functional test tool",
				"parameters": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"to":   map[string]any{"type": "string"},
						"code": map[string]any{"type": "string"},
					},
				},
			},
		})
	}
	return map[string]any{
		"model":    "gpt-4o-mini",
		"messages": []map[string]string{{"role": "user", "content": "do it"}},
		"tools":    tools,
	}
}

// toolCallChatRequestWithPrompt is like toolCallChatRequest but lets the caller
// set the user message, which the semantic validator feeds to the LLM as the
// user's request when judging whether the tool_call is appropriate.
func toolCallChatRequestWithPrompt(prompt string, toolNames ...string) map[string]any {
	req := toolCallChatRequest(toolNames...)
	req["messages"] = []map[string]string{{"role": "user", "content": prompt}}
	return req
}

// TestPluginE2E_ToolCallValidation drives the tool_call_validation plugin end to
// end through the proxy plane: an allowed tool_call is forwarded untouched, a
// hallucinated tool is rejected with 403, a regex allow-pattern miss is rejected
// with 502, and a denylisted argument is transparently redacted in the body.
func TestPluginE2E_ToolCallValidation(t *testing.T) {
	defer Track(t, "PluginToolCallValidation")()

	t.Run("allowed tool with valid argument is forwarded", func(t *testing.T) {
		up := newToolCallUpstream(t, "send_email", `{"to":"bob@company.com"}`)
		settings := map[string]any{
			"rules": []any{
				map[string]any{"validator": "not_in_allowed_list", "behavior": "reject_response"},
			},
		}
		apiKey, path := setupPolicyRoute(t, up, policyPlugin("tool_call_validation", settings))

		status, _, body := proxyPost(t, apiKey, path, toolCallChatRequest("send_email"))

		require.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(body), "send_email")
		assert.Equal(t, 1, up.Hits())
	})

	t.Run("hallucinated tool not in the request is rejected with 403", func(t *testing.T) {
		up := newToolCallUpstream(t, "transfer_money", `{"amount":"100"}`)
		settings := map[string]any{
			"rules": []any{
				map[string]any{"validator": "not_in_allowed_list", "behavior": "reject_response"},
			},
		}
		apiKey, path := setupPolicyRoute(t, up, policyPlugin("tool_call_validation", settings))

		status, _, body := proxyPost(t, apiKey, path, toolCallChatRequest("send_email"))

		require.Equal(t, http.StatusForbidden, status, "body: %s", body)
		assert.Contains(t, string(body), "tool_not_in_list")
	})

	t.Run("regex allow-pattern miss is rejected with 502", func(t *testing.T) {
		up := newToolCallUpstream(t, "send_email", `{"to":"attacker@evil.com"}`)
		settings := map[string]any{
			"rules": []any{
				map[string]any{
					"tool":          "send_email",
					"validator":     "regex",
					"argument_path": "$.to",
					"pattern":       `^[\w.+-]+@(company\.com|partner\.com)$`,
					"behavior":      "reject_response",
				},
			},
		}
		apiKey, path := setupPolicyRoute(t, up, policyPlugin("tool_call_validation", settings))

		status, _, body := proxyPost(t, apiKey, path, toolCallChatRequest("send_email"))

		require.Equal(t, http.StatusBadGateway, status, "body: %s", body)
		assert.Contains(t, string(body), "tool_call_validation_failed")
	})

	t.Run("denylisted argument is redacted in the forwarded body", func(t *testing.T) {
		up := newToolCallUpstream(t, "run_shell", `{"code":"rm -rf / \u0026\u0026 echo done"}`)
		settings := map[string]any{
			"rules": []any{
				map[string]any{
					"tool":          "run_shell",
					"validator":     "denylist",
					"argument_path": "$.code",
					"denylist":      []any{"rm -rf"},
					"behavior":      "redact",
					"redact_with":   "[REDACTED]",
				},
			},
		}
		apiKey, path := setupPolicyRoute(t, up, policyPlugin("tool_call_validation", settings))

		status, _, body := proxyPost(t, apiKey, path, toolCallChatRequest("run_shell"))

		require.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(body), "[REDACTED]")
		assert.NotContains(t, string(body), "rm -rf")
	})
}

// TestPluginE2E_ToolCallValidationSemantic exercises the semantic validator
// against a real OpenAI Responses API, so it is skipped when OPENAI_API_KEY is
// absent, mirroring the semantic_cache functional test. A tool_call that is
// clearly misaligned with the user request is blocked with 403
// tool_semantic_blocked; an aligned tool_call is forwarded.
func TestPluginE2E_ToolCallValidationSemantic(t *testing.T) {
	defer Track(t, "PluginToolCallValidationSemantic")()

	openAIKey := os.Getenv("OPENAI_API_KEY")
	if openAIKey == "" {
		t.Skip("OPENAI_API_KEY not set, skipping semantic tool_call_validation functional test")
	}

	semanticSettings := func() map[string]any {
		return map[string]any{
			"semantic": map[string]any{
				"provider": "openai",
				"api_key":  openAIKey,
				"model":    "gpt-4o-mini",
			},
			"rules": []any{
				map[string]any{"validator": "semantic", "behavior": "reject_response"},
			},
		}
	}

	t.Run("misaligned tool_call is blocked with 403", func(t *testing.T) {
		up := newToolCallUpstream(t, "delete_database", `{"target":"production","drop_all":true}`)
		apiKey, path := setupPolicyRoute(t, up, policyPlugin("tool_call_validation", semanticSettings()))

		status, _, body := proxyPost(t, apiKey, path,
			toolCallChatRequestWithPrompt("What is the capital of France?", "delete_database"),
		)

		require.Equal(t, http.StatusForbidden, status, "body: %s", body)
		assert.Contains(t, string(body), "tool_semantic_blocked")
	})

	t.Run("aligned tool_call is forwarded", func(t *testing.T) {
		up := newToolCallUpstream(t, "get_weather", `{"city":"Paris"}`)
		apiKey, path := setupPolicyRoute(t, up, policyPlugin("tool_call_validation", semanticSettings()))

		status, _, body := proxyPost(t, apiKey, path,
			toolCallChatRequestWithPrompt("What is the weather in Paris today?", "get_weather"),
		)

		require.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(body), "get_weather")
	})
}

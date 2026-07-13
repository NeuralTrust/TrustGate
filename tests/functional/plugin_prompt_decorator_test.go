//go:build functional

package functional_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func promptDecoratorPolicy(settings map[string]any) map[string]any {
	return policyPlugin("prompt_decorator", settings)
}

func promptDecoratorSettings(decorators ...map[string]any) map[string]any {
	return map[string]any{"decorators": decorators}
}

func promptDecorator(position, role, content string) map[string]any {
	return map[string]any{
		"position": position,
		"role":     role,
		"content":  content,
	}
}

func promptSystemDecorator(content, strategy string) map[string]any {
	entry := promptDecorator("system", "system", content)
	entry["on_existing_system"] = strategy
	return entry
}

func decodedPromptBody(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var body map[string]any
	require.NoError(t, json.Unmarshal(raw, &body))
	return body
}

func decodedPromptMessages(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	var body struct {
		Messages []map[string]any `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(raw, &body))
	messages := body.Messages
	return messages
}

func promptRoles(messages []map[string]any) []string {
	roles := make([]string, 0, len(messages))
	for _, message := range messages {
		role, _ := message["role"].(string)
		roles = append(roles, role)
	}
	return roles
}

func TestPluginE2E_PromptDecorator_ScopeAndSameSlugOverride(t *testing.T) {
	defer Track(t, "PromptDecorator")()

	up := newJSONUpstream(t, "scope-response")
	gatewayID, backendID := setupGatewayBackend(t, up)
	createGlobalPolicy(t, gatewayID, "prompt_decorator",
		promptDecoratorSettings(promptDecorator("end", "assistant", "global-marker")))
	scopedID := createScopedPolicy(t, gatewayID, "prompt_decorator",
		promptDecoratorSettings(promptDecorator("end", "assistant", "consumer-marker")), 0, false)
	scopedPath, scopedKey := addConsumerRoute(t, gatewayID, backendID, scopedID)
	globalPath, globalKey := addConsumerRoute(t, gatewayID, backendID)
	body := mustJSON(t, chatBody([]map[string]any{
		{"role": "user", "content": "scope-input"},
	}, nil))
	status, _, _ := proxyRequest(t, http.MethodPost, scopedKey, scopedPath, nil, body)
	require.Equal(t, http.StatusOK, status)
	scopedMessages := decodedPromptMessages(t, up.LastBody())
	require.Equal(t, "consumer-marker", scopedMessages[len(scopedMessages)-1]["content"])
	assert.NotContains(t, string(up.LastBody()), "global-marker")
	status, _, _ = proxyRequest(t, http.MethodPost, globalKey, globalPath, nil, body)
	require.Equal(t, http.StatusOK, status)
	globalMessages := decodedPromptMessages(t, up.LastBody())
	require.Equal(t, "global-marker", globalMessages[len(globalMessages)-1]["content"])
	assert.NotContains(t, string(up.LastBody()), "consumer-marker")
	assert.Equal(t, 2, up.Hits())
}

func TestPluginE2E_PromptDecorator_OpenAIPositionsOrderAndFidelity(t *testing.T) {
	defer Track(t, "PromptDecorator")()

	up := newJSONUpstream(t, "openai-response")
	settings := promptDecoratorSettings(
		promptSystemDecorator("system-decoration", "merge"),
		promptDecorator("after_system", "assistant", "after-system"),
		promptDecorator("start", "user", "start-entry"),
		promptDecorator("before_last_user", "assistant", "before-user"),
		promptDecorator("end", "assistant", "end-entry"),
	)
	apiKey, path := setupPolicyRoute(t, up, promptDecoratorPolicy(settings))
	body := mustJSON(t, chatBody([]map[string]any{
		{"role": "system", "content": "base-system", "system_extension": map[string]any{"enabled": true}},
		{
			"role": "user",
			"content": []map[string]any{
				{"type": "text", "text": "rich-user", "cache_control": map[string]any{"type": "ephemeral"}},
				{"type": "image_url", "image_url": map[string]any{"url": "https://example.invalid/neutral.png"}},
			},
			"message_extension": map[string]any{"enabled": true},
		},
	}, map[string]any{"request_extension": map[string]any{"enabled": true}}))

	status, _, _ := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	require.Equal(t, http.StatusOK, status)

	forwarded := decodedPromptBody(t, up.LastBody())
	messages := decodedPromptMessages(t, up.LastBody())
	require.Equal(t, []string{"user", "system", "assistant", "assistant", "user", "assistant"}, promptRoles(messages))
	assert.Equal(t, "start-entry", messages[0]["content"])
	assert.Equal(t, "base-system\n\nsystem-decoration", messages[1]["content"])
	assert.Equal(t, "after-system", messages[2]["content"])
	assert.Equal(t, "before-user", messages[3]["content"])
	assert.Equal(t, "end-entry", messages[5]["content"])
	assert.Equal(t, map[string]any{"enabled": true}, messages[1]["system_extension"])
	assert.Equal(t, map[string]any{"enabled": true}, messages[4]["message_extension"])
	assert.Equal(t, map[string]any{"enabled": true}, forwarded["request_extension"])
	content, ok := messages[4]["content"].([]any)
	require.True(t, ok)
	require.Len(t, content, 2)
	assert.Equal(t, "rich-user", content[0].(map[string]any)["text"])
	assert.Equal(t, "image_url", content[1].(map[string]any)["type"])
}

func TestPluginE2E_PromptDecorator_OpenAISystemStrategies(t *testing.T) {
	defer Track(t, "PromptDecorator")()

	tests := []struct {
		strategy string
		want     []map[string]any
	}{
		{strategy: "merge", want: []map[string]any{
			{"role": "system", "content": "base-system\n\ndecoration"},
			{"role": "user", "content": "strategy-input"},
		}},
		{strategy: "replace", want: []map[string]any{
			{"role": "system", "content": "decoration"},
			{"role": "user", "content": "strategy-input"},
		}},
		{strategy: "append", want: []map[string]any{
			{"role": "system", "content": "base-system"},
			{"role": "system", "content": "decoration"},
			{"role": "user", "content": "strategy-input"},
		}},
		{strategy: "skip", want: []map[string]any{
			{"role": "system", "content": "base-system"},
			{"role": "user", "content": "strategy-input"},
		}},
	}

	for _, test := range tests {
		t.Run(test.strategy, func(t *testing.T) {
			up := newJSONUpstream(t, "strategy-response")
			apiKey, path := setupPolicyRoute(t, up, promptDecoratorPolicy(
				promptDecoratorSettings(promptSystemDecorator("decoration", test.strategy))))
			body := mustJSON(t, chatBody([]map[string]any{
				{"role": "system", "content": "base-system"},
				{"role": "user", "content": "strategy-input"},
			}, nil))
			status, _, _ := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
			require.Equal(t, http.StatusOK, status)
			messages := decodedPromptMessages(t, up.LastBody())
			require.Len(t, messages, len(test.want))
			actual := make([]map[string]any, 0, len(messages))
			for _, message := range messages {
				actual = append(actual, map[string]any{
					"role":    message["role"],
					"content": message["content"],
				})
			}
			assert.Equal(t, test.want, actual)
			if test.strategy == "skip" {
				assert.NotContains(t, string(up.LastBody()), "decoration")
			}
		})
	}
}

func TestPluginE2E_PromptDecorator_AnthropicSystemsAndMessages(t *testing.T) {
	defer Track(t, "PromptDecorator")()

	tests := []struct {
		name   string
		system any
	}{
		{name: "string", system: "anthropic-base"},
		{name: "blocks", system: []map[string]any{
			{"type": "text", "text": "anthropic-base", "cache_control": map[string]any{"type": "ephemeral"}},
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			up := newJSONUpstream(t, "anthropic-response")
			settings := promptDecoratorSettings(
				promptSystemDecorator("anthropic-decoration", "append"),
				promptDecorator("after_system", "assistant", "anthropic-first"),
				promptDecorator("end", "user", "anthropic-last"),
			)
			settings["require_system_message"] = true
			apiKey, chatPath := setupPolicyRoute(t, up, promptDecoratorPolicy(settings))
			body := map[string]any{
				"model":      "@openai/gpt-4o-mini",
				"max_tokens": 64,
				"system":     test.system,
				"messages": []map[string]any{
					{"role": "user", "content": []map[string]any{{"type": "text", "text": "anthropic-user"}}},
				},
			}

			status, _, _ := proxyRequest(t, http.MethodPost, apiKey, anthropicMessagesPath(chatPath), nil, mustJSON(t, body))
			require.Equal(t, http.StatusOK, status)
			require.Equal(t, 1, up.Hits())
			messages := decodedPromptMessages(t, up.LastBody())
			require.Equal(t, []string{"system", "assistant", "user", "user"}, promptRoles(messages))
			assert.Equal(t, "anthropic-base\nanthropic-decoration", messages[0]["content"])
			assert.Equal(t, "anthropic-first", messages[1]["content"])
			assert.Equal(t, "anthropic-user", messages[2]["content"])
			assert.Equal(t, "anthropic-last", messages[3]["content"])
		})
	}
}

func TestPluginE2E_PromptDecorator_ObserveDoesNotMutateOrReject(t *testing.T) {
	defer Track(t, "PromptDecorator")()

	up := newJSONUpstream(t, "observe-response")
	entry := promptDecoratorPolicy(map[string]any{
		"decorators":             []map[string]any{promptSystemDecorator("observe-decoration", "merge")},
		"require_system_message": true,
	})
	entry["mode"] = "observe"
	apiKey, path := setupPolicyRoute(t, up, entry)
	body := mustJSON(t, chatBody([]map[string]any{
		{
			"role": "user",
			"content": []map[string]any{
				{"type": "text", "text": "observe-input", "content_extension": map[string]any{"enabled": true}},
			},
			"message_extension": map[string]any{"enabled": true},
		},
	}, map[string]any{
		"request_extension": map[string]any{"enabled": true},
		"unknown_scalar":    "preserve-me",
	}))

	status, _, _ := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, up.Hits())
	assert.JSONEq(t, string(body), string(up.LastBody()))
}

func TestPluginE2E_PromptDecorator_RequireSystemRejectsOriginalAbsence(t *testing.T) {
	defer Track(t, "PromptDecorator")()

	tests := []struct {
		name   string
		path   func(string) string
		body   map[string]any
		before []map[string]any
	}{
		{
			name: "own decorator cannot satisfy missing original",
			path: func(path string) string { return path },
			body: chatBody([]map[string]any{{"role": "user", "content": "missing-system"}}, nil),
			before: []map[string]any{promptDecoratorPolicy(map[string]any{
				"decorators":             []map[string]any{promptSystemDecorator("self-injected", "merge")},
				"require_system_message": true,
			})},
		},
		{
			name: "blank original is absent",
			path: func(path string) string { return path },
			body: chatBody([]map[string]any{
				{"role": "system", "content": " \n\t "},
				{"role": "user", "content": "blank-system"},
			}, nil),
			before: []map[string]any{promptDecoratorPolicy(map[string]any{"require_system_message": true})},
		},
		{
			name: "blank anthropic blocks are absent",
			path: anthropicMessagesPath,
			body: map[string]any{
				"model":      "@openai/gpt-4o-mini",
				"max_tokens": 64,
				"system":     []map[string]any{{"type": "text", "text": " \n\t "}},
				"messages":   []map[string]any{{"role": "user", "content": "blank-block"}},
			},
			before: []map[string]any{promptDecoratorPolicy(map[string]any{"require_system_message": true})},
		},
		{
			name: "preceding content mutator cannot satisfy missing original",
			path: func(path string) string { return path },
			body: chatBody([]map[string]any{{"role": "user", "content": "preceding-mutator"}}, nil),
			before: []map[string]any{
				policyPayload("prompt_template", map[string]any{
					"inject_templates": []map[string]any{{"id": "sys", "content": "preceding-injection"}},
				}, 0, false),
				policyPayload("prompt_decorator", map[string]any{"require_system_message": true}, 1, false),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			up := newJSONUpstream(t, "rejected-response")
			apiKey, path := setupPolicyRoute(t, up, test.before...)

			status, _, raw := proxyRequest(t, http.MethodPost, apiKey, test.path(path), nil, mustJSON(t, test.body))

			require.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, []byte(`{"error":{"type":"system_message_required"}}`), raw)
			assert.Equal(t, 0, up.Hits())
		})
	}
}

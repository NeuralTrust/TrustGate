//go:build functional

package functional_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func promptTemplatePolicy(settings map[string]any) map[string]any {
	return policyPlugin("prompt_template", settings)
}

func promptObservePolicy(settings map[string]any) map[string]any {
	entry := policyPlugin("prompt_template", settings)
	entry["mode"] = "observe"
	return entry
}

func chatBody(messages []map[string]any, extra map[string]any) map[string]any {
	body := map[string]any{
		"model":    "gpt-4o-mini",
		"messages": messages,
	}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

func unsignedJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
}

func TestPluginE2E_PromptTemplate_ModeAHeaderInjection(t *testing.T) {
	defer Track(t, "PromptTemplate")()

	t.Run("inserts a system message when none exists", func(t *testing.T) {
		up := newJSONUpstream(t, "prompt-insert")
		apiKey, path := setupPolicyRoute(t, up, promptTemplatePolicy(map[string]any{
			"context_variables": map[string]any{
				"tenant": map[string]any{"source": "header", "name": "X-Tenant-Id"},
			},
			"inject_templates": []map[string]any{
				{"id": "sys", "content": "You are support for {{tenant}}."},
			},
			"on_missing_context_variable": "error",
		}))

		body := mustJSON(t, chatBody([]map[string]any{
			{"role": "user", "content": "Hello"},
		}, nil))
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path,
			map[string]string{"X-Tenant-Id": "acme"}, body)

		require.Equal(t, http.StatusOK, status, "body: %s", raw)
		require.Equal(t, 1, up.Hits())
		forwarded := string(up.LastBody())
		assert.Contains(t, forwarded, "You are support for acme.")
		assert.Contains(t, forwarded, `"role":"system"`)
	})

	t.Run("merge appends rendered content to an existing system message", func(t *testing.T) {
		up := newJSONUpstream(t, "prompt-merge")
		apiKey, path := setupPolicyRoute(t, up, promptTemplatePolicy(map[string]any{
			"context_variables": map[string]any{
				"tenant": map[string]any{"source": "header", "name": "X-Tenant-Id"},
			},
			"inject_templates": []map[string]any{
				{"id": "sys", "content": "You are support for {{tenant}}.", "on_existing_system": "merge"},
			},
		}))

		body := mustJSON(t, chatBody([]map[string]any{
			{"role": "system", "content": "Be concise."},
			{"role": "user", "content": "Hello"},
		}, nil))
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path,
			map[string]string{"X-Tenant-Id": "acme"}, body)

		require.Equal(t, http.StatusOK, status, "body: %s", raw)
		forwarded := string(up.LastBody())
		assert.Contains(t, forwarded, "Be concise.")
		assert.Contains(t, forwarded, "You are support for acme.")
	})

	t.Run("replace overwrites an existing system message", func(t *testing.T) {
		up := newJSONUpstream(t, "prompt-replace")
		apiKey, path := setupPolicyRoute(t, up, promptTemplatePolicy(map[string]any{
			"context_variables": map[string]any{
				"tenant": map[string]any{"source": "header", "name": "X-Tenant-Id"},
			},
			"inject_templates": []map[string]any{
				{"id": "sys", "content": "You are support for {{tenant}}.", "on_existing_system": "replace"},
			},
		}))

		body := mustJSON(t, chatBody([]map[string]any{
			{"role": "system", "content": "Be concise."},
			{"role": "user", "content": "Hello"},
		}, nil))
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path,
			map[string]string{"X-Tenant-Id": "acme"}, body)

		require.Equal(t, http.StatusOK, status, "body: %s", raw)
		forwarded := string(up.LastBody())
		assert.Contains(t, forwarded, "You are support for acme.")
		assert.NotContains(t, forwarded, "Be concise.")
	})
}

func TestPluginE2E_PromptTemplate_ModeAJWTClaimInjection(t *testing.T) {
	defer Track(t, "PromptTemplate")()

	up := newJSONUpstream(t, "prompt-jwt")
	apiKey, path := setupPolicyRoute(t, up, promptTemplatePolicy(map[string]any{
		"context_variables": map[string]any{
			"user_role": map[string]any{"source": "jwt_claim", "name": "role"},
		},
		"inject_templates": []map[string]any{
			{"id": "sys", "content": "Caller role is {{user_role}}."},
		},
	}))

	token := unsignedJWT(t, map[string]any{"role": "admin"})
	body := mustJSON(t, chatBody([]map[string]any{
		{"role": "user", "content": "Hello"},
	}, nil))
	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path,
		map[string]string{"Authorization": "Bearer " + token}, body)

	require.Equal(t, http.StatusOK, status, "body: %s", raw)
	assert.Contains(t, string(up.LastBody()), "Caller role is admin.")
}

func TestPluginE2E_PromptTemplate_ModeBRenderReplacesMessages(t *testing.T) {
	defer Track(t, "PromptTemplate")()

	up := newJSONUpstream(t, "prompt-modeb")
	apiKey, path := setupPolicyRoute(t, up, promptTemplatePolicy(map[string]any{
		"named_templates": []map[string]any{
			{
				"name": "support-bot",
				"versions": []map[string]any{
					{
						"version": "v3",
						"labels":  []string{"stable"},
						"content": `[{"role":"system","content":"You are {{persona}} support."},{"role":"user","content":"{{question}}"}]`,
						"required_variables": map[string]any{
							"persona": map[string]any{"type": "string", "enum": []string{"friendly", "formal"}},
						},
					},
				},
			},
		},
		"default_label":              "stable",
		"allow_untemplated_requests": false,
	}))

	body := mustJSON(t, chatBody([]map[string]any{
		{"role": "user", "content": "{template://support-bot@stable}"},
	}, map[string]any{
		"properties": map[string]any{"persona": "friendly", "question": "How do I reset my password?"},
	}))
	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)

	require.Equal(t, http.StatusOK, status, "body: %s", raw)
	forwarded := string(up.LastBody())
	assert.Contains(t, forwarded, "You are friendly support.")
	assert.Contains(t, forwarded, "How do I reset my password?")
	assert.NotContains(t, forwarded, "template://", "the reference token must not reach the upstream")
	assert.NotContains(t, forwarded, "properties", "the gateway-only properties field must be stripped")
}

func TestPluginE2E_PromptTemplate_ErrorCodes(t *testing.T) {
	defer Track(t, "PromptTemplate")()

	namedTemplate := []map[string]any{
		{
			"name": "support-bot",
			"versions": []map[string]any{
				{
					"version": "v3",
					"labels":  []string{"stable"},
					"content": `[{"role":"system","content":"You are {{persona}} support."}]`,
					"required_variables": map[string]any{
						"persona": map[string]any{"type": "string", "enum": []string{"friendly", "formal"}},
					},
				},
			},
		},
	}

	t.Run("unresolved context variable returns 500 template_variable_unresolved", func(t *testing.T) {
		up := newJSONUpstream(t, "prompt-unresolved")
		apiKey, path := setupPolicyRoute(t, up, promptTemplatePolicy(map[string]any{
			"context_variables": map[string]any{
				"tenant": map[string]any{"source": "header", "name": "X-Tenant-Id"},
			},
			"inject_templates": []map[string]any{
				{"id": "sys", "content": "You are support for {{tenant}}."},
			},
			"on_missing_context_variable": "error",
		}))

		body := mustJSON(t, chatBody([]map[string]any{{"role": "user", "content": "Hello"}}, nil))
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)

		assert.Equal(t, http.StatusInternalServerError, status, "body: %s", raw)
		assert.Contains(t, string(raw), "template_variable_unresolved")
		assert.Equal(t, 0, up.Hits(), "a rejected request must not reach the upstream")
	})

	t.Run("missing required client variable returns 400 template_variable_missing", func(t *testing.T) {
		up := newJSONUpstream(t, "prompt-missing")
		apiKey, path := setupPolicyRoute(t, up, promptTemplatePolicy(map[string]any{
			"named_templates":            namedTemplate,
			"default_label":              "stable",
			"allow_untemplated_requests": false,
		}))

		body := mustJSON(t, chatBody([]map[string]any{
			{"role": "user", "content": "{template://support-bot@stable}"},
		}, map[string]any{"properties": map[string]any{}}))
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)

		assert.Equal(t, http.StatusBadRequest, status, "body: %s", raw)
		assert.Contains(t, string(raw), "template_variable_missing")
		assert.Equal(t, 0, up.Hits())
	})

	t.Run("invalid client variable returns 400 template_variable_invalid", func(t *testing.T) {
		up := newJSONUpstream(t, "prompt-invalid")
		apiKey, path := setupPolicyRoute(t, up, promptTemplatePolicy(map[string]any{
			"named_templates":            namedTemplate,
			"default_label":              "stable",
			"allow_untemplated_requests": false,
		}))

		body := mustJSON(t, chatBody([]map[string]any{
			{"role": "user", "content": "{template://support-bot@stable}"},
		}, map[string]any{"properties": map[string]any{"persona": "rude"}}))
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)

		assert.Equal(t, http.StatusBadRequest, status, "body: %s", raw)
		assert.Contains(t, string(raw), "template_variable_invalid")
		assert.Equal(t, 0, up.Hits())
	})

	t.Run("unknown template returns 400 template_not_found", func(t *testing.T) {
		up := newJSONUpstream(t, "prompt-notfound")
		apiKey, path := setupPolicyRoute(t, up, promptTemplatePolicy(map[string]any{
			"named_templates":            namedTemplate,
			"default_label":              "stable",
			"allow_untemplated_requests": false,
		}))

		body := mustJSON(t, chatBody([]map[string]any{
			{"role": "user", "content": "{template://nope@v9}"},
		}, map[string]any{"properties": map[string]any{"persona": "friendly"}}))
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)

		assert.Equal(t, http.StatusBadRequest, status, "body: %s", raw)
		assert.Contains(t, string(raw), "template_not_found")
		assert.Equal(t, 0, up.Hits())
	})

	t.Run("no reference with allow_untemplated_requests false returns 400 template_required", func(t *testing.T) {
		up := newJSONUpstream(t, "prompt-required")
		apiKey, path := setupPolicyRoute(t, up, promptTemplatePolicy(map[string]any{
			"named_templates":            namedTemplate,
			"default_label":              "stable",
			"allow_untemplated_requests": false,
		}))

		body := mustJSON(t, chatBody([]map[string]any{
			{"role": "user", "content": "Hello, no template here"},
		}, nil))
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)

		assert.Equal(t, http.StatusBadRequest, status, "body: %s", raw)
		assert.Contains(t, string(raw), "template_required")
		assert.Equal(t, 0, up.Hits())
	})
}

func TestPluginE2E_PromptTemplate_ObserveDoesNotMutateButStripsProperties(t *testing.T) {
	defer Track(t, "PromptTemplate")()

	up := newJSONUpstream(t, "prompt-observe")
	apiKey, path := setupPolicyRoute(t, up, promptObservePolicy(map[string]any{
		"context_variables": map[string]any{
			"tenant": map[string]any{"source": "header", "name": "X-Tenant-Id"},
		},
		"inject_templates": []map[string]any{
			{"id": "sys", "content": "You are support for {{tenant}}."},
		},
		"on_missing_context_variable": "error",
	}))

	body := mustJSON(t, chatBody([]map[string]any{
		{"role": "user", "content": "Hello"},
	}, map[string]any{"properties": map[string]any{"foo": "bar"}}))
	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)

	require.Equal(t, http.StatusOK, status,
		"observe must never reject even when enforce would, body: %s", raw)
	require.Equal(t, 1, up.Hits())
	forwarded := string(up.LastBody())
	assert.NotContains(t, forwarded, "You are support for", "observe must not inject the prompt")
	assert.NotContains(t, forwarded, "properties", "the gateway-only properties field must still be stripped under observe")
}

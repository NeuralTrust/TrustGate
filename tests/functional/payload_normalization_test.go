//go:build functional

package functional_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func anthropicChatRequest(model string) map[string]any {
	return map[string]any{
		"model":      model,
		"max_tokens": 128,
		"messages":   []map[string]string{{"role": "user", "content": "Hello"}},
	}
}

// setupSlugRoute wires a gateway with one OpenAI backend pointing at up and a
// consumer bound to it with the given model policy, returning the api key and
// the consumer slug so tests can build any fixed proxy route.
func setupSlugRoute(t *testing.T, up *fakeUpstream, allowed []string, defaultModel string) (string, string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"name": uniqueName("norm-gw")})
	backendID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be"), up.URL()))
	policy := map[string]any{"allowed": allowed}
	if defaultModel != "" {
		policy["default"] = defaultModel
	}
	coID := CreateConsumer(t, gatewayID, map[string]any{
		"name": uniqueName("cons"),
		"registries": []map[string]any{
			{"id": backendID, "model_policies": policy},
		},
	})
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	return apiKey, ConsumerSlug(t, coID)
}

func TestPayloadNormalization_CrossFormat(t *testing.T) {
	defer Track(t, "PayloadNormalization")()

	t.Run("anthropic request to an openai upstream is adapted both ways", func(t *testing.T) {
		up := newJSONUpstream(t, "cross-format-served")
		apiKey, slug := setupSlugRoute(t, up, []string{"gpt-4o-mini"}, "")

		status, _, body := proxyPost(t, apiKey, "/"+slug+"/v1/messages",
			anthropicChatRequest("@openai/gpt-4o-mini"))

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(body), `"type":"message"`,
			"the client must receive an anthropic-format response")
		assert.Contains(t, string(body), "cross-format-served")
		assert.Equal(t, 1, up.Hits())
		assert.Contains(t, string(up.LastBody()), `"model":"gpt-4o-mini"`,
			"the upstream must receive the native model in OpenAI format")
		assert.NotContains(t, string(up.LastBody()), "@openai/",
			"the routing prefix must never leak upstream")
	})

	t.Run("anthropic streaming request receives anthropic SSE events", func(t *testing.T) {
		up := newStreamUpstream(t, "cross-stream-token")
		apiKey, slug := setupSlugRoute(t, up, []string{"gpt-4o-mini"}, "")

		payload := anthropicChatRequest("@openai/gpt-4o-mini")
		payload["stream"] = true
		status, _, body := proxyPost(t, apiKey, "/"+slug+"/v1/messages", payload)

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(body), "content_block_delta",
			"the client must receive anthropic stream events")
		assert.Contains(t, string(body), "cross-stream-token")
		assert.NotContains(t, string(body), "[DONE]",
			"the OpenAI stream terminator must not leak into an anthropic stream")
		assert.Equal(t, 1, up.Hits())
	})

	t.Run("responses request to an openai upstream is adapted both ways", func(t *testing.T) {
		up := newJSONUpstream(t, "responses-served")
		apiKey, slug := setupSlugRoute(t, up, []string{"gpt-4o-mini"}, "")

		payload := map[string]any{"model": "@openai/gpt-4o-mini", "input": "Hello"}
		status, _, body := proxyPost(t, apiKey, "/"+slug+"/v1/responses", payload)

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(body), `"object":"response"`,
			"the client must receive a responses-format payload")
		assert.Contains(t, string(body), "responses-served")
		assert.Equal(t, 1, up.Hits())
		assert.Contains(t, string(up.LastBody()), `"messages"`,
			"the upstream must receive a chat-completions body")
		assert.Contains(t, string(up.LastBody()), `"model":"gpt-4o-mini"`)
	})

	t.Run("gemini request with the model in the path is adapted both ways", func(t *testing.T) {
		up := newJSONUpstream(t, "gemini-served")
		apiKey, slug := setupSlugRoute(t, up, []string{"gpt-4o-mini"}, "")

		payload := map[string]any{
			"contents": []map[string]any{
				{"role": "user", "parts": []map[string]any{{"text": "Hello"}}},
			},
		}
		status, _, body := proxyPost(t, apiKey,
			"/"+slug+"/v1beta/models/gpt-4o-mini:generateContent", payload)

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(body), `"candidates"`,
			"the client must receive a gemini-format response")
		assert.Contains(t, string(body), "gemini-served")
		assert.Equal(t, 1, up.Hits())
		assert.Contains(t, string(up.LastBody()), `"model":"gpt-4o-mini"`,
			"the path model must be stamped into the upstream body")
	})

	t.Run("pool alias never leaks to the upstream regardless of source format", func(t *testing.T) {
		up := newJSONUpstream(t, "pool-cross-served")
		gatewayID := CreateGateway(t, map[string]any{"name": uniqueName("norm-pool-gw")})
		backendID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be"), up.URL()))
		coID := CreateConsumer(t, gatewayID, map[string]any{
			"name": uniqueName("cons"),
			"registries": []map[string]any{
				{"id": backendID, "model_policies": map[string]any{"allowed": []string{"gpt-4o-mini"}, "default": "gpt-4o-mini"}},
			},
			"lb_config": map[string]any{
				"enabled":    true,
				"algorithm":  "round-robin",
				"pool_alias": "fast-chat",
				"members":    []map[string]any{{"registry_id": backendID}},
			},
		})
		apiKey := createAndAttachAPIKey(t, gatewayID, coID)

		status, _, body := proxyPost(t, apiKey, "/"+ConsumerSlug(t, coID)+"/v1/messages",
			anthropicChatRequest("pool:fast-chat"))

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Equal(t, 1, up.Hits())
		assert.NotContains(t, string(up.LastBody()), "pool:",
			"internal pool identifiers must never reach a provider")
		assert.Contains(t, string(up.LastBody()), `"model":"gpt-4o-mini"`,
			"the member default model must be injected natively")
	})
}

func TestProxyPaths_FixedRoutes(t *testing.T) {
	defer Track(t, "PayloadNormalization")()

	t.Run("unknown route under a valid slug returns 404", func(t *testing.T) {
		up := newJSONUpstream(t, "must-not-serve")
		apiKey, slug := setupSlugRoute(t, up, []string{"gpt-4o-mini"}, "")

		status, _, _ := proxyPost(t, apiKey, "/"+slug+"/v1/embeddings", chatRequest(false))

		assert.Equal(t, http.StatusNotFound, status)
		assert.Equal(t, 0, up.Hits())
	})

	t.Run("gemini route with an empty model segment returns 404", func(t *testing.T) {
		up := newJSONUpstream(t, "must-not-serve")
		apiKey, slug := setupSlugRoute(t, up, []string{"gpt-4o-mini"}, "")

		status, _, _ := proxyPost(t, apiKey, "/"+slug+"/v1beta/models/:generateContent", map[string]any{})

		assert.Equal(t, http.StatusNotFound, status)
		assert.Equal(t, 0, up.Hits())
	})

	t.Run("unknown consumer slug returns 404", func(t *testing.T) {
		up := newJSONUpstream(t, "must-not-serve")
		apiKey, _ := setupSlugRoute(t, up, []string{"gpt-4o-mini"}, "")

		status, _, _ := proxyPost(t, apiKey, "/zzzzzzzz/v1/chat/completions", chatRequest(false))

		assert.Equal(t, http.StatusNotFound, status)
		assert.Equal(t, 0, up.Hits())
	})
}

func TestQualifiedPin_Authorization(t *testing.T) {
	defer Track(t, "PayloadNormalization")()

	t.Run("pin to a provider not associated to the consumer returns 403", func(t *testing.T) {
		up := newJSONUpstream(t, "must-not-serve")
		apiKey, slug := setupSlugRoute(t, up, []string{"gpt-4o-mini"}, "")

		status, _, body := proxyPost(t, apiKey, "/"+slug+"/v1/messages",
			anthropicChatRequest("@anthropic/claude-sonnet-4"))

		assert.Equal(t, http.StatusForbidden, status, "body: %s", body)
		assert.Contains(t, string(body), "model_not_allowed")
		assert.Equal(t, 0, up.Hits())
	})

	t.Run("pin to a model outside the allow-list returns 403", func(t *testing.T) {
		up := newJSONUpstream(t, "must-not-serve")
		apiKey, slug := setupSlugRoute(t, up, []string{"gpt-4o-mini"}, "")

		status, _, body := proxyPost(t, apiKey, "/"+slug+"/v1/messages",
			anthropicChatRequest("@openai/gpt-4-forbidden"))

		assert.Equal(t, http.StatusForbidden, status, "body: %s", body)
		assert.Contains(t, string(body), "model_not_allowed")
		assert.Equal(t, 0, up.Hits())
	})

	t.Run("client-supplied modelId is rejected", func(t *testing.T) {
		up := newJSONUpstream(t, "must-not-serve")
		apiKey, slug := setupSlugRoute(t, up, []string{"gpt-4o-mini"}, "")

		payload := map[string]any{
			"model":    "@openai/gpt-4o-mini",
			"modelId":  "forbidden-model",
			"messages": []map[string]string{{"role": "user", "content": "Hello"}},
		}
		status, _, body := proxyPost(t, apiKey, "/"+slug+"/v1/chat/completions", payload)

		assert.Equal(t, http.StatusBadRequest, status, "body: %s", body)
		assert.Contains(t, string(body), "invalid_model")
		assert.Equal(t, 0, up.Hits(), "modelId is not a supported request field")
	})
}

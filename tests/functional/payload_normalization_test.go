//go:build functional

package functional_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("norm-gw")})
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
		assert.Contains(t, string(up.LastBody()), `"max_completion_tokens":128`,
			"openai upstreams take max_completion_tokens")
		assert.NotContains(t, string(up.LastBody()), `"max_tokens"`)
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

	// A client picks an OpenAI chat surface by the route it calls, and the
	// gateway serves that one instead of downgrading it (ENG-1281).
	t.Run("responses request to an openai upstream reaches the responses surface", func(t *testing.T) {
		up := newJSONUpstream(t, "responses-served")
		apiKey, slug := setupSlugRoute(t, up, []string{"gpt-4o-mini"}, "")

		payload := map[string]any{"model": "@openai/gpt-4o-mini", "input": "Hello"}
		status, _, body := proxyPost(t, apiKey, "/"+slug+"/v1/responses", payload)

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Equal(t, 1, up.Hits())
		assert.Equal(t, "/responses", up.LastPath(),
			"the upstream must be called on the surface the client asked for")
		assert.Contains(t, string(up.LastBody()), `"input"`,
			"the responses body must reach the upstream intact")
		assert.NotContains(t, string(up.LastBody()), `"messages"`,
			"the request must not be downgraded to chat completions")
		assert.Contains(t, string(up.LastBody()), `"model":"gpt-4o-mini"`)
		assert.NotContains(t, string(up.LastBody()), "@openai/",
			"the routing prefix must never leak upstream")
	})

	// Setting provider_options.api is the only way to reach a surface the
	// client did not ask for, and the answer still comes back in the client's
	// own dialect.
	t.Run("an explicit completions option overrides the responses route", func(t *testing.T) {
		up := newJSONUpstream(t, "responses-served")
		gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("norm-gw")})
		backend := openaiBackendPayload(uniqueName("be"), up.URL())
		backend["provider_options"] = map[string]any{"base_url": up.URL(), "api": "completions"}
		backendID := CreateRegistry(t, gatewayID, backend)
		coID := CreateConsumer(t, gatewayID, map[string]any{
			"name": uniqueName("cons"),
			"registries": []map[string]any{
				{"id": backendID, "model_policies": map[string]any{"allowed": []string{"gpt-4o-mini"}}},
			},
		})
		apiKey := createAndAttachAPIKey(t, gatewayID, coID)

		payload := map[string]any{"model": "@openai/gpt-4o-mini", "input": "Hello"}
		status, _, body := proxyPost(t, apiKey, "/"+ConsumerSlug(t, coID)+"/v1/responses", payload)

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Equal(t, 1, up.Hits())
		assert.Equal(t, "/chat/completions", up.LastPath(),
			"the explicit option must win over the inbound route")
		assert.Contains(t, string(up.LastBody()), `"messages"`,
			"the upstream must receive a chat-completions body")
		assert.Contains(t, string(body), `"object":"response"`,
			"the client must still receive a responses-format payload")
		assert.Contains(t, string(body), "responses-served")
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
		gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("norm-pool-gw")})
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

		status, _, _ := proxyPost(t, apiKey, "/"+slug+"/v2/chat/completions", chatRequest(false))

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

const functionalPNGBase64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="

func anthropicImageRequest(model string, withImage bool) map[string]any {
	content := []map[string]any{{"type": "text", "text": "What is in the image?"}}
	if withImage {
		content = append([]map[string]any{{
			"type":   "image",
			"source": map[string]any{"type": "base64", "media_type": "image/png", "data": functionalPNGBase64},
		}}, content...)
	}
	return map[string]any{
		"model":      model,
		"max_tokens": 128,
		"messages":   []map[string]any{{"role": "user", "content": content}},
	}
}

func setupAnthropicSlugRoute(t *testing.T, baseURL, model string) (string, string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("img-gw")})
	backendID := CreateRegistry(t, gatewayID, anthropicFilesBackendPayload(uniqueName("ant-be"), baseURL))
	coID := CreateConsumer(t, gatewayID, map[string]any{
		"name": uniqueName("cons"),
		"registries": []map[string]any{
			{"id": backendID, "model_policies": map[string]any{"allowed": []string{model}}},
		},
	})
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	return apiKey, ConsumerSlug(t, coID)
}

func TestPayloadNormalization_ImageContent(t *testing.T) {
	defer Track(t, "PayloadNormalization")()

	t.Run("anthropic image block reaches an openai upstream as image_url", func(t *testing.T) {
		up := newJSONUpstream(t, "image-served")
		apiKey, slug := setupSlugRoute(t, up, []string{"gpt-4o-mini"}, "")

		status, _, body := proxyPost(t, apiKey, "/"+slug+"/v1/messages",
			anthropicImageRequest("@openai/gpt-4o-mini", true))

		require.Equal(t, http.StatusOK, status, "body: %s", body)
		require.Equal(t, 1, up.Hits())
		var sent struct {
			Messages []struct {
				Content json.RawMessage `json:"content"`
			} `json:"messages"`
		}
		require.NoError(t, json.Unmarshal(up.LastBody(), &sent))
		require.Len(t, sent.Messages, 1)
		assert.JSONEq(t,
			`[{"type":"image_url","image_url":{"url":"data:image/png;base64,`+functionalPNGBase64+`"}},{"type":"text","text":"What is in the image?"}]`,
			string(sent.Messages[0].Content))
	})

	t.Run("text-only request still sends string content", func(t *testing.T) {
		up := newJSONUpstream(t, "text-served")
		apiKey, slug := setupSlugRoute(t, up, []string{"gpt-4o-mini"}, "")

		status, _, body := proxyPost(t, apiKey, "/"+slug+"/v1/messages",
			anthropicImageRequest("@openai/gpt-4o-mini", false))

		require.Equal(t, http.StatusOK, status, "body: %s", body)
		require.Equal(t, 1, up.Hits())
		assert.Contains(t, string(up.LastBody()), `"content":"What is in the image?"`)
		assert.NotContains(t, string(up.LastBody()), "image_url")
	})

	t.Run("ftp image to an anthropic backend is a 400 without an upstream call", func(t *testing.T) {
		up := newJSONUpstream(t, "must-not-serve")
		apiKey, slug := setupAnthropicSlugRoute(t, up.URL()+"/v1", "claude-sonnet-4")

		payload := map[string]any{
			"model": "claude-sonnet-4",
			"messages": []map[string]any{{"role": "user", "content": []map[string]any{
				{"type": "text", "text": "What is in the image?"},
				{"type": "image_url", "image_url": map[string]any{"url": "ftp://example.com/private.png"}},
			}}},
		}
		status, _, body := proxyPost(t, apiKey, "/"+slug+"/v1/chat/completions", payload)

		assert.Equal(t, http.StatusBadRequest, status, "body: %s", body)
		assert.Contains(t, string(body), `"invalid_request"`)
		assert.Contains(t, string(body), "unsupported content")
		for _, leak := range []string{"private.png", "adapter", "anthropic", "bedrock"} {
			assert.NotContains(t, string(body), leak)
		}
		assert.Equal(t, 0, up.Hits())
	})
}

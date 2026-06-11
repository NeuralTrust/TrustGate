//go:build functional

package functional_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func proxyPostWithHeaders(t *testing.T, apiKey, path string, body any, headers map[string]string) (int, http.Header, []byte) {
	t.Helper()
	buf, err := json.Marshal(body)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, ProxyURL+path, bytes.NewReader(buf))
	require.NoError(t, err)
	host, ok := proxyHosts.Load(apiKey)
	require.True(t, ok, "proxy host missing for api key")
	req.Host = host.(string)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(proxyAPIKeyHeader, apiKey)
	for name, value := range headers {
		req.Header.Set(name, value)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, resp.Header, raw
}

func anthropicChatRequest(model string) map[string]any {
	return map[string]any{
		"model":      model,
		"max_tokens": 128,
		"messages":   []map[string]string{{"role": "user", "content": "Hello"}},
	}
}

func TestPayloadNormalization_CrossFormat(t *testing.T) {
	defer Track(t, "PayloadNormalization")()

	t.Run("anthropic-format request with qualified intent reaches an openai upstream natively", func(t *testing.T) {
		up := newJSONUpstream(t, "cross-format-served")
		apiKey, path := setupIntentRoute(t, up, []string{"gpt-4o-mini"}, "")

		status, _, body := proxyPostWithHeaders(t, apiKey, path,
			anthropicChatRequest("openai/gpt-4o-mini"),
			map[string]string{"X-Provider": "anthropic"})

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(body), "cross-format-served")
		assert.Equal(t, 1, up.Hits())
		assert.Contains(t, string(up.LastBody()), `"model":"gpt-4o-mini"`,
			"the upstream must receive the native model in OpenAI format")
		assert.NotContains(t, string(up.LastBody()), "openai/",
			"the routing prefix must never leak upstream")
	})

	t.Run("pool alias never leaks to the upstream regardless of source format", func(t *testing.T) {
		up := newJSONUpstream(t, "pool-cross-served")
		gatewayID := CreateGateway(t, map[string]any{"name": uniqueName("norm-gw")})
		backendID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be"), up.URL()))
		path := "/v1/" + uniqueName("route")
		coID := CreateConsumer(t, gatewayID, map[string]any{
			"name": uniqueName("cons"),
			"path": path,
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

		status, _, body := proxyPostWithHeaders(t, apiKey, path,
			anthropicChatRequest("pool:fast-chat"),
			map[string]string{"X-Provider": "anthropic"})

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Equal(t, 1, up.Hits())
		assert.NotContains(t, string(up.LastBody()), "pool:",
			"internal pool identifiers must never reach a provider")
		assert.Contains(t, string(up.LastBody()), `"model":"gpt-4o-mini"`,
			"the member default model must be injected natively")
	})
}

func TestXProvider_SourceFormatOnly(t *testing.T) {
	defer Track(t, "PayloadNormalization")()

	t.Run("x-provider never grants access to an unauthorized upstream provider", func(t *testing.T) {
		up := newJSONUpstream(t, "must-not-serve")
		apiKey, path := setupIntentRoute(t, up, []string{"gpt-4o-mini"}, "")

		status, _, body := proxyPostWithHeaders(t, apiKey, path,
			anthropicChatRequest("anthropic/claude-sonnet-4"),
			map[string]string{"X-Provider": "anthropic"})

		assert.Equal(t, http.StatusForbidden, status, "body: %s", body)
		assert.Contains(t, string(body), "model_not_allowed")
		assert.Equal(t, 0, up.Hits(), "payload intent, not X-Provider, drives upstream authorization")
	})

	t.Run("x-provider does not bypass the model allow-list", func(t *testing.T) {
		up := newJSONUpstream(t, "must-not-serve")
		apiKey, path := setupIntentRoute(t, up, []string{"gpt-4o-mini"}, "")

		status, _, body := proxyPostWithHeaders(t, apiKey, path,
			anthropicChatRequest("openai/gpt-4-forbidden"),
			map[string]string{"X-Provider": "anthropic"})

		assert.Equal(t, http.StatusForbidden, status, "body: %s", body)
		assert.Contains(t, string(body), "model_not_allowed")
		assert.Equal(t, 0, up.Hits())
	})
}

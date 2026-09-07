//go:build functional

package functional_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func embeddingsRequest(model string) map[string]any {
	return map[string]any{
		"model": model,
		"input": []string{"hello"},
	}
}

func newEmbeddingsUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.record(r)
		w.Header().Set("Content-Type", "application/json")
		if !strings.Contains(r.URL.Path, "embeddings") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprintf(w, `{"error":{"message":"unexpected path %s"}}`, r.URL.Path)
			return
		}
		_, _ = io.WriteString(w, `{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2,0.3]}],"model":"text-embedding-3-small","usage":{"prompt_tokens":1,"total_tokens":1}}`)
	}))
	t.Cleanup(u.server.Close)
	return u
}

func azureBackendPayload(name, endpoint string) map[string]any {
	return map[string]any{
		"name":     name,
		"provider": "azure",
		"weight":   1,
		"auth": map[string]any{
			"type": "azure",
			"azure": map[string]any{
				"endpoint": endpoint,
				"api_key":  "az-test",
			},
		},
	}
}

func anthropicBackendPayload(name string) map[string]any {
	return map[string]any{
		"name":     name,
		"provider": "anthropic",
		"weight":   1,
		"auth": map[string]any{
			"type":    "api_key",
			"api_key": map[string]any{"api_key": "sk-ant-test"},
		},
	}
}

func setupEmbeddingsRoute(t *testing.T, payload map[string]any) (string, string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("emb-gw")})
	registryID := CreateRegistry(t, gatewayID, payload)
	coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("emb-cons")})
	AttachRegistry(t, gatewayID, coID, registryID)
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	return apiKey, "/" + ConsumerSlug(t, coID) + "/v1/embeddings"
}

func assertOpenAIEmbeddingsResponse(t *testing.T, body []byte) {
	t.Helper()
	var resp map[string]any
	require.NoError(t, json.Unmarshal(body, &resp))
	data, ok := resp["data"].([]any)
	require.True(t, ok, "body: %s", body)
	assert.Len(t, data, 1)
}

func TestOpenAIProvider_Embeddings(t *testing.T) {
	defer Track(t, "EmbeddingsProvider")()

	up := newEmbeddingsUpstream(t)
	apiKey, path := setupEmbeddingsRoute(t, openaiBackendPayload(uniqueName("oai-emb"), up.URL()+"/v1"))

	status, headers, body := proxyPost(t, apiKey, path, embeddingsRequest("text-embedding-3-small"))

	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "openai", headers.Get("X-Selected-Provider"))
	assert.Equal(t, "/v1/embeddings", up.LastPath())
	assertOpenAIEmbeddingsResponse(t, body)
	assert.Equal(t, 1, up.Hits())
}

func TestAzureProvider_Embeddings(t *testing.T) {
	defer Track(t, "EmbeddingsProvider")()

	up := newEmbeddingsUpstream(t)
	apiKey, path := setupEmbeddingsRoute(t, azureBackendPayload(uniqueName("az-emb"), up.URL()))

	status, headers, body := proxyPost(t, apiKey, path, embeddingsRequest("text-embedding-3-small"))

	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "azure", headers.Get("X-Selected-Provider"))
	assert.Equal(t, "/openai/deployments/text-embedding-3-small/embeddings", up.LastPath())
	assertOpenAIEmbeddingsResponse(t, body)
	assert.Equal(t, 1, up.Hits())
}

func mistralBackendPayload(name, baseURL string) map[string]any {
	return map[string]any{
		"name":             name,
		"provider":         "mistral",
		"weight":           1,
		"provider_options": map[string]any{"base_url": baseURL},
		"auth": map[string]any{
			"type":    "api_key",
			"api_key": map[string]any{"api_key": "mistral-test"},
		},
	}
}

func TestMistralProvider_Embeddings(t *testing.T) {
	defer Track(t, "EmbeddingsProvider")()

	up := newEmbeddingsUpstream(t)
	apiKey, path := setupEmbeddingsRoute(t, mistralBackendPayload(uniqueName("mistral-emb"), up.URL()+"/v1"))

	status, headers, body := proxyPost(t, apiKey, path, embeddingsRequest("mistral-embed"))

	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "mistral", headers.Get("X-Selected-Provider"))
	assert.Equal(t, "/v1/embeddings", up.LastPath())
	assertOpenAIEmbeddingsResponse(t, body)
	assert.Equal(t, 1, up.Hits())
}

func TestOpenAICompatibleProvider_Embeddings(t *testing.T) {
	defer Track(t, "EmbeddingsProvider")()

	up := newEmbeddingsUpstream(t)
	apiKey, path := setupEmbeddingsRoute(t, openaiCompatibleBackendPayload(uniqueName("compat-emb"), up.URL()+"/v1"))

	status, headers, body := proxyPost(t, apiKey, path, embeddingsRequest("nomic-embed-text"))

	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "openai_compatible", headers.Get("X-Selected-Provider"))
	assert.Equal(t, "/v1/embeddings", up.LastPath())
	assertOpenAIEmbeddingsResponse(t, body)
	assert.Equal(t, 1, up.Hits())
}

func TestEmbeddings_FiltersIncapableProviderFromPool(t *testing.T) {
	defer Track(t, "EmbeddingsProvider")()

	capable := newEmbeddingsUpstream(t)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("emb-mix-gw")})
	openaiID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("oai-emb"), capable.URL()+"/v1"))
	anthropicID := CreateRegistry(t, gatewayID, anthropicBackendPayload(uniqueName("ant-chat")))
	coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("emb-mix")})
	AttachRegistry(t, gatewayID, coID, openaiID)
	AttachRegistry(t, gatewayID, coID, anthropicID)
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	path := "/" + ConsumerSlug(t, coID) + "/v1/embeddings"

	status, headers, body := proxyPost(t, apiKey, path, embeddingsRequest("text-embedding-3-small"))

	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "openai", headers.Get("X-Selected-Provider"))
	assert.Equal(t, 1, capable.Hits())
	assertOpenAIEmbeddingsResponse(t, body)
}

func vertexBackendPayload(name, baseURL string) map[string]any {
	return map[string]any{
		"name":     name,
		"provider": "vertex",
		"weight":   1,
		"provider_options": map[string]any{
			"project":  "test-proj",
			"location": "us-central1",
			"base_url": baseURL,
		},
		"auth": map[string]any{
			"type":    "api_key",
			"api_key": map[string]any{"api_key": "vertex-token"},
		},
	}
}

func newVertexEmbeddingsUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.record(r)
		w.Header().Set("Content-Type", "application/json")
		if !strings.Contains(r.URL.Path, "embedContent") && !strings.Contains(r.URL.Path, "batchEmbedContents") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprintf(w, `{"error":{"message":"unexpected path %s"}}`, r.URL.Path)
			return
		}
		_, _ = io.WriteString(w, `{"embedding":{"values":[0.1,0.2,0.3]}}`)
	}))
	t.Cleanup(u.server.Close)
	return u
}

func TestVertexProvider_Embeddings(t *testing.T) {
	defer Track(t, "EmbeddingsProvider")()

	up := newVertexEmbeddingsUpstream(t)
	apiKey, path := setupEmbeddingsRoute(t, vertexBackendPayload(uniqueName("vertex-emb"), up.URL()))

	status, headers, body := proxyPost(t, apiKey, path, embeddingsRequest("text-embedding-004"))

	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "vertex", headers.Get("X-Selected-Provider"))
	assert.Contains(t, up.LastPath(), "text-embedding-004:embedContent")
	assertOpenAIEmbeddingsResponse(t, body)
	assert.Equal(t, 1, up.Hits())
}

func TestEmbeddings_PinnedIncapableProviderIsTerminal(t *testing.T) {
	defer Track(t, "EmbeddingsProvider")()

	capable := newEmbeddingsUpstream(t)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("emb-pin-gw")})
	openaiID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("oai-emb"), capable.URL()+"/v1"))
	anthropicID := CreateRegistry(t, gatewayID, anthropicBackendPayload(uniqueName("ant-chat")))
	coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("emb-pin")})
	AttachRegistry(t, gatewayID, coID, openaiID)
	AttachRegistry(t, gatewayID, coID, anthropicID)
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	path := "/" + ConsumerSlug(t, coID) + "/v1/embeddings"

	status, _, body := proxyPost(t, apiKey, path, embeddingsRequest("@anthropic/claude-4"))

	assert.Equal(t, http.StatusBadRequest, status, "body: %s", body)
	assert.Equal(t, 0, capable.Hits(), "pinned incapable provider must not fail over")
	assert.Contains(t, string(body), "does not support this capability")
}

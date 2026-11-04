//go:build functional

package functional_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupNativeEmbeddingsRoute(t *testing.T, payload map[string]any, policies ...map[string]any) (apiKey, slug string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("native-emb-gw")})
	registryID := CreateRegistry(t, gatewayID, payload)
	consumerID := CreateConsumerWithRegistries(t, gatewayID, uniqueName("native-emb"), registryID)
	for _, entry := range policies {
		policy := map[string]any{"name": uniqueName("pol")}
		for k, v := range entry {
			policy[k] = v
		}
		AttachPolicy(t, gatewayID, consumerID, CreatePolicy(t, gatewayID, policy))
	}
	return createAndAttachAPIKey(t, gatewayID, consumerID), ConsumerSlug(t, consumerID)
}

func geminiEmbedBody(texts ...string) map[string]any {
	requests := make([]map[string]any, 0, len(texts))
	for _, text := range texts {
		requests = append(requests, map[string]any{
			"model":   "models/gemini-embedding-001",
			"content": map[string]any{"parts": []map[string]any{{"text": text}}},
		})
	}
	return map[string]any{"requests": requests}
}

func TestNativeEmbeddings_GeminiPathsAgainstVertex(t *testing.T) {
	defer Track(t, "NativeEmbeddings")()
	up := newVertexEmbeddingsUpstream(t)
	apiKey, slug := setupNativeEmbeddingsRoute(t, vertexBackendPayload(uniqueName("vertex-native-emb"), up.URL()))

	t.Run("embedContent answers a single embedding", func(t *testing.T) {
		status, headers, body := proxyPost(t, apiKey, "/"+slug+"/v1beta/models/gemini-embedding-001:embedContent", map[string]any{
			"content":  map[string]any{"parts": []map[string]any{{"text": "hello"}}},
			"taskType": "RETRIEVAL_QUERY",
		})
		require.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Equal(t, "vertex", headers.Get("X-Selected-Provider"))
		assert.JSONEq(t, `{"embedding":{"values":[0.1,0.2,0.3]}}`, string(body))
		assert.Contains(t, up.LastPath(), "gemini-embedding-001:embedContent")
	})

	t.Run("batchEmbedContents with one request stays a batch", func(t *testing.T) {
		status, _, body := proxyPost(t, apiKey, "/"+slug+"/v1beta/models/gemini-embedding-001:batchEmbedContents", geminiEmbedBody("hello"))
		require.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.JSONEq(t, `{"embeddings":[{"values":[0.1,0.2,0.3]}]}`, string(body))
	})

	t.Run("the Vertex path takes any project and region and uses the registry URL", func(t *testing.T) {
		status, _, body := proxyPost(t, apiKey,
			"/"+slug+"/v1/projects/x/locations/y/publishers/google/models/gemini-embedding-001:embedContent",
			map[string]any{"content": map[string]any{"parts": []map[string]any{{"text": "hello"}}}})
		require.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.JSONEq(t, `{"embedding":{"values":[0.1,0.2,0.3]}}`, string(body))
		assert.NotContains(t, up.LastPath(), "/projects/x/")
		assert.NotContains(t, up.LastPath(), "/locations/y/")
		assert.Contains(t, up.LastPath(), "gemini-embedding-001:embedContent")
	})

	t.Run("countTokens is not served", func(t *testing.T) {
		before := up.Hits()
		for _, path := range []string{
			"/" + slug + "/v1beta/models/gemini-embedding-001:countTokens",
			"/" + slug + "/v1/projects/x/locations/y/publishers/google/models/gemini-embedding-001:countTokens",
		} {
			status, _, body := proxyPost(t, apiKey, path, geminiEmbedBody("hello"))
			assert.Equal(t, http.StatusNotFound, status, "%s body: %s", path, body)
		}
		assert.Equal(t, before, up.Hits())
	})

	t.Run("a mixed batch is a Gemini 400", func(t *testing.T) {
		before := up.Hits()
		status, _, body := proxyPost(t, apiKey, "/"+slug+"/v1beta/models/gemini-embedding-001:batchEmbedContents", map[string]any{
			"requests": []map[string]any{
				{"content": map[string]any{"parts": []map[string]any{{"text": "a"}}}, "taskType": "CLUSTERING"},
				{"content": map[string]any{"parts": []map[string]any{{"text": "b"}}}},
			},
		})
		require.Equal(t, http.StatusBadRequest, status, "body: %s", body)
		assertGeminiError(t, body, "INVALID_ARGUMENT")
		assert.Equal(t, before, up.Hits())
	})
}

func TestNativeEmbeddings_GeminiPathAgainstOpenAI(t *testing.T) {
	defer Track(t, "NativeEmbeddings")()
	up := newEmbeddingsUpstream(t)
	apiKey, slug := setupNativeEmbeddingsRoute(t, openaiBackendPayload(uniqueName("oai-native-emb"), up.URL()+"/v1"))

	status, headers, body := proxyPost(t, apiKey, "/"+slug+"/v1beta/models/text-embedding-3-small:batchEmbedContents", map[string]any{
		"requests": []map[string]any{{
			"content":              map[string]any{"parts": []map[string]any{{"text": "hello"}}},
			"outputDimensionality": 3,
		}},
	})

	require.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "openai", headers.Get("X-Selected-Provider"))
	assert.JSONEq(t, `{"embeddings":[{"values":[0.1,0.2,0.3]}]}`, string(body))
	var sent map[string]any
	require.NoError(t, json.Unmarshal(up.LastBody(), &sent))
	assert.Equal(t, "text-embedding-3-small", sent["model"])
	assert.EqualValues(t, 3, sent["dimensions"])
}

func TestNativeEmbeddings_ModelPolicyAppliesToThePathModel(t *testing.T) {
	defer Track(t, "NativeEmbeddings")()
	up := newVertexEmbeddingsUpstream(t)
	apiKey, slug := setupNativeEmbeddingsRoute(t, vertexBackendPayload(uniqueName("vertex-native-emb"), up.URL()),
		policyPlugin("model_allowlist", map[string]any{
			"allowed_models":         []string{"gemini-embedding-001"},
			"behavior_on_disallowed": "reject",
		}),
	)

	status, _, body := proxyPost(t, apiKey, "/"+slug+"/v1beta/models/gemini-embedding-001:embedContent",
		map[string]any{"content": map[string]any{"parts": []map[string]any{{"text": "hello"}}}})
	require.Equal(t, http.StatusOK, status, "body: %s", body)

	before := up.Hits()
	status, _, body = proxyPost(t, apiKey, "/"+slug+"/v1beta/models/text-embedding-005:embedContent",
		map[string]any{"model": "models/gemini-embedding-001", "content": map[string]any{"parts": []map[string]any{{"text": "hello"}}}})
	require.Equal(t, http.StatusForbidden, status, "body: %s", body)
	assert.Contains(t, string(body), `"model":"text-embedding-005"`, "the path model is the one checked, not the body's")
	assert.Equal(t, before, up.Hits())
}

func TestNativeEmbeddings_OpenAIEmbeddingsUnchanged(t *testing.T) {
	defer Track(t, "NativeEmbeddings")()
	up := newVertexEmbeddingsUpstream(t)
	apiKey, path := setupEmbeddingsRoute(t, vertexBackendPayload(uniqueName("vertex-emb"), up.URL()))

	status, _, body := proxyPost(t, apiKey, path, embeddingsRequest("text-embedding-004"))

	require.Equal(t, http.StatusOK, status, "body: %s", body)
	assertOpenAIEmbeddingsResponse(t, body)
	assert.NotContains(t, string(up.LastBody()), "outputDimensionality")
	assert.NotContains(t, string(up.LastBody()), "taskType")
}

func assertGeminiError(t *testing.T, body []byte, wantStatus string) {
	t.Helper()
	var got struct {
		Error struct {
			Status string `json:"status"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(body, &got), "body: %s", body)
	assert.Equal(t, wantStatus, got.Error.Status, "body: %s", body)
}

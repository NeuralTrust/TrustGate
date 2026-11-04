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

const vertexPredictUpstreamBody = `{"predictions":[{"embeddings":{"values":[0.1,0.2],"statistics":{"token_count":2,"truncated":false}}}]}`

func newVertexPredictUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.record(r)
		w.Header().Set("Content-Type", "application/json")
		if !strings.HasSuffix(r.URL.Path, ":predict") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprintf(w, `{"error":{"message":"unexpected path %s"}}`, r.URL.Path)
			return
		}
		_, _ = io.WriteString(w, vertexPredictUpstreamBody)
	}))
	t.Cleanup(u.server.Close)
	return u
}

func setupVertexPredictRoute(t *testing.T, registryPayload map[string]any, policies ...map[string]any) (apiKey, slug string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("vx-predict-gw")})
	registryID := CreateRegistry(t, gatewayID, registryPayload)
	consumerID := CreateConsumerWithRegistries(t, gatewayID, uniqueName("cons"), registryID)
	for _, entry := range policies {
		payload := map[string]any{"name": uniqueName("pol")}
		for k, v := range entry {
			payload[k] = v
		}
		AttachPolicy(t, gatewayID, consumerID, CreatePolicy(t, gatewayID, payload))
	}
	return createAndAttachAPIKey(t, gatewayID, consumerID), ConsumerSlug(t, consumerID)
}

func vertexPredictPath(slug, model string) string {
	return "/" + slug + "/v1beta1/projects/p/locations/global/publishers/google/models/" + model + ":predict"
}

func TestVertexPredictEmbeddings_VertexRegistry(t *testing.T) {
	defer Track(t, "VertexPredictEmbeddings")()

	up := newVertexPredictUpstream(t)
	apiKey, slug := setupVertexPredictRoute(t,
		vertexBackendPayload(uniqueName("vertex-predict"), up.URL()),
		policyPlugin("model_allowlist", map[string]any{
			"allowed_models":         []string{"gemini-embedding-*"},
			"behavior_on_disallowed": "reject",
		}),
	)

	t.Run("an embedding model is forwarded to :predict without the stamped model", func(t *testing.T) {
		request := map[string]any{
			"instances":  []map[string]any{{"content": "hello", "task_type": "RETRIEVAL_QUERY"}},
			"parameters": map[string]any{"outputDimensionality": 2},
		}
		status, headers, body := proxyPost(t, apiKey, vertexPredictPath(slug, "gemini-embedding-001"), request)

		require.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Equal(t, "vertex", headers.Get("X-Selected-Provider"))
		assert.True(t, strings.HasSuffix(up.LastPath(), "/gemini-embedding-001:predict"), up.LastPath())
		assert.JSONEq(t,
			`{"instances":[{"content":"hello","task_type":"RETRIEVAL_QUERY"}],"parameters":{"outputDimensionality":2}}`,
			string(up.LastBody()))
		assert.JSONEq(t, vertexPredictUpstreamBody, string(body))
	})

	t.Run("a model outside the allowlist is refused from the path", func(t *testing.T) {
		before := up.Hits()
		status, _, body := proxyPost(t, apiKey, vertexPredictPath(slug, "text-embedding-005"),
			map[string]any{"instances": []map[string]any{{"content": "hello"}}})

		require.Equal(t, http.StatusForbidden, status, "body: %s", body)
		var env struct {
			Error struct {
				Type  string `json:"type"`
				Model string `json:"model"`
			} `json:"error"`
		}
		require.NoError(t, json.Unmarshal(body, &env), "body: %s", body)
		assert.Equal(t, "model_not_allowed", env.Error.Type, "body: %s", body)
		assert.Equal(t, "text-embedding-005", env.Error.Model, "body: %s", body)
		assert.Equal(t, before, up.Hits())
	})

	t.Run("a chat model on :predict is not a route", func(t *testing.T) {
		before := up.Hits()
		status, _, body := proxyPost(t, apiKey, vertexPredictPath(slug, "gemini-2.5-flash"),
			map[string]any{"instances": []map[string]any{{"content": "hello"}}})

		assert.Equal(t, http.StatusNotFound, status, "body: %s", body)
		assert.Equal(t, before, up.Hits())
	})
}

func TestVertexPredictEmbeddings_OpenAIRegistry(t *testing.T) {
	defer Track(t, "VertexPredictEmbeddings")()

	up := newEmbeddingsUpstream(t)
	apiKey, slug := setupVertexPredictRoute(t, openaiBackendPayload(uniqueName("openai-emb"), up.URL()))

	t.Run("instances are translated to OpenAI and predictions come back", func(t *testing.T) {
		request := map[string]any{
			"instances":  []map[string]any{{"content": "hello"}},
			"parameters": map[string]any{"outputDimensionality": 3},
		}
		status, _, body := proxyPost(t, apiKey, vertexPredictPath(slug, "text-embedding-3-small"), request)

		require.Equal(t, http.StatusOK, status, "body: %s", body)
		var sent map[string]any
		require.NoError(t, json.Unmarshal(up.LastBody(), &sent))
		assert.Equal(t, "text-embedding-3-small", sent["model"])
		assert.Equal(t, "hello", sent["input"])
		assert.EqualValues(t, 3, sent["dimensions"])
		assert.JSONEq(t, `{"predictions":[{"embeddings":{"values":[0.1,0.2,0.3]}}]}`, string(body))
	})

	t.Run("a body without text is rejected before the upstream", func(t *testing.T) {
		before := up.Hits()
		status, _, body := proxyPost(t, apiKey, vertexPredictPath(slug, "text-embedding-3-small"),
			map[string]any{"instances": []map[string]any{}})

		require.Equal(t, http.StatusBadRequest, status, "body: %s", body)
		var env struct {
			Error struct {
				Status string `json:"status"`
			} `json:"error"`
		}
		require.NoError(t, json.Unmarshal(body, &env), "body: %s", body)
		assert.Equal(t, "INVALID_ARGUMENT", env.Error.Status, "body: %s", body)
		assert.Equal(t, before, up.Hits())
	})
}

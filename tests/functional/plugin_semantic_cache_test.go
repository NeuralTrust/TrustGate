//go:build functional

package functional_test

import (
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPluginE2E_SemanticCache exercises the semantic cache end to end. It needs a
// real embedding provider (OPENAI_API_KEY) and a Redis Stack (RediSearch)
// backing the vector store, so it is skipped when the key is absent, mirroring
// the TrustGate-EE functional test.
func TestPluginE2E_SemanticCache(t *testing.T) {
	defer Track(t, "PluginSemanticCache")()

	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		t.Skip("OPENAI_API_KEY not set, skipping semantic cache functional test")
	}

	settings := map[string]any{
		"similarity_threshold": 0.85,
		"ttl":                  "10m",
		"embedding": map[string]any{
			"provider": "openai",
			"model":    "text-embedding-ada-002",
			"api_key":  apiKey,
		},
	}

	up := newJSONUpstream(t, "semantic-cache-answer")
	gatewayID, path := setupPolicyRoute(t, up,
		policyPlugin("semantic_cache", "pre_request", settings),
		policyPlugin("semantic_cache", "post_response", settings),
	)

	ask := func(content string) map[string]any {
		return map[string]any{
			"model":    "gpt-4o-mini",
			"messages": []map[string]string{{"role": "user", "content": content}},
		}
	}

	var firstBody []byte

	t.Run("first request misses and is stored", func(t *testing.T) {
		status, headers, body := proxyRequest(t, http.MethodPost, gatewayID, path, nil,
			mustJSON(t, ask("What is the capital of France?")),
		)
		require.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Empty(t, headers.Get("X-Cache-Status"), "first request must be a miss")
		assert.NotEmpty(t, body)
		firstBody = body
	})

	t.Run("identical request hits the cache", func(t *testing.T) {
		// PostResponse stores asynchronously; give it a moment to land.
		time.Sleep(2 * time.Second)
		hitsBefore := up.Hits()

		status, headers, body := proxyRequest(t, http.MethodPost, gatewayID, path, nil,
			mustJSON(t, ask("What is the capital of France?")),
		)
		require.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Equal(t, "HIT", headers.Get("X-Cache-Status"))
		assert.NotEmpty(t, headers.Get("X-Cache-Similarity"))
		assert.Equal(t, firstBody, body, "a cache hit must replay the stored response")
		assert.Equal(t, hitsBefore, up.Hits(), "a cache hit must not reach the upstream")
	})

	t.Run("semantically similar request hits the cache", func(t *testing.T) {
		status, headers, body := proxyRequest(t, http.MethodPost, gatewayID, path, nil,
			mustJSON(t, ask("What's the capital city of France?")),
		)
		require.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Equal(t, "HIT", headers.Get("X-Cache-Status"))
		assert.Equal(t, firstBody, body)
	})

	t.Run("dissimilar request misses", func(t *testing.T) {
		status, headers, body := proxyRequest(t, http.MethodPost, gatewayID, path, nil,
			mustJSON(t, ask("How do you implement a binary search tree in Rust?")),
		)
		require.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Empty(t, headers.Get("X-Cache-Status"), "a dissimilar request must not hit")
	})

	t.Run("Cache-Control no-cache bypasses the cache", func(t *testing.T) {
		status, headers, body := proxyRequest(t, http.MethodPost, gatewayID, path,
			map[string]string{"Cache-Control": "no-cache"},
			mustJSON(t, ask("What is the capital of France?")),
		)
		require.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Empty(t, headers.Get("X-Cache-Status"), "no-cache must bypass the cache")
	})
}

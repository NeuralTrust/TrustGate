//go:build functional

package functional_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func cohereBackendPayload(name, baseURL string) map[string]any {
	return map[string]any{
		"name":             name,
		"provider":         "cohere",
		"weight":           1,
		"provider_options": map[string]any{"base_url": baseURL},
		"auth": map[string]any{
			"type":    "api_key",
			"api_key": map[string]any{"api_key": "cohere-test"},
		},
	}
}

func newCohereUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.record(r)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v2/chat":
			_, _ = io.WriteString(w, `{"id":"chat-1","finish_reason":"COMPLETE","message":{"role":"assistant","content":[{"type":"text","text":"cohere-reply"}]}}`)
		case "/v2/embed":
			_, _ = io.WriteString(w, `{"embeddings":[[0.1,0.2,0.3]]}`)
		case "/v2/rerank":
			_, _ = io.WriteString(w, `{"results":[{"index":0,"relevance_score":0.95}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprintf(w, `{"message":"unknown path %s"}`, r.URL.Path)
		}
	}))
	t.Cleanup(u.server.Close)
	return u
}

func setupCohereRoute(t *testing.T, up *fakeUpstream) (string, string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("cohere-gw")})
	registryID := CreateRegistry(t, gatewayID, cohereBackendPayload(uniqueName("cohere-be"), up.URL()))
	coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("cohere-cons")})
	AttachRegistry(t, gatewayID, coID, registryID)
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	return apiKey, ConsumerSlug(t, coID)
}

func TestCohereProvider_NativeChat(t *testing.T) {
	defer Track(t, "CohereProvider")()

	up := newCohereUpstream(t)
	apiKey, slug := setupCohereRoute(t, up)

	status, headers, body := proxyPost(t, apiKey, "/"+slug+"/v2/chat", map[string]any{
		"model":    "command-r-plus",
		"messages": []map[string]string{{"role": "user", "content": "Hello"}},
	})

	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "cohere", headers.Get("X-Selected-Provider"))
	assert.Contains(t, string(body), "cohere-reply")
	assert.Equal(t, 1, up.Hits())
}

func TestCohereProvider_EmbeddingsCrossFormat(t *testing.T) {
	defer Track(t, "CohereProvider")()

	up := newCohereUpstream(t)
	apiKey, slug := setupCohereRoute(t, up)

	status, headers, body := proxyPost(t, apiKey, "/"+slug+"/v1/embeddings", map[string]any{
		"model": "embed-english-v3.0",
		"input": []string{"hello"},
	})

	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "cohere", headers.Get("X-Selected-Provider"))

	var resp map[string]any
	require.NoError(t, json.Unmarshal(body, &resp))
	data := resp["data"].([]any)
	assert.Len(t, data, 1)
	assert.Equal(t, 1, up.Hits())
}

func TestCohereProvider_Rerank(t *testing.T) {
	defer Track(t, "CohereProvider")()

	up := newCohereUpstream(t)
	apiKey, slug := setupCohereRoute(t, up)

	status, headers, body := proxyPost(t, apiKey, "/"+slug+"/v1/rerank", map[string]any{
		"model":     "rerank-english-v3.0",
		"query":     "capital of France",
		"documents": []string{"Paris is the capital of France."},
	})

	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "cohere", headers.Get("X-Selected-Provider"))

	var resp map[string]any
	require.NoError(t, json.Unmarshal(body, &resp))
	results := resp["results"].([]any)
	assert.Len(t, results, 1)
	assert.Equal(t, 1, up.Hits())
}

//go:build functional

package functional_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func vertexPassthroughPayload(name, baseURL string) map[string]any {
	return map[string]any{
		"name":     name,
		"provider": "vertex",
		"weight":   1,
		"provider_options": map[string]any{
			"project":  "test-proj",
			"location": "us-central1",
			"base_url": baseURL,
		},
		"auth": map[string]any{"type": "passthrough"},
	}
}

// throwawayServiceAccountKey is a well-formed key for an account that does not
// exist, so Google's token endpoint refuses it.
func throwawayServiceAccountKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	raw, err := json.Marshal(map[string]string{
		"type":           "service_account",
		"project_id":     "test-proj",
		"private_key_id": "0000000000000000000000000000000000000000",
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email":   "nobody@test-proj.iam.gserviceaccount.com",
		"token_uri":      "https://oauth2.googleapis.com/token",
	})
	require.NoError(t, err)
	return string(raw)
}

func proxyPostPassthrough(t *testing.T, apiKey, path, authorization string, body any) (int, []byte) {
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
	req.Header.Set("Authorization", authorization)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, raw
}

func TestVertexPassthrough_ServiceAccountKey(t *testing.T) {
	defer Track(t, "VertexPassthrough")()

	// Only the embeddings client honours base_url, so the fake upstream can
	// observe what reaches the provider on that route alone.
	up := newVertexEmbeddingsUpstream(t)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("vtx-pt-gw")})
	registryID := CreateRegistry(t, gatewayID, vertexPassthroughPayload(uniqueName("vtx-pt"), up.URL()))
	coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("vtx-pt-cons")})
	AttachRegistry(t, gatewayID, coID, registryID)
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	slug := ConsumerSlug(t, coID)

	key := throwawayServiceAccountKey(t)
	keys := map[string]string{
		"raw":    "Bearer " + key,
		"base64": "Bearer " + base64.StdEncoding.EncodeToString([]byte(key)),
	}
	embeddingsPath := "/" + slug + "/v1/embeddings"

	t.Run("access token is forwarded unchanged", func(t *testing.T) {
		status, body := proxyPostPassthrough(t, apiKey, embeddingsPath, "Bearer ya29.caller-token", embeddingsRequest("text-embedding-004"))

		require.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Equal(t, "Bearer ya29.caller-token", up.LastAuth())
	})

	for encoding, authorization := range keys {
		t.Run(encoding+" key never reaches the provider", func(t *testing.T) {
			hits := up.Hits()

			status, body := proxyPostPassthrough(t, apiKey, embeddingsPath, authorization, embeddingsRequest("text-embedding-004"))

			assert.Equal(t, hits, up.Hits(), "the gateway must mint a token, not forward the key")
			assertCallerKeyRefused(t, status, body)
		})
	}

	routes := map[string]struct {
		path string
		body map[string]any
	}{
		"native": {
			path: "/" + slug + "/v1/projects/test-proj/locations/us-central1/publishers/google/models/gemini-2.5-flash:generateContent",
			body: map[string]any{"contents": []any{map[string]any{"role": "user", "parts": []any{map[string]any{"text": "hi"}}}}},
		},
		"chat completions": {
			path: "/" + slug + "/v1/chat/completions",
			body: map[string]any{"model": "gemini-2.5-flash", "messages": []any{map[string]any{"role": "user", "content": "hi"}}},
		},
	}
	for name, route := range routes {
		for encoding, authorization := range keys {
			t.Run(name+"/"+encoding+" key is refused", func(t *testing.T) {
				status, body := proxyPostPassthrough(t, apiKey, route.path, authorization, route.body)

				assertCallerKeyRefused(t, status, body)
			})
		}
	}
}

// assertCallerKeyRefused accepts 401 when Google refuses the unknown account
// and 502 when the test host has no egress to Google.
func assertCallerKeyRefused(t *testing.T, status int, body []byte) {
	t.Helper()
	assert.NotContains(t, string(body), "PRIVATE KEY")
	require.Contains(t, []int{http.StatusUnauthorized, http.StatusBadGateway}, status, "body: %s", body)
	if status == http.StatusUnauthorized {
		assert.Contains(t, string(body), "provider credential in Authorization was rejected")
	}
}

//go:build functional

package functional_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// newUsageUpstream answers every request with a 200 chat-completion that carries
// an OpenAI-style usage block, so PostResponse plugins (e.g. token_rate_limiter)
// can observe the tokens the call "consumed".
func newUsageUpstream(t *testing.T, marker string, totalTokens int) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w,
			`{"id":"chatcmpl-test","object":"chat.completion",`+
				`"choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}],`+
				`"usage":{"prompt_tokens":%d,"completion_tokens":0,"total_tokens":%d}}`,
			marker, totalTokens, totalTokens,
		)
	}))
	t.Cleanup(u.server.Close)
	return u
}

// policyPlugin builds a single enabled policy payload for the given plugin
// slug. Stages are left to the plugin: the executor drives each plugin at its
// mandatory stages, so callers do not need to select any.
func policyPlugin(slug string, settings map[string]any) map[string]any {
	return map[string]any{
		"slug":     slug,
		"enabled":  true,
		"priority": 0,
		"settings": settings,
	}
}

// proxyAPIKeyHeader is the fixed ingress header the proxy plane reads the client
const proxyAPIKeyHeader = "X-AG-API-Key"

// setupPolicyRoute wires a full proxy route guarded by one or more policies: a
// gateway, one OpenAI-compatible backend pointing at up, a policy per entry and
// a consumer that references them all, plus an api_key credential attached to
// that consumer. It returns that credential's key and the routing path to POST
// against the proxy plane.
func setupPolicyRoute(t *testing.T, up *fakeUpstream, pluginEntries ...map[string]any) (string, string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("plugin-gw")})
	backendID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be"), up.URL()))

	policyIDs := make([]string, 0, len(pluginEntries))
	for _, entry := range pluginEntries {
		payload := map[string]any{"name": uniqueName("pol")}
		for k, v := range entry {
			payload[k] = v
		}
		policyIDs = append(policyIDs, CreatePolicy(t, gatewayID, payload))
	}

	name := uniqueName("cons")
	coID := CreateConsumerWithRegistries(t, gatewayID, name, backendID)
	for _, policyID := range policyIDs {
		AttachPolicy(t, gatewayID, coID, policyID)
	}
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	return apiKey, chatCompletionsPath(t, coID)
}

// proxyRequest forwards an arbitrary-method request through the proxy plane
// authenticating with apiKey at path, applying extra headers. body may be nil
// (no payload). It presents the key in the fixed X-AG-API-Key header and returns
// the status, response headers and the full body.
func proxyRequest(
	t *testing.T,
	method, apiKey, path string,
	headers map[string]string,
	body []byte,
) (int, http.Header, []byte) {
	t.Helper()

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, ProxyURL+path, reader)
	require.NoError(t, err)
	host, ok := proxyHosts.Load(apiKey)
	require.True(t, ok, "proxy host missing for api key")
	req.Host = host.(string)
	req.Header.Set(proxyAPIKeyHeader, apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, resp.Header, raw
}

// mustJSON marshals v to bytes for a proxy request body, failing the test on
// error.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	buf, err := json.Marshal(v)
	require.NoError(t, err)
	return buf
}

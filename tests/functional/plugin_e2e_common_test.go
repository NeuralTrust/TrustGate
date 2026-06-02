package functional_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// newUsageUpstream answers every request with a 200 chat-completion that carries
// an OpenAI-style usage block, so PostResponse plugins (e.g. token_rate_limiter)
// can observe the tokens the call "consumed".
func newUsageUpstream(t *testing.T, marker string, totalTokens int) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&u.hits, 1)
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

// policyPlugin builds a single enabled plugin entry for a policy payload. The
// stage only has to be a valid enum: the executor drives each plugin at the
// stages it declares via Stages(), ignoring the configured stage.
func policyPlugin(name, stage string, settings map[string]any) map[string]any {
	return map[string]any{
		"name":     name,
		"enabled":  true,
		"stage":    stage,
		"priority": 0,
		"settings": settings,
	}
}

// setupPolicyRoute wires a full proxy route guarded by a policy: a gateway, one
// OpenAI-compatible backend pointing at up, a policy carrying pluginEntries and
// a consumer that references both. It returns the gateway id and the routing
// path to POST against the proxy plane.
func setupPolicyRoute(t *testing.T, up *fakeUpstream, pluginEntries ...map[string]any) (string, string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"name": uniqueName("plugin-gw")})
	backendID := CreateBackend(t, gatewayID, openaiBackendPayload(uniqueName("be"), up.URL()))
	policyID := CreatePolicy(t, gatewayID, map[string]any{
		"name":    uniqueName("pol"),
		"plugins": pluginEntries,
	})

	path := "/v1/" + uniqueName("route")
	CreateConsumer(t, gatewayID, map[string]any{
		"name":        uniqueName("cons"),
		"path":        path,
		"backend_ids": []string{backendID},
		"policy_ids":  []string{policyID},
	})
	return gatewayID, path
}

// proxyRequest forwards an arbitrary-method request through the proxy plane for
// gatewayID at path, applying extra headers. body may be nil (no payload). It
// identifies the gateway with the interim X-Gateway-Id header and returns the
// status, response headers and the full body.
func proxyRequest(
	t *testing.T,
	method, gatewayID, path string,
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
	req.Header.Set("X-Gateway-Id", gatewayID)
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

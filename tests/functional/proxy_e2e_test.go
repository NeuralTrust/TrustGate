package functional_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeUpstream is an in-process OpenAI-compatible LLM endpoint the proxy plane
// forwards to (via a backend whose provider_options.base_url points at it). It
// counts the requests it serves so the tests can assert routing and retries.
type fakeUpstream struct {
	server *httptest.Server
	hits   int64
}

func (u *fakeUpstream) URL() string { return u.server.URL }

func (u *fakeUpstream) Hits() int { return int(atomic.LoadInt64(&u.hits)) }

// newJSONUpstream answers every request with a 200 chat-completion whose
// assistant content is marker, so a test can tell which backend served it.
func newJSONUpstream(t *testing.T, marker string) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&u.hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w,
			`{"id":"chatcmpl-test","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}]}`,
			marker,
		)
	}))
	t.Cleanup(u.server.Close)
	return u
}

// newStreamUpstream answers every request with a 200 SSE stream carrying marker
// in a delta chunk and terminated by the OpenAI "[DONE]" sentinel.
func newStreamUpstream(t *testing.T, marker string) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&u.hits, 1)
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		write := func(s string) {
			_, _ = io.WriteString(w, s)
			if flusher != nil {
				flusher.Flush()
			}
		}
		write(fmt.Sprintf(
			`data: {"id":"chatcmpl-test","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":%q}}]}`+"\n\n",
			marker,
		))
		write("data: [DONE]\n\n")
	}))
	t.Cleanup(u.server.Close)
	return u
}

// newFailingUpstream answers every request with status, used to drive the
// retry/failover path until the budget is exhausted.
func newFailingUpstream(t *testing.T, status int) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&u.hits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"error":{"message":"upstream failure","type":"server_error"}}`)
	}))
	t.Cleanup(u.server.Close)
	return u
}

// openaiBackendPayload builds a CreateBackend body for an OpenAI-compatible
// target whose base_url is overridden to a fake upstream.
func openaiBackendPayload(name, baseURL string) map[string]any {
	return map[string]any{
		"name":             name,
		"provider":         "openai",
		"weight":           1,
		"provider_options": map[string]any{"base_url": baseURL},
		"auth": map[string]any{
			"type":    "api_key",
			"api_key": map[string]any{"api_key": "sk-test"},
		},
	}
}

// chatRequest returns a minimal OpenAI chat-completions body; stream toggles the
// "stream" flag that the proxy uses to pick the streaming path.
func chatRequest(stream bool) map[string]any {
	body := map[string]any{
		"model":    "gpt-4o-mini",
		"messages": []map[string]string{{"role": "user", "content": "Hello"}},
	}
	if stream {
		body["stream"] = true
	}
	return body
}

// expectedAttempts is the total number of upstream calls a single request makes
// when every attempt fails: the first try plus the configured retry budget.
func expectedAttempts() int {
	return GlobalConfig.Provider.MaxRetries + 1
}

// proxyPost forwards body through the proxy plane for gatewayID at path. It
// identifies the gateway with the interim X-Gateway-Id header and returns the
// status, response headers and the full (buffered or streamed) body.
func proxyPost(t *testing.T, gatewayID, path string, body any) (int, http.Header, []byte) {
	t.Helper()
	buf, err := json.Marshal(body)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, ProxyURL+path, bytes.NewReader(buf))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gateway-Id", gatewayID)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, resp.Header, raw
}

// setupRoute creates a gateway, one backend per upstream and a consumer routing
// path to those backends, returning the gateway id and the routing path.
func setupRoute(t *testing.T, algorithm string, upstreams ...*fakeUpstream) (string, string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"name": uniqueName("proxy-gw")})

	backendIDs := make([]string, 0, len(upstreams))
	for _, up := range upstreams {
		backendIDs = append(backendIDs, CreateBackend(t, gatewayID, openaiBackendPayload(uniqueName("be"), up.URL())))
	}

	path := "/v1/" + uniqueName("route")
	consumer := map[string]any{
		"name":        uniqueName("cons"),
		"path":        path,
		"backend_ids": backendIDs,
	}
	if algorithm != "" {
		consumer["algorithm"] = algorithm
	}
	CreateConsumer(t, gatewayID, consumer)
	return gatewayID, path
}

func TestProxyE2E_NonStreaming_NoLB(t *testing.T) {
	defer Track(t, "ProxyE2E")()

	t.Run("success", func(t *testing.T) {
		up := newJSONUpstream(t, "hello-from-upstream")
		gatewayID, path := setupRoute(t, "", up)

		status, headers, body := proxyPost(t, gatewayID, path, chatRequest(false))

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Equal(t, "openai", headers.Get("X-Selected-Provider"))
		assert.Contains(t, string(body), "hello-from-upstream")
		assert.Equal(t, 1, up.Hits(), "a successful call must hit the upstream exactly once")
	})

	t.Run("retries exhausted", func(t *testing.T) {
		up := newFailingUpstream(t, http.StatusInternalServerError)
		gatewayID, path := setupRoute(t, "", up)

		status, _, body := proxyPost(t, gatewayID, path, chatRequest(false))

		assert.Equal(t, http.StatusInternalServerError, status, "the final upstream error is relayed, body: %s", body)
		assert.Equal(t, expectedAttempts(), up.Hits(), "every attempt (first + retries) must reach the upstream")
	})
}

func TestProxyE2E_Streaming_NoLB(t *testing.T) {
	defer Track(t, "ProxyE2E")()

	t.Run("success", func(t *testing.T) {
		up := newStreamUpstream(t, "streamed-token")
		gatewayID, path := setupRoute(t, "", up)

		status, headers, body := proxyPost(t, gatewayID, path, chatRequest(true))

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Equal(t, "openai", headers.Get("X-Selected-Provider"))
		assert.Contains(t, string(body), "streamed-token")
		assert.Contains(t, string(body), "[DONE]", "the SSE terminator must be relayed")
		assert.Equal(t, 1, up.Hits())
	})

	t.Run("retries exhausted", func(t *testing.T) {
		up := newFailingUpstream(t, http.StatusInternalServerError)
		gatewayID, path := setupRoute(t, "", up)

		status, _, body := proxyPost(t, gatewayID, path, chatRequest(true))

		// A pre-stream failure never opens a stream, so the budget is exhausted
		// exactly like the synchronous path and the final error is relayed.
		assert.Equal(t, http.StatusInternalServerError, status, "body: %s", body)
		assert.Equal(t, expectedAttempts(), up.Hits())
	})
}

func TestProxyE2E_NonStreaming_LB(t *testing.T) {
	defer Track(t, "ProxyE2E")()

	upA := newJSONUpstream(t, "upstream-A")
	upB := newJSONUpstream(t, "upstream-B")
	gatewayID, path := setupRoute(t, "round-robin", upA, upB)

	const total = 6
	for i := 0; i < total; i++ {
		status, headers, body := proxyPost(t, gatewayID, path, chatRequest(false))
		assert.Equal(t, http.StatusOK, status, "request %d body: %s", i, body)
		assert.Equal(t, "openai", headers.Get("X-Selected-Provider"))
	}

	assert.Greater(t, upA.Hits(), 0, "backend A should receive traffic")
	assert.Greater(t, upB.Hits(), 0, "backend B should receive traffic")
	assert.Equal(t, total, upA.Hits()+upB.Hits(), "every request must reach exactly one backend")
}

func TestProxyE2E_Streaming_LB(t *testing.T) {
	defer Track(t, "ProxyE2E")()

	upA := newStreamUpstream(t, "stream-A")
	upB := newStreamUpstream(t, "stream-B")
	gatewayID, path := setupRoute(t, "round-robin", upA, upB)

	const total = 6
	servedByA, servedByB := 0, 0
	for i := 0; i < total; i++ {
		status, headers, body := proxyPost(t, gatewayID, path, chatRequest(true))
		assert.Equal(t, http.StatusOK, status, "request %d body: %s", i, body)
		assert.Equal(t, "openai", headers.Get("X-Selected-Provider"))
		assert.Contains(t, string(body), "[DONE]", "request %d must yield a terminated stream", i)
		switch {
		case strings.Contains(string(body), "stream-A"):
			servedByA++
		case strings.Contains(string(body), "stream-B"):
			servedByB++
		}
	}

	assert.Greater(t, upA.Hits(), 0, "backend A should receive streaming traffic")
	assert.Greater(t, upB.Hits(), 0, "backend B should receive streaming traffic")
	assert.Equal(t, total, upA.Hits()+upB.Hits())
	assert.Equal(t, total, servedByA+servedByB, "each stream must carry exactly one backend's marker")
}

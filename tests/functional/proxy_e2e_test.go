//go:build functional

package functional_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeUpstream is an in-process OpenAI-compatible LLM endpoint the proxy plane
// forwards to (via a backend whose provider_options.base_url points at it). It
// counts the requests it serves so the tests can assert routing and retries.
type fakeUpstream struct {
	server   *httptest.Server
	hits     int64
	mu       sync.Mutex
	lastBody []byte
}

func (u *fakeUpstream) URL() string { return u.server.URL }

func (u *fakeUpstream) Hits() int { return int(atomic.LoadInt64(&u.hits)) }

func (u *fakeUpstream) LastBody() []byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.lastBody
}

func (u *fakeUpstream) record(r *http.Request) {
	atomic.AddInt64(&u.hits, 1)
	body, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.lastBody = body
	u.mu.Unlock()
}

// newJSONUpstream answers every request with a 200 chat-completion whose
// assistant content is marker, so a test can tell which backend served it.
func newJSONUpstream(t *testing.T, marker string) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.record(r)
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

// openaiBackendPayload builds a CreateRegistry body for an OpenAI-compatible
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

// openaiCompatibleBackendPayload builds a CreateRegistry body for a generic
// OpenAI-compatible target (provider "openai_compatible") whose base_url points
// at a fake upstream. Unlike openaiBackendPayload, base_url is mandatory.
func openaiCompatibleBackendPayload(name, baseURL string) map[string]any {
	return map[string]any{
		"name":             name,
		"provider":         "openai_compatible",
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

// chatRequestModel returns an OpenAI chat body that requests an explicit model.
func chatRequestModel(model string) map[string]any {
	return map[string]any{
		"model":    model,
		"messages": []map[string]string{{"role": "user", "content": "Hello"}},
	}
}

// chatRequestNoModel returns an OpenAI chat body that omits the "model" field,
// exercising the default-injection path of the model policy.
func chatRequestNoModel() map[string]any {
	return map[string]any{
		"messages": []map[string]string{{"role": "user", "content": "Hello"}},
	}
}

// expectedAttempts is the total number of upstream calls a single request makes
// when every attempt fails: the first try plus the configured retry budget.
func expectedAttempts() int {
	return GlobalConfig.Provider.MaxRetries + 1
}

// proxyPost forwards body through the proxy plane authenticating with apiKey at
// path. It presents the key in the fixed X-AG-API-Key header and returns the
// status, response headers and the full (buffered or streamed) body.
func proxyPost(t *testing.T, apiKey, path string, body any) (int, http.Header, []byte) {
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

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, resp.Header, raw
}

func setupRoute(t *testing.T, algorithm string, upstreams ...*fakeUpstream) (string, string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"name": uniqueName("proxy-gw")})

	registryIDs := make([]string, 0, len(upstreams))
	for _, up := range upstreams {
		registryIDs = append(registryIDs, CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be"), up.URL())))
	}

	consumer := map[string]any{
		"name": uniqueName("cons"),
	}
	if algorithm != "" {
		consumer["algorithm"] = algorithm
	}
	coID := CreateConsumer(t, gatewayID, consumer)
	for _, registryID := range registryIDs {
		AttachRegistry(t, gatewayID, coID, registryID)
	}
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	return apiKey, chatCompletionsPath(t, coID)
}

func TestProxyE2E_NonStreaming_NoLB(t *testing.T) {
	defer Track(t, "ProxyE2E")()

	t.Run("success", func(t *testing.T) {
		up := newJSONUpstream(t, "hello-from-upstream")
		apiKey, path := setupRoute(t, "", up)

		status, headers, body := proxyPost(t, apiKey, path, chatRequest(false))

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Equal(t, "openai", headers.Get("X-Selected-Provider"))
		assert.Contains(t, string(body), "hello-from-upstream")
		assert.Equal(t, 1, up.Hits(), "a successful call must hit the upstream exactly once")
	})

	t.Run("retries exhausted", func(t *testing.T) {
		up := newFailingUpstream(t, http.StatusInternalServerError)
		apiKey, path := setupRoute(t, "", up)

		status, _, body := proxyPost(t, apiKey, path, chatRequest(false))

		assert.Equal(t, http.StatusInternalServerError, status, "the final upstream error is relayed, body: %s", body)
		assert.Equal(t, expectedAttempts(), up.Hits(), "every attempt (first + retries) must reach the upstream")
	})
}

func TestProxyE2E_Streaming_NoLB(t *testing.T) {
	defer Track(t, "ProxyE2E")()

	t.Run("success", func(t *testing.T) {
		up := newStreamUpstream(t, "streamed-token")
		apiKey, path := setupRoute(t, "", up)

		status, headers, body := proxyPost(t, apiKey, path, chatRequest(true))

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Equal(t, "openai", headers.Get("X-Selected-Provider"))
		assert.Contains(t, string(body), "streamed-token")
		assert.Contains(t, string(body), "[DONE]", "the SSE terminator must be relayed")
		assert.Equal(t, 1, up.Hits())
	})

	t.Run("retries exhausted", func(t *testing.T) {
		up := newFailingUpstream(t, http.StatusInternalServerError)
		apiKey, path := setupRoute(t, "", up)

		status, _, body := proxyPost(t, apiKey, path, chatRequest(true))

		assert.Equal(t, http.StatusInternalServerError, status, "body: %s", body)
		assert.Equal(t, expectedAttempts(), up.Hits())
	})
}

func TestProxyE2E_OpenAICompatibleProvider(t *testing.T) {
	defer Track(t, "ProxyE2E")()

	setupCompatRoute := func(t *testing.T, up *fakeUpstream) (string, string) {
		t.Helper()
		gatewayID := CreateGateway(t, map[string]any{"name": uniqueName("compat-gw")})
		registryID := CreateRegistry(t, gatewayID, openaiCompatibleBackendPayload(uniqueName("be"), up.URL()))
		coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("cons")})
		AttachRegistry(t, gatewayID, coID, registryID)
		apiKey := createAndAttachAPIKey(t, gatewayID, coID)
		return apiKey, chatCompletionsPath(t, coID)
	}

	t.Run("non-streaming", func(t *testing.T) {
		up := newJSONUpstream(t, "compat-hello")
		apiKey, path := setupCompatRoute(t, up)

		status, headers, body := proxyPost(t, apiKey, path, chatRequest(false))

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Equal(t, "openai_compatible", headers.Get("X-Selected-Provider"))
		assert.Contains(t, string(body), "compat-hello")
		assert.Equal(t, 1, up.Hits())
	})

	t.Run("streaming", func(t *testing.T) {
		up := newStreamUpstream(t, "compat-token")
		apiKey, path := setupCompatRoute(t, up)

		status, headers, body := proxyPost(t, apiKey, path, chatRequest(true))

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Equal(t, "openai_compatible", headers.Get("X-Selected-Provider"))
		assert.Contains(t, string(body), "compat-token")
		assert.Contains(t, string(body), "[DONE]", "the SSE terminator must be relayed")
		assert.Equal(t, 1, up.Hits())
	})
}

func TestProxyE2E_NonStreaming_LB(t *testing.T) {
	defer Track(t, "ProxyE2E")()

	upA := newJSONUpstream(t, "upstream-A")
	upB := newJSONUpstream(t, "upstream-B")
	apiKey, path := setupRoute(t, "round-robin", upA, upB)

	const total = 6
	for i := 0; i < total; i++ {
		status, headers, body := proxyPost(t, apiKey, path, chatRequest(false))
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
	apiKey, path := setupRoute(t, "round-robin", upA, upB)

	const total = 6
	servedByA, servedByB := 0, 0
	for i := 0; i < total; i++ {
		status, headers, body := proxyPost(t, apiKey, path, chatRequest(true))
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

// setupModelPolicyRoute wires a gateway with a single backend pointing at up and
// a consumer that binds the given model policy to that backend, returning the
// api key attached to that consumer and the routing path.
func setupModelPolicyRoute(t *testing.T, up *fakeUpstream, allowed []string, defaultModel string) (string, string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"name": uniqueName("mp-gw")})
	backendID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be"), up.URL()))
	name := uniqueName("cons")
	policy := map[string]any{"allowed": allowed}
	if defaultModel != "" {
		policy["default"] = defaultModel
	}
	// The atomic create path binds the registry and its model policy in one POST.
	coID := CreateConsumer(t, gatewayID, map[string]any{
		"name": name,
		"registries": []map[string]any{
			{"id": backendID, "model_policies": policy},
		},
	})
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	return apiKey, chatCompletionsPath(t, coID)
}

func TestProxyE2E_ModelPolicies(t *testing.T) {
	defer Track(t, "ProxyE2E")()

	t.Run("allowed model is forwarded", func(t *testing.T) {
		up := newJSONUpstream(t, "allowed-served")
		apiKey, path := setupModelPolicyRoute(t, up, []string{"gpt-4o-mini"}, "gpt-4o-mini")

		status, _, body := proxyPost(t, apiKey, path, chatRequestModel("gpt-4o-mini"))

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(body), "allowed-served")
		assert.Equal(t, 1, up.Hits())
	})

	t.Run("disallowed model is rejected with 403 and never reaches upstream", func(t *testing.T) {
		up := newJSONUpstream(t, "should-not-be-served")
		apiKey, path := setupModelPolicyRoute(t, up, []string{"gpt-4o-mini"}, "")

		status, _, body := proxyPost(t, apiKey, path, chatRequestModel("gpt-4-forbidden"))

		assert.Equal(t, http.StatusForbidden, status, "a disallowed model must be rejected, body: %s", body)
		assert.Equal(t, 0, up.Hits(), "a rejected model must never reach the upstream")
	})

	t.Run("missing model injects the configured default", func(t *testing.T) {
		up := newJSONUpstream(t, "default-served")
		apiKey, path := setupModelPolicyRoute(t, up, []string{"gpt-4o-mini"}, "gpt-4o-mini")

		status, _, body := proxyPost(t, apiKey, path, chatRequestNoModel())

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Equal(t, 1, up.Hits())
		assert.Contains(t, string(up.LastBody()), `"gpt-4o-mini"`,
			"the default model must be injected into the upstream request body")
	})
}

// setupFallbackRoute wires a gateway whose consumer routes to primary and, when
// fallbackEnabled, fails over to the fallback backend on the given triggers. It
// returns the api key attached to that consumer and the routing path.
func setupFallbackRoute(t *testing.T, primary, fallback *fakeUpstream, fallbackEnabled bool, triggers ...string) (string, string) {
	t.Helper()
	if len(triggers) == 0 {
		triggers = []string{"http_5xx"}
	}
	gatewayID := CreateGateway(t, map[string]any{"name": uniqueName("fb-gw")})
	primaryID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be-primary"), primary.URL()))
	fallbackID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be-fallback"), fallback.URL()))
	name := uniqueName("cons")
	coID := CreateConsumer(t, gatewayID, map[string]any{"name": name})
	path := chatCompletionsPath(t, coID)
	AttachRegistry(t, gatewayID, coID, primaryID)
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)

	if !fallbackEnabled {
		_ = fallbackID
		return apiKey, path
	}

	AttachRegistry(t, gatewayID, coID, fallbackID)
	UpdateConsumer(t, gatewayID, coID, map[string]any{
		"name": name,
		"fallback": map[string]any{
			"enabled":  true,
			"triggers": triggers,
			"chain":    []string{fallbackID},
		},
	})
	return apiKey, path
}

func TestProxyE2E_Fallback(t *testing.T) {
	defer Track(t, "ProxyE2E")()

	t.Run("primary exhausts then fallback serves", func(t *testing.T) {
		primary := newFailingUpstream(t, http.StatusInternalServerError)
		fallback := newJSONUpstream(t, "fallback-served")
		apiKey, path := setupFallbackRoute(t, primary, fallback, true)

		status, headers, body := proxyPost(t, apiKey, path, chatRequest(false))

		assert.Equal(t, http.StatusOK, status, "the fallback must rescue the request, body: %s", body)
		assert.Contains(t, string(body), "fallback-served")
		assert.Equal(t, "openai", headers.Get("X-Selected-Provider"))
		assert.Equal(t, expectedAttempts(), primary.Hits(), "primary must exhaust its retry budget before failover")
		assert.Equal(t, 1, fallback.Hits(), "fallback must serve exactly once")
	})

	t.Run("all registries failing relays the final error", func(t *testing.T) {
		primary := newFailingUpstream(t, http.StatusInternalServerError)
		fallback := newFailingUpstream(t, http.StatusBadGateway)
		apiKey, path := setupFallbackRoute(t, primary, fallback, true)

		status, _, body := proxyPost(t, apiKey, path, chatRequest(false))

		assert.Equal(t, http.StatusBadGateway, status, "the final fallback error is relayed, body: %s", body)
		assert.Equal(t, expectedAttempts(), primary.Hits(), "primary must be fully retried")
		assert.Equal(t, expectedAttempts(), fallback.Hits(), "fallback must be fully retried before giving up")
	})

	t.Run("429 with only http_5xx trigger relays the 429 without using the chain", func(t *testing.T) {
		primary := newFailingUpstream(t, http.StatusTooManyRequests)
		fallback := newJSONUpstream(t, "must-not-serve")
		apiKey, path := setupFallbackRoute(t, primary, fallback, true, "http_5xx")

		status, _, body := proxyPost(t, apiKey, path, chatRequest(false))

		assert.Equal(t, http.StatusTooManyRequests, status, "the 429 must be relayed verbatim, body: %s", body)
		assert.Equal(t, expectedAttempts(), primary.Hits(), "primary retries are not gated by triggers")
		assert.Equal(t, 0, fallback.Hits(), "the chain must not be used when the failure kind is not a configured trigger")
	})

	t.Run("429 with http_429 trigger fails over to the chain", func(t *testing.T) {
		primary := newFailingUpstream(t, http.StatusTooManyRequests)
		fallback := newJSONUpstream(t, "rescued-from-429")
		apiKey, path := setupFallbackRoute(t, primary, fallback, true, "http_429")

		status, _, body := proxyPost(t, apiKey, path, chatRequest(false))

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(body), "rescued-from-429")
		assert.Equal(t, 1, fallback.Hits())
	})

	t.Run("disabled fallback never fails over", func(t *testing.T) {
		primary := newFailingUpstream(t, http.StatusInternalServerError)
		fallback := newJSONUpstream(t, "must-not-serve")
		apiKey, path := setupFallbackRoute(t, primary, fallback, false)

		status, _, body := proxyPost(t, apiKey, path, chatRequest(false))

		assert.Equal(t, http.StatusInternalServerError, status, "body: %s", body)
		assert.Equal(t, expectedAttempts(), primary.Hits())
		assert.Equal(t, 0, fallback.Hits(), "a disabled fallback chain must never be used")
	})
}

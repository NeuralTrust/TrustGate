//go:build functional

package functional_test

// End-to-end checks for a customer's gateway evaluation, one test per finding
// (S06, S08, G01, T02, F04/T04, S04, R04, F02, F08/O01). Every check goes
// through the real binary: the admin API configures it, the proxy plane serves
// it, and in-process stubs stand in for the identity provider and the LLM
// providers. A finding that needs a setting the shared planes do not boot with
// (INFO access logs, a short provider timeout, an admin API on TLS) starts one
// more process of the same binary with that setting.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Extra gateway processes

// lineLog keeps every line a process writes, so a test can assert on its logs.
type lineLog struct {
	mu    sync.Mutex
	buf   []byte
	lines []string
}

func (l *lineLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf = append(l.buf, p...)
	for {
		idx := bytes.IndexByte(l.buf, '\n')
		if idx < 0 {
			break
		}
		l.lines = append(l.lines, string(l.buf[:idx]))
		l.buf = l.buf[idx+1:]
	}
	return len(p), nil
}

// find returns the first line holding every substring, "" when none does.
func (l *lineLog) find(substrings ...string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range l.lines {
		matches := true
		for _, s := range substrings {
			if !strings.Contains(line, s) {
				matches = false
				break
			}
		}
		if matches {
			return line
		}
	}
	return ""
}

func (l *lineLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n") + string(l.buf)
}

type extraServer struct {
	cmd  *exec.Cmd
	port int
	logs *lineLog
}

func freeLocalPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

// startExtraServer boots one more process of the suite's gateway binary in
// mode, on its own port, with the suite's environment plus extra (which wins
// over both the environment and the .env file). It shares the suite's
// database and Redis, so everything the admin API created is served by it.
func startExtraServer(t *testing.T, mode string, extra map[string]string) *extraServer {
	t.Helper()
	require.NotEmpty(t, serverEnv, "suite environment not captured")
	port := freeLocalPort(t)
	env := slices.Clone(serverEnv)
	switch mode {
	case "admin":
		env = append(env, fmt.Sprintf("SERVER_ADMIN_PORT=%d", port),
			fmt.Sprintf("CONFIG_SYNC_GRPC_LISTEN_ADDR=127.0.0.1:%d", freeLocalPort(t)))
	case "proxy":
		env = append(env, fmt.Sprintf("SERVER_PROXY_PORT=%d", port))
	default:
		t.Fatalf("unsupported extra server mode %q", mode)
	}
	for key, value := range extra {
		env = append(env, key+"="+value)
	}
	logs := &lineLog{}
	cmd := exec.Command(gatewayBinaryPath, mode) //nolint:gosec // the suite's own binary
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout, cmd.Stderr = logs, logs
	require.NoError(t, cmd.Start())
	srv := &extraServer{cmd: cmd, port: port, logs: logs}
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			t.Logf("%s server output:\n%s", mode, logs.String())
		}
	})
	return srv
}

// waitHTTP polls url with client until it answers below 500.
func waitHTTP(t *testing.T, client *http.Client, url string, logs *lineLog) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url) //nolint:noctx // test poll
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode < 500 {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("%s never became ready; output:\n%s", url, logs.String())
}

func (s *extraServer) proxyURL() string { return fmt.Sprintf("http://127.0.0.1:%d", s.port) }

// ---------------------------------------------------------------------------
// Requests and stubs

// gatewayPost sends body to the proxy plane at base+path under the gateway's
// host, with the given headers (credentials included), and returns the status,
// headers and the whole body.
func gatewayPost(t *testing.T, base, gatewayID, path string, headers map[string]string, body any) (int, http.Header, []byte) {
	t.Helper()
	buf, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(buf))
	require.NoError(t, err)
	host, ok := gatewayHosts.Load(gatewayID)
	require.True(t, ok, "gateway host missing for %s", gatewayID)
	req.Host = host.(string)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, resp.Header, raw
}

func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

// headerUpstream is an OpenAI-compatible stub that answers a chat completion
// and keeps the headers of every request it received.
type headerUpstream struct {
	server *httptest.Server
	hits   atomic.Int64
	mu     sync.Mutex
	last   http.Header
}

func newHeaderUpstream(t *testing.T) *headerUpstream {
	t.Helper()
	u := &headerUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		u.mu.Lock()
		u.last = r.Header.Clone()
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/messages") {
			_, _ = io.WriteString(w, `{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"anthropic-ok"}],"stop_reason":"end_turn","usage":{"input_tokens":3,"output_tokens":2}}`)
			return
		}
		_, _ = io.WriteString(w, `{"id":"chatcmpl-h","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"headers-ok"},"finish_reason":"stop"}]}`)
	}))
	t.Cleanup(u.server.Close)
	return u
}

func (u *headerUpstream) lastHeaders() http.Header {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.last
}

// scriptedStream is a provider stub that writes the given SSE frames, flushing
// each, and then ends the response as end says: "done" returns normally (the
// frames carry their own terminal), "eof" returns without a terminal (a clean
// close), "reset" aborts the TCP connection (RST) mid-body.
func scriptedStream(t *testing.T, frames []string, end string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for _, frame := range frames {
			_, _ = io.WriteString(w, frame)
			flusher.Flush()
		}
		if end != "reset" {
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
		_ = conn.Close()
	}))
	t.Cleanup(srv.Close)
	return srv
}

// sseEvents parses body the way the SSE specification says a client must:
// an event is dispatched only when a blank line ends it, and an event the body
// ends inside is discarded. It returns each dispatched event's name and data.
func sseEvents(body []byte) [][2]string {
	var out [][2]string
	var name string
	var data []string
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			if len(data) > 0 || name != "" {
				out = append(out, [2]string{name, strings.Join(data, "\n")})
			}
			name, data = "", nil
		case strings.HasPrefix(line, ":"):
		case strings.HasPrefix(line, "event:"):
			name = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	// bufio.Scanner hides whether the body ended on a newline, so a last
	// event is never dispatched here unless a blank line ended it above.
	return out
}

func eventData(events [][2]string) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e[1])
	}
	return out
}

// identityRoute is a gateway with one OpenAI backend at upstreamURL, a consumer
// bound to it and an OAuth2 identity provider (the stub) attached to it. The
// consumer is created with extra fields merged into its create body.
type identityRoute struct {
	gatewayID  string
	consumerID string
	path       string
	idp        *oauthIDPStub
	audience   string
}

func newIdentityRoute(t *testing.T, upstreamURL string, consumerExtra map[string]any) identityRoute {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("hard-gw")})
	registryID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be"), upstreamURL))
	idp := newOAuthIDPStub(t)
	audience := "trustgate-agents"
	authID := CreateAuth(t, gatewayID, oauth2AuthPayload(uniqueName("idp"), idp.issuer, idp.jwksURL(), audience, "agent-app", idpStubScope))
	payload := map[string]any{
		"name":       uniqueName("agents"),
		"registries": []map[string]any{{"id": registryID}},
	}
	for k, v := range consumerExtra {
		payload[k] = v
	}
	consumerID := CreateConsumer(t, gatewayID, payload)
	AttachAuth(t, gatewayID, consumerID, authID)
	return identityRoute{
		gatewayID:  gatewayID,
		consumerID: consumerID,
		path:       chatCompletionsPath(t, consumerID),
		idp:        idp,
		audience:   audience,
	}
}

func (r identityRoute) token(t *testing.T, claims map[string]any) string {
	t.Helper()
	return r.idp.mint(t, r.audience, claims)
}

func (r identityRoute) chat(t *testing.T, base, token string, extraHeaders map[string]string) (int, []byte) {
	t.Helper()
	headers := bearer(token)
	for k, v := range extraHeaders {
		headers[k] = v
	}
	status, _, body := gatewayPost(t, base, r.gatewayID, r.path, headers, chatRequest(false))
	return status, body
}

// ---------------------------------------------------------------------------
// S06: tokens that carry a person's claims are refused on an agent route

func TestCustomerE2E_S06_ClaimRulesRefusePersonTokens(t *testing.T) {
	defer Track(t, "CustomerHardening")()

	up := newJSONUpstream(t, "served-to-agent")
	route := newIdentityRoute(t, up.URL(), map[string]any{
		"auth_binding": map[string]any{
			"allowed_client_ids": []string{"agent-app"},
			"required_claims":    map[string][]string{"idtyp": {"app"}},
			"forbidden_claims":   []string{"email", "upn", "name", "preferred_username"},
		},
	})

	// The binding round-trips through the admin API.
	status, consumer := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, route.gatewayID, route.consumerID), nil, nil)
	require.Equal(t, http.StatusOK, status, "%v", consumer)
	binding, _ := consumer["auth_binding"].(map[string]any)
	forbidden, _ := binding["forbidden_claims"].([]any)
	assert.ElementsMatch(t, []any{"email", "upn", "name", "preferred_username"}, forbidden)
	assert.Equal(t, map[string]any{"idtyp": []any{"app"}}, binding["required_claims"])

	cases := []struct {
		name   string
		claims map[string]any
		want   int
	}{
		{"workload token", map[string]any{"sub": "agent-1", "azp": "agent-app", "idtyp": "app"}, http.StatusOK},
		{"person's token issued to the agent's own client", map[string]any{"sub": "user-1", "azp": "agent-app", "idtyp": "app", "upn": "ana@corp.example", "name": "Ana"}, http.StatusForbidden},
		{"person's token with only an email", map[string]any{"sub": "user-1", "azp": "agent-app", "idtyp": "app", "email": "ana@corp.example"}, http.StatusForbidden},
		{"token without the required claim", map[string]any{"sub": "agent-1", "azp": "agent-app"}, http.StatusForbidden},
		{"token issued to another client", map[string]any{"sub": "agent-1", "azp": "spa-app", "idtyp": "app"}, http.StatusForbidden},
	}
	for _, tc := range cases {
		status, body := route.chat(t, ProxyURL, route.token(t, tc.claims), nil)
		assert.Equal(t, tc.want, status, "%s: body %s", tc.name, body)
		if tc.want == http.StatusOK {
			assert.Contains(t, string(body), "served-to-agent", tc.name)
		}
	}
	assert.Equal(t, 1, up.Hits(), "only the workload token may reach the provider")
}

// ---------------------------------------------------------------------------
// S08: a rate limit per person, not per application

func rateLimitPolicy(settings map[string]any) map[string]any {
	return map[string]any{
		"name":     uniqueName("per-caller"),
		"slug":     "rate_limiter",
		"enabled":  true,
		"priority": 0,
		"settings": settings,
	}
}

func TestCustomerE2E_S08_RateLimitPerCaller(t *testing.T) {
	defer Track(t, "CustomerHardening")()

	t.Run("by verified subject", func(t *testing.T) {
		up := newJSONUpstream(t, "ok")
		route := newIdentityRoute(t, up.URL(), nil)
		policyID := CreatePolicy(t, route.gatewayID, rateLimitPolicy(map[string]any{"limit": 1, "window": "1m", "group_by": "subject"}))
		AttachPolicy(t, route.gatewayID, route.consumerID, policyID)

		alice := route.token(t, map[string]any{"sub": "alice"})
		bob := route.token(t, map[string]any{"sub": "bob"})

		status, body := route.chat(t, ProxyURL, alice, nil)
		require.Equal(t, http.StatusOK, status, "alice's first request: %s", body)
		status, body = route.chat(t, ProxyURL, alice, map[string]string{"X-User-Id": "someone-else"})
		assert.Equal(t, http.StatusTooManyRequests, status, "alice's burst is limited whatever header she sends: %s", body)
		status, body = route.chat(t, ProxyURL, bob, nil)
		assert.Equal(t, http.StatusOK, status, "bob is not throttled by alice's burst: %s", body)
		status, _ = route.chat(t, ProxyURL, bob, nil)
		assert.Equal(t, http.StatusTooManyRequests, status, "bob has his own limit")
	})

	t.Run("by verified claim", func(t *testing.T) {
		up := newJSONUpstream(t, "ok")
		route := newIdentityRoute(t, up.URL(), nil)
		policyID := CreatePolicy(t, route.gatewayID, rateLimitPolicy(map[string]any{"limit": 1, "window": "1m", "group_by": "claim", "group_by_claim": "oid"}))
		AttachPolicy(t, route.gatewayID, route.consumerID, policyID)

		status, body := route.chat(t, ProxyURL, route.token(t, map[string]any{"sub": "agent-a", "oid": "tenant-1"}), nil)
		require.Equal(t, http.StatusOK, status, "%s", body)
		status, _ = route.chat(t, ProxyURL, route.token(t, map[string]any{"sub": "agent-b", "oid": "tenant-1"}), nil)
		assert.Equal(t, http.StatusTooManyRequests, status, "the same oid shares one budget whatever the subject")
		status, body = route.chat(t, ProxyURL, route.token(t, map[string]any{"sub": "agent-a", "oid": "tenant-2"}), nil)
		assert.Equal(t, http.StatusOK, status, "another oid has its own budget: %s", body)
	})

	t.Run("an invalid partition is refused at save", func(t *testing.T) {
		gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("hard-gw")})
		url := fmt.Sprintf("%s/v1/gateways/%s/policies", AdminURL, gatewayID)
		status, body := sendRequest(t, http.MethodPost, url, nil, rateLimitPolicy(map[string]any{"limit": 1, "window": "1m", "group_by": "claim"}))
		assert.Equal(t, http.StatusUnprocessableEntity, status, "group_by claim without a claim: %v", body)
	})
}

// ---------------------------------------------------------------------------
// G01: the default access log says who sent a request

func TestCustomerE2E_G01_AccessLogAttributesCaller(t *testing.T) {
	defer Track(t, "CustomerHardening")()

	up := newJSONUpstream(t, "ok")
	route := newIdentityRoute(t, up.URL(), nil)
	proxy := startExtraServer(t, "proxy", map[string]string{"LOG_LEVEL": "INFO", "LOG_FORMAT": "json"})
	waitHTTP(t, http.DefaultClient, proxy.proxyURL()+"/healthz", proxy.logs)

	subject := uniqueName("agent-log")
	token := route.token(t, map[string]any{"sub": subject, "azp": "agent-app", "email": "should-not-be-logged@corp.example"})
	status, body := route.chat(t, proxy.proxyURL(), token, nil)
	require.Equal(t, http.StatusOK, status, "%s", body)

	var line string
	require.Eventually(t, func() bool {
		line = proxy.logs.find(`"msg":"http access"`, `"principal_subject":"`+subject+`"`)
		return line != ""
	}, 10*time.Second, 100*time.Millisecond, "no access line for %s; output:\n%s", subject, proxy.logs.String())

	var entry map[string]any
	require.NoError(t, json.Unmarshal([]byte(line), &entry), line)
	assert.Equal(t, route.gatewayID, entry["gateway_id"])
	assert.Equal(t, route.consumerID, entry["consumer_id"])
	assert.Equal(t, "oauth2", entry["auth_method"])
	assert.NotEmpty(t, entry["auth_id"])
	assert.Equal(t, "agent-app", entry["client_id"])
	assert.EqualValues(t, 200, entry["status"])
	assert.NotContains(t, line, "should-not-be-logged@corp.example", "an email is never logged")
}

// ---------------------------------------------------------------------------
// F04/T04: the [DONE] event is a whole event

func TestCustomerE2E_F04_DoneEventIsTerminated(t *testing.T) {
	defer Track(t, "CustomerHardening")()

	up := newStreamUpstream(t, "streamed")
	apiKey, path := setupRoute(t, "", up)
	status, _, body := proxyPost(t, apiKey, path, chatRequest(true))
	require.Equal(t, http.StatusOK, status, "%s", body)

	assert.True(t, bytes.HasSuffix(body, []byte("data: [DONE]\n\n")), "the stream must end with a terminated [DONE] event, got %q", body)
	data := eventData(sseEvents(body))
	require.NotEmpty(t, data)
	assert.Equal(t, "[DONE]", data[len(data)-1], "a strict SSE parser must dispatch [DONE]: %q", body)
}

// ---------------------------------------------------------------------------
// T02: a provider that fails mid-stream is visible to the client

const (
	openAIChunk = `data: {"id":"chatcmpl-x","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":"partial answer"}}]}` + "\n\n"
	openAIFinal = `data: {"id":"chatcmpl-x","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}` + "\n\n"
)

func TestCustomerE2E_T02_MidStreamFailureIsVisible(t *testing.T) {
	defer Track(t, "CustomerHardening")()

	openAICases := []struct {
		name      string
		frames    []string
		end       string
		wantError bool
	}{
		{"complete stream", []string{openAIChunk, openAIFinal, "data: [DONE]\n\n"}, "done", false},
		{"connection reset mid-stream", []string{openAIChunk}, "reset", true},
		{"clean close before [DONE]", []string{openAIChunk, openAIFinal}, "eof", true},
	}
	for _, tc := range openAICases {
		t.Run("openai/"+tc.name, func(t *testing.T) {
			srv := scriptedStream(t, tc.frames, tc.end)
			apiKey, path := setupRoute(t, "", &fakeUpstream{server: srv})
			status, _, body := proxyPost(t, apiKey, path, chatRequest(true))
			require.Equal(t, http.StatusOK, status, "%s", body)
			require.Contains(t, string(body), "partial answer")
			data := eventData(sseEvents(body))
			require.NotEmpty(t, data, "%q", body)
			last := data[len(data)-1]
			if tc.wantError {
				assert.Contains(t, last, `"error"`, "the client must be told the answer is truncated: %q", body)
				assert.NotContains(t, string(body), "[DONE]", "a truncated answer must not look finished: %q", body)
				return
			}
			assert.Equal(t, "[DONE]", last, "%q", body)
			assert.NotContains(t, string(body), `"error"`, "%q", body)
		})
	}

	anthropicFrames := []string{
		"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-5\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":3,\"output_tokens\":0}}}\n\n",
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"partial answer\"}}\n\n",
	}
	anthropicEnd := []string{
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}}\n\n",
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
	}
	anthropicCases := []struct {
		name      string
		frames    []string
		end       string
		wantError bool
	}{
		{"complete stream", append(slices.Clone(anthropicFrames), anthropicEnd...), "done", false},
		{"connection reset mid-stream", anthropicFrames, "reset", true},
		{"clean close before message_stop", anthropicFrames, "eof", true},
	}
	for _, tc := range anthropicCases {
		t.Run("anthropic/"+tc.name, func(t *testing.T) {
			srv := scriptedStream(t, tc.frames, tc.end)
			gatewayID, path, apiKey := anthropicRoute(t, srv.URL+"/v1", nil)
			payload := anthropicChatRequest("claude-sonnet-4-5")
			payload["stream"] = true
			status, _, body := gatewayPost(t, ProxyURL, gatewayID, path, map[string]string{proxyAPIKeyHeader: apiKey}, payload)
			require.Equal(t, http.StatusOK, status, "%s", body)
			require.Contains(t, string(body), "partial answer")
			events := sseEvents(body)
			require.NotEmpty(t, events, "%q", body)
			last := events[len(events)-1]
			if tc.wantError {
				assert.Equal(t, "error", last[0], "the client must get an error event: %q", body)
				assert.NotContains(t, string(body), "message_stop", "%q", body)
				return
			}
			assert.Equal(t, "message_stop", last[0], "%q", body)
		})
	}
}

// anthropicRoute is a gateway with one Anthropic backend whose base_url is
// baseURL and whose provider_options also carry extraOptions, and a consumer
// on it reached with an api key. It returns the gateway, the consumer's
// /v1/messages path and the key.
func anthropicRoute(t *testing.T, baseURL string, extraOptions map[string]any) (string, string, string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("hard-ant")})
	options := map[string]any{"base_url": baseURL}
	for k, v := range extraOptions {
		options[k] = v
	}
	registryID := CreateRegistry(t, gatewayID, map[string]any{
		"name":             uniqueName("ant"),
		"provider":         "anthropic",
		"weight":           1,
		"provider_options": options,
		"auth":             map[string]any{"type": "api_key", "api_key": map[string]any{"api_key": "sk-ant-test"}},
	})
	consumerID := CreateConsumer(t, gatewayID, map[string]any{
		"name":       uniqueName("ant-cons"),
		"registries": []map[string]any{{"id": registryID}},
	})
	apiKey := createAndAttachAPIKey(t, gatewayID, consumerID)
	return gatewayID, "/" + ConsumerSlug(t, consumerID) + "/v1/messages", apiKey
}

// ---------------------------------------------------------------------------
// F08/O01: chosen client headers reach the provider, nothing else does

func TestCustomerE2E_F08_ClientHeadersToProvider(t *testing.T) {
	defer Track(t, "CustomerHardening")()

	const traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	clientHeaders := map[string]string{
		"traceparent":     traceparent,
		"tracestate":      "vendor=abc",
		"X-Client-Secret": "must-not-leave-the-gateway",
	}

	t.Run("registry forwards the headers it lists", func(t *testing.T) {
		up := newHeaderUpstream(t)
		gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("hard-fwd")})
		payload := openaiBackendPayload(uniqueName("be"), up.server.URL)
		payload["provider_options"] = map[string]any{"base_url": up.server.URL, "forward_client_headers": []string{"traceparent", "tracestate"}}
		registryID := CreateRegistry(t, gatewayID, payload)
		consumerID := CreateConsumerWithRegistries(t, gatewayID, uniqueName("fwd"), registryID)
		apiKey := createAndAttachAPIKey(t, gatewayID, consumerID)

		status, registry := sendRequest(t, http.MethodGet, fmt.Sprintf("%s/v1/gateways/%s/registries/%s", AdminURL, gatewayID, registryID), nil, nil)
		require.Equal(t, http.StatusOK, status)
		options, _ := registry["provider_options"].(map[string]any)
		assert.Equal(t, []any{"Traceparent", "Tracestate"}, options["forward_client_headers"])

		headers := map[string]string{proxyAPIKeyHeader: apiKey}
		for k, v := range clientHeaders {
			headers[k] = v
		}
		status, _, body := gatewayPost(t, ProxyURL, gatewayID, chatCompletionsPath(t, consumerID), headers, chatRequest(false))
		require.Equal(t, http.StatusOK, status, "%s", body)
		got := up.lastHeaders()
		assert.Equal(t, traceparent, got.Get("traceparent"))
		assert.Equal(t, "vendor=abc", got.Get("tracestate"))
		assert.Empty(t, got.Get("X-Client-Secret"), "an unlisted header is never forwarded")
		assert.Empty(t, got.Get(proxyAPIKeyHeader), "the gateway credential is never forwarded")
		assert.Equal(t, "Bearer sk-test", got.Get("Authorization"), "the provider gets the registry's credential")
	})

	t.Run("nothing is forwarded by default", func(t *testing.T) {
		up := newHeaderUpstream(t)
		apiKey, path := setupRoute(t, "", &fakeUpstream{server: up.server})
		headers := map[string]string{proxyAPIKeyHeader: apiKey}
		for k, v := range clientHeaders {
			headers[k] = v
		}
		host, _ := proxyHosts.Load(apiKey)
		req, err := http.NewRequest(http.MethodPost, ProxyURL+path, strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`))
		require.NoError(t, err)
		req.Host = host.(string)
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Empty(t, up.lastHeaders().Get("traceparent"))
		assert.Empty(t, up.lastHeaders().Get("X-Client-Secret"))
	})

	t.Run("a credential can never be listed", func(t *testing.T) {
		gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("hard-fwd")})
		for _, name := range []string{"authorization", "x-api-key", "cookie", "X-AG-API-Key"} {
			payload := openaiBackendPayload(uniqueName("be"), "http://127.0.0.1:1")
			payload["provider_options"] = map[string]any{"base_url": "http://127.0.0.1:1", "forward_client_headers": []string{name}}
			status, body := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/v1/gateways/%s/registries", AdminURL, gatewayID), nil, payload)
			assert.Equal(t, http.StatusUnprocessableEntity, status, "%s must be refused: %v", name, body)
		}
	})

	t.Run("anthropic-beta reaches an Anthropic-format provider", func(t *testing.T) {
		up := newHeaderUpstream(t)
		gatewayID, path, apiKey := anthropicRoute(t, up.server.URL+"/v1", map[string]any{"forward_client_headers": []string{"traceparent"}})
		status, _, body := gatewayPost(t, ProxyURL, gatewayID, path, map[string]string{
			proxyAPIKeyHeader: apiKey,
			"anthropic-beta":  "context-management-2025-06-27",
			"traceparent":     traceparent,
		}, anthropicChatRequest("claude-sonnet-4-5"))
		require.Equal(t, http.StatusOK, status, "%s", body)
		assert.Contains(t, string(body), "anthropic-ok")
		got := up.lastHeaders()
		assert.Equal(t, "context-management-2025-06-27", got.Get("anthropic-beta"))
		assert.Equal(t, "2023-06-01", got.Get("anthropic-version"), "the gateway's own anthropic-version is kept")
		assert.Equal(t, "sk-ant-test", got.Get("x-api-key"))
		assert.Equal(t, traceparent, got.Get("traceparent"))
	})
}

// ---------------------------------------------------------------------------
// R04: a failed request does not multiply billable provider calls

func TestCustomerE2E_R04_RetriesDoNotMultiplyCalls(t *testing.T) {
	defer Track(t, "CustomerHardening")()

	t.Run("no retries by default", func(t *testing.T) {
		// An empty value makes the process ignore the suite's .env setting
		// and fall back to the built-in default.
		proxy := startExtraServer(t, "proxy", map[string]string{"PROVIDER_MAX_RETRIES": ""})
		waitHTTP(t, http.DefaultClient, proxy.proxyURL()+"/healthz", proxy.logs)
		up := newFailingUpstream(t, http.StatusInternalServerError)
		apiKey, path := setupRoute(t, "", up)
		host, _ := proxyHosts.Load(apiKey)
		status := postWithHost(t, proxy.proxyURL()+path, host.(string), apiKey)
		assert.Equal(t, http.StatusInternalServerError, status)
		assert.Equal(t, 1, up.Hits(), "one client request must make one provider call by default")
	})

	t.Run("a timeout is never retried on the same backend", func(t *testing.T) {
		proxy := startExtraServer(t, "proxy", map[string]string{
			"PROVIDER_MAX_RETRIES":             "2",
			"PROVIDER_RESPONSE_HEADER_TIMEOUT": "2s",
		})
		waitHTTP(t, http.DefaultClient, proxy.proxyURL()+"/healthz", proxy.logs)

		var hits atomic.Int64
		slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		}))
		t.Cleanup(slow.Close)
		apiKey, path := setupRoute(t, "", &fakeUpstream{server: slow})
		host, _ := proxyHosts.Load(apiKey)
		started := time.Now()
		status := postWithHost(t, proxy.proxyURL()+path, host.(string), apiKey)
		assert.GreaterOrEqual(t, status, 500, "a provider that never answers is a gateway error")
		assert.Less(t, time.Since(started), 15*time.Second, "the client is not held for three timeouts")
		assert.EqualValues(t, 1, hits.Load(), "the provider may still be generating the first answer; it must not be asked again")

		failing := newFailingUpstream(t, http.StatusServiceUnavailable)
		apiKey, path = setupRoute(t, "", failing)
		host, _ = proxyHosts.Load(apiKey)
		assert.Equal(t, http.StatusServiceUnavailable, postWithHost(t, proxy.proxyURL()+path, host.(string), apiKey))
		assert.Equal(t, 3, failing.Hits(), "a 5xx is still retried as configured")
	})
}

func postWithHost(t *testing.T, url, host, apiKey string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`))
	require.NoError(t, err)
	req.Host = host
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(proxyAPIKeyHeader, apiKey)
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// ---------------------------------------------------------------------------
// F02: an application reaches only the models it lists, once it lists some

func TestCustomerE2E_F02_ModelAllowList(t *testing.T) {
	defer Track(t, "CustomerHardening")()

	open := newJSONUpstream(t, "any-model")
	apiKey, path := setupRoute(t, "", open)
	status, _, body := proxyPost(t, apiKey, path, chatRequestModel("gpt-unknown-model"))
	assert.Equal(t, http.StatusOK, status, "with no model list any model is forwarded (the default the console warns about): %s", body)
	assert.Equal(t, 1, open.Hits())

	restricted := newJSONUpstream(t, "restricted")
	apiKey, slug := setupSlugRoute(t, restricted, []string{"gpt-4o-mini"}, "")
	status, _, body = proxyPost(t, apiKey, "/"+slug+"/v1/chat/completions", chatRequestModel("gpt-unknown-model"))
	assert.GreaterOrEqual(t, status, 400, "%s", body)
	assert.Less(t, status, 500, "%s", body)
	assert.Equal(t, 0, restricted.Hits(), "a model outside the list never reaches the provider")
	status, _, body = proxyPost(t, apiKey, "/"+slug+"/v1/chat/completions", chatRequestModel("gpt-4o-mini"))
	assert.Equal(t, http.StatusOK, status, "%s", body)
}

// ---------------------------------------------------------------------------
// S04: the management API binds where it is told and serves TLS

func writeAdminCert(t *testing.T) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "trustgate-admin.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool = x509.NewCertPool()
	pool.AddCert(cert)
	return certFile, keyFile, pool
}

// nonLoopbackIPv4 is an address of this host other than loopback, "" when the
// host has none.
func nonLoopbackIPv4() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			return ipNet.IP.String()
		}
	}
	return ""
}

func TestCustomerE2E_S04_AdminListener(t *testing.T) {
	defer Track(t, "CustomerHardening")()

	t.Run("loopback only, over TLS", func(t *testing.T) {
		certFile, keyFile, pool := writeAdminCert(t)
		admin := startExtraServer(t, "admin", map[string]string{
			"SERVER_ADMIN_HOST":          "127.0.0.1",
			"SERVER_ADMIN_TLS_CERT_FILE": certFile,
			"SERVER_ADMIN_TLS_KEY_FILE":  keyFile,
		})
		tlsClient := &http.Client{
			Timeout:   5 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		}
		base := fmt.Sprintf("https://127.0.0.1:%d", admin.port)
		waitHTTP(t, tlsClient, base+"/healthz", admin.logs)

		// The admin API itself answers over TLS with an admin token.
		gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("hard-adm")})
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v1/gateways/%s", base, gatewayID), nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+AdminToken)
		resp, err := tlsClient.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		require.NotNil(t, resp.TLS)
		assert.GreaterOrEqual(t, resp.TLS.Version, uint16(tls.VersionTLS12))

		// Plain HTTP on the same port gets no admin API.
		plain := &http.Client{Timeout: 3 * time.Second}
		if resp, err := plain.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", admin.port)); err == nil {
			_ = resp.Body.Close()
			assert.NotEqual(t, http.StatusOK, resp.StatusCode, "plain HTTP must not be served")
		}

		// Another interface of the host cannot reach it.
		if ip := nonLoopbackIPv4(); ip != "" {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(admin.port)), 2*time.Second)
			if err == nil {
				_ = conn.Close()
			}
			assert.Error(t, err, "the admin API must not listen on %s", ip)
		} else {
			t.Log("no non-loopback IPv4 on this host; bind check skipped")
		}
	})

	t.Run("a certificate without its key does not boot", func(t *testing.T) {
		certFile, _, _ := writeAdminCert(t)
		env := append(slices.Clone(serverEnv),
			fmt.Sprintf("SERVER_ADMIN_PORT=%d", freeLocalPort(t)),
			fmt.Sprintf("CONFIG_SYNC_GRPC_LISTEN_ADDR=127.0.0.1:%d", freeLocalPort(t)),
			"SERVER_ADMIN_TLS_CERT_FILE="+certFile,
			"SERVER_ADMIN_TLS_KEY_FILE=",
		)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, gatewayBinaryPath, "admin") //nolint:gosec // the suite's own binary
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		require.Error(t, err, "the admin must refuse to start: %s", out)
		assert.Contains(t, string(out), "SERVER_ADMIN_TLS_CERT_FILE")
	})
}

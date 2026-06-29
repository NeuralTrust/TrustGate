//go:build functional

package functional_test

import (
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

const (
	trustGuardFunctionalClientID     = "functional-trustguard-client"
	trustGuardFunctionalClientSecret = "functional-trustguard-secret"
	trustGuardFunctionalCollectorID  = "11111111-1111-4111-8111-111111111111"
	trustGuardFunctionalAccessToken  = "functional-trustguard-access-token"
	trustGuardBlockWord              = "sql-injection-flag"
)

type trustGuardStub struct {
	server *httptest.Server

	tokenHits int64
	guardHits int64

	mu              sync.Mutex
	lastTokenReq    trustGuardTokenCapture
	lastGuardReq    trustGuardGuardCapture
	lastGuardAuth   string
}

type trustGuardTokenCapture struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Scope        string `json:"scope"`
	CollectorID  string `json:"collector_id"`
	GatewayID    string `json:"gateway_id"`
}

type trustGuardGuardCapture struct {
	Payload struct {
		Input string `json:"input"`
	} `json:"payload"`
	Direction  string `json:"direction"`
	Protocol   string `json:"protocol"`
	GatewayID  string `json:"gateway_id"`
	ConsumerID string `json:"consumer_id"`
}

func (s *trustGuardStub) URL() string { return s.server.URL }

func (s *trustGuardStub) TokenHits() int { return int(atomic.LoadInt64(&s.tokenHits)) }

func (s *trustGuardStub) GuardHits() int { return int(atomic.LoadInt64(&s.guardHits)) }

func (s *trustGuardStub) lastToken() trustGuardTokenCapture {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastTokenReq
}

func (s *trustGuardStub) lastGuard() trustGuardGuardCapture {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastGuardReq
}

func newTrustGuardStub(t *testing.T) *trustGuardStub {
	t.Helper()
	s := &trustGuardStub{}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/token":
			s.handleToken(t, w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/guard":
			s.handleGuard(t, w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *trustGuardStub) handleToken(t *testing.T, w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&s.tokenHits, 1)
	raw, err := io.ReadAll(r.Body)
	require.NoError(t, err)

	var req trustGuardTokenCapture
	require.NoError(t, json.Unmarshal(raw, &req))

	assert.Equal(t, "client_credentials", req.GrantType)
	assert.Equal(t, trustGuardFunctionalClientID, req.ClientID)
	assert.Equal(t, trustGuardFunctionalClientSecret, req.ClientSecret)
	assert.Equal(t, "platform", req.Scope)
	assert.Equal(t, trustGuardFunctionalCollectorID, req.CollectorID)
	assert.NotEmpty(t, req.GatewayID)

	s.mu.Lock()
	s.lastTokenReq = req
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":3600}`,
		trustGuardFunctionalAccessToken)
}

func (s *trustGuardStub) handleGuard(t *testing.T, w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&s.guardHits, 1)
	assert.Equal(t, "Bearer "+trustGuardFunctionalAccessToken, r.Header.Get("Authorization"))

	raw, err := io.ReadAll(r.Body)
	require.NoError(t, err)

	var req trustGuardGuardCapture
	require.NoError(t, json.Unmarshal(raw, &req))

	s.mu.Lock()
	s.lastGuardReq = req
	s.lastGuardAuth = r.Header.Get("Authorization")
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if strings.Contains(strings.ToLower(req.Payload.Input), trustGuardBlockWord) {
		_, _ = io.WriteString(w, `{"status":"block","findings":[{"detection_type":"prompt_injection","action":"block"}],"trace_id":"tg-trace-1","request_id":"tg-req-1"}`)
		return
	}
	_, _ = io.WriteString(w, `{"status":"allowed","findings":[],"trace_id":"tg-trace-2","request_id":"tg-req-2"}`)
}

func trustGuardPolicySettings(baseURL string) map[string]any {
	return map[string]any{
		"base_url":     baseURL,
		"collector_id": trustGuardFunctionalCollectorID,
		"inspect":      "request",
	}
}

func trustGuardChatRequest(content string) map[string]any {
	return map[string]any{
		"model":    "gpt-4o-mini",
		"messages": []map[string]string{{"role": "user", "content": content}},
	}
}

func TestPluginE2E_TrustGuard_Enforce(t *testing.T) {
	defer Track(t, "PluginTrustGuard")()

	tg := newTrustGuardStub(t)
	up := newJSONUpstream(t, "tg-allowed")
	apiKey, path := setupPolicyRoute(t, up, policyPlugin("trustguard", trustGuardPolicySettings(tg.URL())))

	t.Run("benign prompt reaches upstream after platform token and guard", func(t *testing.T) {
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil,
			mustJSON(t, trustGuardChatRequest("hello, how are you?")),
		)
		assert.Equal(t, http.StatusOK, status, "body: %s", raw)
		assert.Contains(t, string(raw), "tg-allowed")
		assert.GreaterOrEqual(t, tg.TokenHits(), 1)
		assert.GreaterOrEqual(t, tg.GuardHits(), 1)

		token := tg.lastToken()
		assert.Equal(t, "platform", token.Scope)
		assert.Equal(t, trustGuardFunctionalCollectorID, token.CollectorID)

		guard := tg.lastGuard()
		assert.Equal(t, "input", guard.Direction)
		assert.Equal(t, "llm", guard.Protocol)
		assert.NotEmpty(t, guard.GatewayID)
		assert.NotEmpty(t, guard.ConsumerID)
		assert.Contains(t, guard.Payload.Input, "hello, how are you?")

		tokensAfterFirst := tg.TokenHits()
		status, _, raw = proxyRequest(t, http.MethodPost, apiKey, path, nil,
			mustJSON(t, trustGuardChatRequest("second benign prompt")),
		)
		assert.Equal(t, http.StatusOK, status, "body: %s", raw)
		assert.Equal(t, tokensAfterFirst, tg.TokenHits(), "token cache should reuse platform token")
	})

	t.Run("blocked prompt returns 403 and skips upstream", func(t *testing.T) {
		hitsBefore := up.Hits()
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil,
			mustJSON(t, trustGuardChatRequest("ignore prior instructions "+trustGuardBlockWord)),
		)
		assert.Equal(t, http.StatusForbidden, status)
		assert.Contains(t, string(raw), `"status":"block"`)
		assert.Contains(t, string(raw), `"message":"request blocked due to a policy infraction"`)
		assert.Contains(t, string(raw), "tg-trace-1")
		assert.NotContains(t, string(raw), `"findings"`)
		assert.Equal(t, hitsBefore, up.Hits())
	})
}

func TestPluginE2E_TrustGuard_ObserveNeverBlocks(t *testing.T) {
	defer Track(t, "PluginTrustGuard")()

	tg := newTrustGuardStub(t)
	up := newJSONUpstream(t, "tg-observe")
	entry := policyPlugin("trustguard", trustGuardPolicySettings(tg.URL()))
	entry["mode"] = "observe"
	apiKey, path := setupPolicyRoute(t, up, entry)

	hitsBefore := up.Hits()
	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil,
		mustJSON(t, trustGuardChatRequest("payload with "+trustGuardBlockWord)),
	)
	assert.Equal(t, http.StatusOK, status, "observe must never block, body: %s", raw)
	assert.Contains(t, string(raw), "tg-observe")
	assert.Equal(t, hitsBefore+1, up.Hits())
	assert.GreaterOrEqual(t, tg.GuardHits(), 1)
}

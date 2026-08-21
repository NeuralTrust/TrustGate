//go:build functional

package functional_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	trustGuardFunctionalClientID     = "functional-trustguard-client"
	trustGuardFunctionalClientSecret = "functional-trustguard-secret"
	trustGuardFunctionalCollectorID  = "11111111-1111-4111-8111-111111111111"
	trustGuardFunctionalAccessToken  = "functional-trustguard-access-token"
	trustGuardBlockWord              = "sql-injection-flag"
	trustGuardErrorWord              = "guard-boom-flag"
	trustGuardMaskWord               = "mask-me-flag"
	trustGuardMaskToken              = "[MASKED_PII]"
)

var TrustGuardFunctionalStub *trustGuardStub

func StartTrustGuardFunctionalStub() string {
	if TrustGuardFunctionalStub != nil {
		return TrustGuardFunctionalStub.URL()
	}
	TrustGuardFunctionalStub = newTrustGuardStubServer()
	return TrustGuardFunctionalStub.URL()
}

func StopTrustGuardFunctionalStub() {
	if TrustGuardFunctionalStub == nil {
		return
	}
	TrustGuardFunctionalStub.server.Close()
	TrustGuardFunctionalStub = nil
}

type trustGuardStub struct {
	server *httptest.Server

	tokenHits int64
	guardHits int64

	mu            sync.Mutex
	lastTokenReq  trustGuardTokenCapture
	lastGuardReq  trustGuardGuardCapture
	lastGuardAuth string
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
	Payload    json.RawMessage `json:"payload"`
	Direction  string          `json:"direction"`
	Protocol   string          `json:"protocol"`
	GatewayID  string          `json:"gateway_id"`
	ConsumerID string          `json:"consumer_id"`
}

func trustGuardInspectText(payload json.RawMessage) string {
	if len(payload) == 0 {
		return ""
	}
	var llm struct {
		Input string `json:"input"`
	}
	if err := json.Unmarshal(payload, &llm); err == nil && strings.TrimSpace(llm.Input) != "" {
		return llm.Input
	}
	var mcp map[string]any
	if err := json.Unmarshal(payload, &mcp); err != nil {
		return string(payload)
	}
	var parts []string
	if params, ok := mcp["params"].(map[string]any); ok {
		parts = append(parts, flattenJSONStrings(params)...)
	}
	if result, ok := mcp["result"].(map[string]any); ok {
		parts = append(parts, flattenJSONStrings(result)...)
	}
	if len(parts) == 0 {
		return string(payload)
	}
	return strings.Join(parts, "\n")
}

func flattenJSONStrings(v any) []string {
	switch x := v.(type) {
	case string:
		if strings.TrimSpace(x) == "" {
			return nil
		}
		return []string{x}
	case map[string]any:
		out := make([]string, 0, len(x))
		for _, child := range x {
			out = append(out, flattenJSONStrings(child)...)
		}
		return out
	case []any:
		out := make([]string, 0, len(x))
		for _, child := range x {
			out = append(out, flattenJSONStrings(child)...)
		}
		return out
	default:
		return nil
	}
}

func (s *trustGuardStub) URL() string { return s.server.URL }

func (s *trustGuardStub) TokenHits() int { return int(atomic.LoadInt64(&s.tokenHits)) }

func (s *trustGuardStub) GuardHits() int { return int(atomic.LoadInt64(&s.guardHits)) }

func (s *trustGuardStub) Reset() {
	atomic.StoreInt64(&s.tokenHits, 0)
	atomic.StoreInt64(&s.guardHits, 0)
	s.mu.Lock()
	s.lastTokenReq = trustGuardTokenCapture{}
	s.lastGuardReq = trustGuardGuardCapture{}
	s.lastGuardAuth = ""
	s.mu.Unlock()
}

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

func newTrustGuardStubServer() *trustGuardStub {
	s := &trustGuardStub{}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/token":
			s.handleToken(w, r)
		case "/v1/evaluate":
			s.handleGuard(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	return s
}

func (s *trustGuardStub) handleToken(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&s.tokenHits, 1)
	raw, _ := io.ReadAll(r.Body)
	var req trustGuardTokenCapture
	_ = json.Unmarshal(raw, &req)

	s.mu.Lock()
	s.lastTokenReq = req
	s.mu.Unlock()

	if req.ClientID != trustGuardFunctionalClientID || req.ClientSecret != trustGuardFunctionalClientSecret {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"access_token":"`+trustGuardFunctionalAccessToken+`","token_type":"Bearer","expires_in":3600}`)
}

func (s *trustGuardStub) handleGuard(w http.ResponseWriter, r *http.Request) {
	if got := r.Header.Get("Authorization"); got != "Bearer "+trustGuardFunctionalAccessToken {
		atomic.AddInt64(&s.guardHits, 1)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	var req trustGuardGuardCapture
	_ = json.Unmarshal(raw, &req)

	s.mu.Lock()
	s.lastGuardReq = req
	s.lastGuardAuth = r.Header.Get("Authorization")
	s.mu.Unlock()

	// Counted only once the capture is visible, so a test that waits on
	// GuardHits can read lastGuard without racing the handler.
	atomic.AddInt64(&s.guardHits, 1)

	text := trustGuardInspectText(req.Payload)
	if strings.Contains(strings.ToLower(text), trustGuardErrorWord) {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if strings.Contains(strings.ToLower(text), trustGuardBlockWord) {
		_, _ = io.WriteString(w, `{"status":"block","findings":[{"source":{"kind":"detector","plugin":"prompt_guard"},"signal":{"type":"prompt_injection"},"outcome":{"action":"block"}}],"trace_id":"tg-trace-1","request_id":"tg-req-1"}`)
		return
	}
	if strings.Contains(text, trustGuardMaskWord) {
		masked := strings.ReplaceAll(text, trustGuardMaskWord, trustGuardMaskToken)
		payload, _ := json.Marshal(map[string]string{"input": masked})
		_, _ = io.WriteString(w, `{"status":"transform","transformed_payload":`+string(payload)+`,"findings":[{"source":{"kind":"detector","plugin":"data_loss_prevention"},"signal":{"type":"pii"},"outcome":{"action":"transform"}}],"trace_id":"tg-trace-3","request_id":"tg-req-3"}`)
		return
	}
	_, _ = io.WriteString(w, `{"status":"allowed","findings":[],"trace_id":"tg-trace-2","request_id":"tg-req-2"}`)
}

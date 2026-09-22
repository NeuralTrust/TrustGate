//go:build functional

package functional_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	trustGuardBlockReason = "prompt_injection"

	trustGuardBlockResponse = `{"status":"block","findings":[{"source":{"kind":"detector","plugin":"prompt_guard"},` +
		`"signal":{"type":"` + trustGuardBlockReason + `"},"outcome":{"action":"block"}}],` +
		`"trace_id":"tg-trace-1","request_id":"tg-req-1"}`
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
	guardDelay    time.Duration
	blockOnCall   int
	guardPayloads []json.RawMessage
	guardStreams  []GuardStream
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
	Payload    json.RawMessage         `json:"payload"`
	Direction  string                  `json:"direction"`
	Protocol   string                  `json:"protocol"`
	GatewayID  string                  `json:"gateway_id"`
	ConsumerID string                  `json:"consumer_id"`
	Attributes trustGuardAttributesCap `json:"attributes"`
}

type trustGuardAttributesCap struct {
	Stream *GuardStream `json:"stream"`
}

// GuardStream is the wire shape of attributes.stream, declared here rather than
// imported so the suite asserts the JSON the engine will actually receive and
// not the Go struct that produced it.
type GuardStream struct {
	ID        string `json:"id"`
	Seq       int    `json:"seq"`
	Final     bool   `json:"final"`
	Truncated bool   `json:"truncated"`
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
	// An LLM leg is a chat envelope, and what the engine reads — and hands back
	// masked — is the message content, not the envelope around it. Falling
	// through to the whole JSON would make a transform verdict return a
	// serialised payload as if it were the masked text, which every caller that
	// writes the mask back into a body or a buffer would then reject.
	var chat struct {
		Messages []map[string]any `json:"messages"`
	}
	if err := json.Unmarshal(payload, &chat); err == nil && len(chat.Messages) > 0 {
		var parts []string
		for _, msg := range chat.Messages {
			if content, ok := msg["content"].(string); ok && strings.TrimSpace(content) != "" {
				parts = append(parts, content)
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, "\n")
		}
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

// SetGuardDelay fixes the latency of every /v1/evaluate answer, which is what
// makes the number of events a clock-closed block holds deterministic rather
// than a function of how loaded the machine is.
func (s *trustGuardStub) SetGuardDelay(d time.Duration) {
	s.mu.Lock()
	s.guardDelay = d
	s.mu.Unlock()
}

// BlockOnCall makes the n-th /v1/evaluate answer with a block verdict and
// leaves every call before and after it allowed, so a test picks which point of
// a stream the violation surfaces at: n == 1 is the head, n > 1 is mid-stream.
func (s *trustGuardStub) BlockOnCall(n int) {
	s.mu.Lock()
	s.blockOnCall = n
	s.mu.Unlock()
}

// GuardPayloads returns every evaluate payload in call order.
func (s *trustGuardStub) GuardPayloads() []json.RawMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]json.RawMessage(nil), s.guardPayloads...)
}

// GuardStreams returns the attributes.stream envelope of every evaluate call,
// index-aligned with GuardPayloads. A call that carried no envelope contributes
// a zero value, which a real envelope never is: it always has an id and a seq
// of at least 1.
func (s *trustGuardStub) GuardStreams() []GuardStream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]GuardStream(nil), s.guardStreams...)
}

func (s *trustGuardStub) Reset() {
	atomic.StoreInt64(&s.tokenHits, 0)
	atomic.StoreInt64(&s.guardHits, 0)
	s.mu.Lock()
	s.lastTokenReq = trustGuardTokenCapture{}
	s.lastGuardReq = trustGuardGuardCapture{}
	s.lastGuardAuth = ""
	s.guardDelay = 0
	s.blockOnCall = 0
	s.guardPayloads = nil
	s.guardStreams = nil
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
	s.guardPayloads = append(s.guardPayloads, req.Payload)
	stream := GuardStream{}
	if req.Attributes.Stream != nil {
		stream = *req.Attributes.Stream
	}
	s.guardStreams = append(s.guardStreams, stream)
	delay, blockOn := s.guardDelay, s.blockOnCall
	s.mu.Unlock()

	// The counter is published after the capture: a test that waits on
	// GuardHits() for an async post_response would otherwise read a zero-value
	// lastGuard between the increment and this write.
	call := int(atomic.AddInt64(&s.guardHits, 1))

	if delay > 0 {
		time.Sleep(delay)
	}

	text := trustGuardInspectText(req.Payload)
	if blockOn > 0 && blockOn == call {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, trustGuardBlockResponse)
		return
	}
	if strings.Contains(strings.ToLower(text), trustGuardErrorWord) {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if strings.Contains(strings.ToLower(text), trustGuardBlockWord) {
		_, _ = io.WriteString(w, trustGuardBlockResponse)
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

// TestTrustGuardStub_ResetClearsEveryKnob walks the stub's own fields by
// reflection instead of naming them, because the failure this guards against
// is a knob added later and left out of Reset: a BlockOnCall surviving into an
// unrelated test fails it in a way that reads exactly like a product bug. The
// "populated" half is what keeps the check honest — a field nothing exercises
// would otherwise pass the "cleared" half for free.
func TestTrustGuardStub_ResetClearsEveryKnob(t *testing.T) {
	defer Track(t, "PluginTrustGuard")()

	require.NotNil(t, TrustGuardFunctionalStub, "TrustGuard stub must be started in TestMain")
	tg := TrustGuardFunctionalStub
	tg.Reset()

	tg.SetGuardDelay(time.Millisecond)
	tg.BlockOnCall(1)
	trustGuardStubToken(t, tg)
	trustGuardStubEvaluate(t, tg)

	for name, zero := range trustGuardStubFieldState(t, tg) {
		assert.False(t, zero, "%s is never populated, so asserting Reset clears it proves nothing", name)
	}

	tg.Reset()

	for name, zero := range trustGuardStubFieldState(t, tg) {
		assert.True(t, zero, "Reset must clear %s or it leaks into the next test", name)
	}
}

// trustGuardStubFieldState reports, per stub field, whether it holds its zero
// value. server and mu are the stub's plumbing rather than captured state, so
// they are the only two exemptions and every field added later is covered by
// default.
func trustGuardStubFieldState(t *testing.T, s *trustGuardStub) map[string]bool {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	v := reflect.ValueOf(s).Elem()
	state := make(map[string]bool, v.NumField())
	for i := range v.NumField() {
		name := v.Type().Field(i).Name
		if name == "server" || name == "mu" {
			continue
		}
		state[name] = v.Field(i).IsZero()
	}
	return state
}

func trustGuardStubToken(t *testing.T, s *trustGuardStub) {
	t.Helper()
	body := mustJSON(t, map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     trustGuardFunctionalClientID,
		"client_secret": trustGuardFunctionalClientSecret,
		"scope":         "platform",
		"collector_id":  trustGuardFunctionalCollectorID,
		"gateway_id":    "stub-reset-gateway",
	})
	resp, err := http.Post(s.URL()+"/v1/token", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func trustGuardStubEvaluate(t *testing.T, s *trustGuardStub) {
	t.Helper()
	body := mustJSON(t, map[string]any{
		"payload":     map[string]string{"input": "stub reset probe"},
		"direction":   "output",
		"protocol":    "llm",
		"gateway_id":  "stub-reset-gateway",
		"consumer_id": "stub-reset-consumer",
		"attributes": map[string]any{
			"stream": map[string]any{"id": "stub-reset-stream", "seq": 1, "final": true, "truncated": true},
		},
	})
	req, err := http.NewRequest(http.MethodPost, s.URL()+"/v1/evaluate", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+trustGuardFunctionalAccessToken)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

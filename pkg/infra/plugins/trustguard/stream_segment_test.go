// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package trustguard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

const testStreamTraceID = "trace-stream-1"

func openAIToolRequestBody() []byte {
	return []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hello world"}],` +
		`"tools":[{"type":"function","function":{"name":"search","description":"look things up",` +
		`"parameters":{"type":"object"}}}]}`)
}

func segmentRequest() *infracontext.RequestContext {
	req := requestContext()
	req.Body = openAIToolRequestBody()
	return req
}

type segmentPayloadBody struct {
	Messages []struct {
		Role      string           `json:"role"`
		Content   *string          `json:"content"`
		Reasoning string           `json:"reasoning_content"`
		ToolCalls []map[string]any `json:"tool_calls"`
	} `json:"messages"`
	Tools []map[string]any `json:"tools"`
}

func TestSegmentStreamID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		traceID string
		seg     appplugins.StreamSegment
		want    string
	}{
		{"the trace id names the response leg", testStreamTraceID,
			appplugins.StreamSegment{StreamID: "guard-handle"}, testStreamTraceID + streamIDSeparator + legResponse},
		{"without a trace the caller handle stands in", "",
			appplugins.StreamSegment{StreamID: "guard-handle"}, "guard-handle"},
		{"no trace and no handle leaves no id", "", appplugins.StreamSegment{}, ""},
		{"a blank handle is not an id", "", appplugins.StreamSegment{StreamID: "   "}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, segmentStreamID(tt.traceID, tt.seg))
		})
	}
}

func TestSegmentPayload(t *testing.T) {
	t.Parallel()

	p := &Plugin{registry: adapter.NewRegistry()}
	in := appplugins.ExecInput{Request: segmentRequest()}

	tests := []struct {
		name          string
		seg           appplugins.StreamSegment
		wantOK        bool
		wantContent   *string
		wantReasoning string
		wantToolCalls int
		wantTools     bool
	}{
		{name: "head block", seg: appplugins.StreamSegment{Seq: 1, Accumulated: "Hel"},
			wantOK: true, wantContent: ptr("Hel")},
		{name: "cumulative prefix with reasoning",
			seg:    appplugins.StreamSegment{Seq: 2, Accumulated: "Hello wor", Reasoning: "weighing it up"},
			wantOK: true, wantContent: ptr("Hello wor"), wantReasoning: "weighing it up"},
		{name: "final block carries tools[]",
			seg: appplugins.StreamSegment{
				Seq: 3, Final: true, Accumulated: "Hello world", Reasoning: "weighing it up",
				ToolCalls: []adapter.CanonicalToolCall{{ID: "call-1", Name: "search", Arguments: `{"q":"x"}`}},
			},
			wantOK: true, wantContent: ptr("Hello world"), wantReasoning: "weighing it up",
			wantToolCalls: 1, wantTools: true},
		{name: "a tool call with no text is still inspectable",
			seg: appplugins.StreamSegment{
				Seq:       4,
				ToolCalls: []adapter.CanonicalToolCall{{ID: "call-1", Name: "search", Arguments: `{"q":"x"}`}},
			},
			wantOK: true, wantToolCalls: 1},
		{name: "reasoning with no text is still inspectable",
			seg:    appplugins.StreamSegment{Seq: 5, Reasoning: "weighing it up"},
			wantOK: true, wantContent: ptr(""), wantReasoning: "weighing it up"},
		{name: "nothing produced yet", seg: appplugins.StreamSegment{Seq: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			raw, ok := p.segmentPayload(t.Context(), in, tt.seg)
			require.Equal(t, tt.wantOK, ok)
			if !tt.wantOK {
				assert.Nil(t, raw)
				return
			}

			var payload segmentPayloadBody
			require.NoError(t, json.Unmarshal(raw, &payload))
			require.Len(t, payload.Messages, 1)
			msg := payload.Messages[0]
			assert.Equal(t, "assistant", msg.Role)
			assert.Equal(t, tt.wantContent, msg.Content)
			assert.Equal(t, tt.wantReasoning, msg.Reasoning)
			assert.Len(t, msg.ToolCalls, tt.wantToolCalls)
			if tt.wantTools {
				assert.NotEmpty(t, payload.Tools, "tools[] belongs on the final block")
			} else {
				assert.Empty(t, payload.Tools, "tools[] must be omitted while final is false")
			}
		})
	}
}

func TestRequestTools(t *testing.T) {
	t.Parallel()

	p := &Plugin{registry: adapter.NewRegistry()}

	t.Run("no request", func(t *testing.T) {
		t.Parallel()
		assert.Nil(t, p.requestTools(nil))
	})

	t.Run("decoded from the request body", func(t *testing.T) {
		t.Parallel()
		tools := p.requestTools(segmentRequest())
		require.Len(t, tools, 1)
		assert.Equal(t, "search", tools[0].Name)
	})

	t.Run("unsupported format", func(t *testing.T) {
		t.Parallel()
		req := segmentRequest()
		req.Provider = "not-a-provider"
		req.SourceFormat = "not-a-format"
		assert.Nil(t, p.requestTools(req))
	})
}

func TestSegmentVerdicts(t *testing.T) {
	t.Parallel()

	finding := GuardFinding{
		Source:  &GuardFindingSource{Kind: "detector", DetectorName: "Toxicity"},
		Signal:  &GuardFindingSignal{Type: "toxicity", Confidence: 0.9},
		Outcome: &GuardFindingOutcome{Action: "block"},
	}
	produced := appplugins.StreamSegment{Seq: 1, Accumulated: "Hello world"}
	toolCallOnly := appplugins.StreamSegment{
		Seq:       1,
		ToolCalls: []adapter.CanonicalToolCall{{ID: "call-1", Name: "search", Arguments: `{"q":"x"}`}},
	}

	tests := []struct {
		name string
		seg  appplugins.StreamSegment
		resp GuardResponse
		want appplugins.SegmentVerdict
	}{
		{"allow", produced, GuardResponse{Status: statusAllow}, appplugins.SegmentVerdict{}},
		{"report never blocks a block", produced,
			GuardResponse{Status: statusReport, Findings: []GuardFinding{finding}},
			appplugins.SegmentVerdict{}},
		{"block", produced, GuardResponse{Status: statusBlock, Findings: []GuardFinding{finding}},
			appplugins.SegmentVerdict{
				Block:   true,
				Type:    typeBlocked,
				Message: "Request blocked by security policy: toxicity (Toxicity).",
			}},
		{"ask blocks like block", produced, GuardResponse{Status: statusAsk}, appplugins.SegmentVerdict{
			Block: true, Type: typeBlocked, Message: blockMessage,
		}},
		{"transform carries the masked buffer", produced,
			GuardResponse{Status: statusTransform, TransformedPayload: map[string]any{"input": "Hello [MASKED]"}},
			appplugins.SegmentVerdict{HasTransform: true, Transformed: "Hello [MASKED]"}},
		{"transform without a payload blocks", produced, GuardResponse{Status: statusTransform},
			appplugins.SegmentVerdict{Block: true, Type: typeBlocked, Message: blockMessage}},
		{"transform with nothing accumulated blocks instead of injecting", toolCallOnly,
			GuardResponse{Status: statusTransform, TransformedPayload: map[string]any{"input": "[MASKED]"}},
			appplugins.SegmentVerdict{Block: true, Type: typeBlocked, Message: blockMessage}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			verdict := segmentVerdict(tt.seg, &tt.resp)
			require.NotNil(t, verdict)
			assert.Equal(t, tt.want, *verdict)
		})
	}
}

func TestSegmentVerdictConstructors(t *testing.T) {
	t.Parallel()

	assert.Equal(t, appplugins.SegmentVerdict{}, *segmentAllow())
	assert.Equal(t, appplugins.SegmentVerdict{Block: true, Type: typeRateLimited, Message: rateLimitMessage},
		*segmentBlock(typeRateLimited, rateLimitMessage))
}

func ptr[T any](v T) *T { return &v }

// testClientTimeout is the TRUSTGUARD_TIMEOUT default, so a deadline test
// measures the block's own bound against the one the AC names rather than
// against the shorter timeout the other tests run with.
const testClientTimeout = 15 * time.Second

type segmentGuard struct {
	mu         sync.Mutex
	captured   []GuardRequest
	delays     []time.Duration
	tokenDelay time.Duration
	release    chan struct{}
	status     int
	response   GuardResponse
}

func (g *segmentGuard) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == tokenPath {
			if !g.hold(r, g.tokenDelay) {
				return
			}
			w.Header().Set("Content-Type", contentTypeJSON)
			_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "test-token", TokenType: "Bearer", ExpiresIn: 3600})
			return
		}
		var body GuardRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		g.mu.Lock()
		g.captured = append(g.captured, body)
		call := len(g.captured)
		var delay time.Duration
		if call <= len(g.delays) {
			delay = g.delays[call-1]
		}
		status, resp := g.status, g.response
		g.mu.Unlock()
		if !g.hold(r, delay) {
			return
		}
		if status == 0 {
			status = http.StatusOK
		}
		w.Header().Set("Content-Type", contentTypeJSON)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// hold stalls the handler and reports whether it should still answer. release
// lets a test that abandoned the call shut the server down without waiting the
// delay out; a cancelled request is dropped.
func (g *segmentGuard) hold(r *http.Request, delay time.Duration) bool {
	if delay <= 0 {
		return true
	}
	select {
	case <-time.After(delay):
		return true
	case <-g.release:
		return false
	case <-r.Context().Done():
		return false
	}
}

func (g *segmentGuard) calls() []GuardRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]GuardRequest(nil), g.captured...)
}

func newSegmentServer(t *testing.T, g *segmentGuard) *httptest.Server {
	t.Helper()
	g.release = make(chan struct{})
	srv := httptest.NewServer(g.handler())
	t.Cleanup(srv.Close)
	// Registered last, so it runs first: a handler still stalling on a call the
	// test walked away from would otherwise keep srv.Close waiting.
	t.Cleanup(func() { close(g.release) })
	return srv
}

func streamingSettings(streaming map[string]any) map[string]any {
	s := map[string]any{"enabled": true}
	for k, v := range streaming {
		s[k] = v
	}
	return map[string]any{
		"collector_id": testCollectorID,
		"direction":    legResponse,
		"streaming":    s,
	}
}

func segmentInput(t *testing.T, set map[string]any) appplugins.ExecInput {
	t.Helper()
	return execInput(policy.StagePreResponse, policy.ModeEnforce, set, segmentRequest(), nil)
}

func segmentTraceContext() context.Context {
	return trace.NewContext(context.Background(), trace.New(testStreamTraceID, trace.Metadata{}))
}

func TestInspectSegmentPayloadAndStreamEnvelope(t *testing.T) {
	t.Parallel()

	g := &segmentGuard{response: GuardResponse{Status: statusAllow}}
	p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
	ctx := segmentTraceContext()
	in := segmentInput(t, streamingSettings(nil))

	segments := []appplugins.StreamSegment{
		{StreamID: "guard-handle", Seq: 1, Accumulated: "Hel"},
		{StreamID: "guard-handle", Seq: 2, Accumulated: "Hello wor", Reasoning: "weighing it up"},
		{
			StreamID:    "guard-handle",
			Seq:         3,
			Final:       true,
			Accumulated: "Hello world",
			Reasoning:   "weighing it up",
			ToolCalls:   []adapter.CanonicalToolCall{{ID: "call-1", Name: "search", Arguments: `{"q":"x"}`}},
		},
	}
	for _, seg := range segments {
		verdict, err := p.InspectSegment(ctx, in, seg)
		require.NoError(t, err)
		require.NotNil(t, verdict)
		assert.False(t, verdict.Block)
	}

	calls := g.calls()
	require.Len(t, calls, len(segments))

	finals := 0
	for i, call := range calls {
		require.NotNil(t, call.Attributes.Stream, "call %d carries no stream envelope", i)
		assert.Equal(t, testStreamTraceID+streamIDSeparator+legResponse, call.Attributes.Stream.ID,
			"the stream id must be stable across every block")
		assert.NotEqual(t, call.SessionID, call.Attributes.Stream.ID,
			"the stream id is the response leg, not the conversation")
		assert.Equal(t, directionOutput, call.Direction)
		assert.Equal(t, protocolLLM, call.Protocol)
		if i > 0 {
			assert.Greater(t, call.Attributes.Stream.Seq, calls[i-1].Attributes.Stream.Seq)
		}
		if call.Attributes.Stream.Final {
			finals++
			assert.Equal(t, len(calls)-1, i, "final must be the last call of the stream")
		}
	}
	assert.Equal(t, 1, finals, "final must be set exactly once")

	for i, seg := range segments {
		want, ok := p.segmentPayload(t.Context(), in, seg)
		require.True(t, ok)
		assert.JSONEq(t, string(want), string(calls[i].Payload),
			"the wire payload is the one segmentPayload builds")
	}
}

func TestInspectSegmentTruncatedRidesOnTheEnvelope(t *testing.T) {
	t.Parallel()

	g := &segmentGuard{response: GuardResponse{Status: statusAllow}}
	p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
	_, err := p.InspectSegment(segmentTraceContext(), segmentInput(t, streamingSettings(nil)),
		appplugins.StreamSegment{Seq: 4, Truncated: true, Accumulated: "tail window"})
	require.NoError(t, err)

	calls := g.calls()
	require.Len(t, calls, 1)
	require.NotNil(t, calls[0].Attributes.Stream)
	assert.True(t, calls[0].Attributes.Stream.Truncated)
}

func TestInspectSegmentStreamIDFallsBackToTheCallerHandle(t *testing.T) {
	t.Parallel()

	g := &segmentGuard{response: GuardResponse{Status: statusAllow}}
	p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
	_, err := p.InspectSegment(context.Background(), segmentInput(t, streamingSettings(nil)),
		appplugins.StreamSegment{StreamID: "guard-handle", Seq: 1, Accumulated: "no trace here"})
	require.NoError(t, err)

	calls := g.calls()
	require.Len(t, calls, 1)
	require.NotNil(t, calls[0].Attributes.Stream)
	assert.Equal(t, "guard-handle", calls[0].Attributes.Stream.ID)
}

func TestInspectSegmentDropsTheEnvelopeWithoutAnID(t *testing.T) {
	t.Parallel()

	g := &segmentGuard{response: GuardResponse{Status: statusAllow}}
	p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
	_, err := p.InspectSegment(context.Background(), segmentInput(t, streamingSettings(nil)),
		appplugins.StreamSegment{Seq: 1, Accumulated: "no trace and no handle"})
	require.NoError(t, err)

	calls := g.calls()
	require.Len(t, calls, 1, "the block is still inspected; only the correlation is missing")
	assert.Nil(t, calls[0].Attributes.Stream,
		"an empty id would correlate every stream in the process into one bucket")
}

func TestInspectSegmentDeliberateRejectionsIgnoreOnError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		status   int
		wantType string
	}{
		{"forbidden", http.StatusForbidden, typeUnauthorized},
		{"unauthorized after refresh", http.StatusUnauthorized, typeUnauthorized},
		{"rate limited", http.StatusTooManyRequests, typeRateLimited},
		{"entitlements unavailable", http.StatusServiceUnavailable, typeUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			g := &segmentGuard{status: tt.status}
			p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
			set := streamingSettings(map[string]any{"on_error": onErrorFailOpen})
			verdict, err := p.InspectSegment(segmentTraceContext(), segmentInput(t, set),
				appplugins.StreamSegment{Seq: 1, Accumulated: "Hello world"})
			require.NoError(t, err)
			require.NotNil(t, verdict)
			assert.True(t, verdict.Block, "a deliberate engine rejection must not be left to streaming.on_error")
			assert.Equal(t, tt.wantType, verdict.Type)
		})
	}
}

func TestInspectSegmentTransportFailureIsLeftToTheCaller(t *testing.T) {
	t.Parallel()

	for _, onError := range []string{onErrorFailOpen, onErrorFailClosed} {
		t.Run(onError, func(t *testing.T) {
			t.Parallel()
			g := &segmentGuard{status: http.StatusInternalServerError}
			p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
			set := streamingSettings(map[string]any{"on_error": onError})
			verdict, err := p.InspectSegment(segmentTraceContext(), segmentInput(t, set),
				appplugins.StreamSegment{Seq: 2, Accumulated: "Hello world"})
			require.Error(t, err)
			assert.Nil(t, verdict, "the plugin never resolves a configurable failure itself")
		})
	}
}

func TestInspectSegmentPerBlockDeadline(t *testing.T) {
	t.Parallel()

	g := &segmentGuard{
		response: GuardResponse{Status: statusAllow},
		delays:   []time.Duration{10 * time.Second},
	}
	srv := newSegmentServer(t, g)
	p := New(adapter.NewRegistry(), srv.URL, testClientTimeout, "test-client", "test-secret", nil,
		withBaseTransport(testTransport(t)))
	in := segmentInput(t, streamingSettings(map[string]any{"guard_timeout": "250ms"}))
	ctx := segmentTraceContext()

	start := time.Now()
	verdict, err := p.InspectSegment(ctx, in, appplugins.StreamSegment{Seq: 1, Accumulated: "held text"})
	elapsed := time.Since(start)
	require.Error(t, err)
	assert.Nil(t, verdict)
	assert.Less(t, elapsed, 5*time.Second,
		"a block is bounded by streaming.guard_timeout, never by TRUSTGUARD_TIMEOUT")

	verdict, err = p.InspectSegment(ctx, in, appplugins.StreamSegment{Seq: 2, Accumulated: "held text and more"})
	require.NoError(t, err, "each block gets its own deadline, so a slow block does not spend the next one's")
	require.NotNil(t, verdict)
	assert.False(t, verdict.Block)
	assert.Len(t, g.calls(), 2)
}

// TestInspectSegmentDeadlineCoversTheTokenFetch is the case the evaluate-only
// deadline test cannot see: the token round trip runs before evaluate and,
// through singleflight, cancellation-free. Unbounded, a cold or expired token
// stalls the held head block for the whole client timeout.
func TestInspectSegmentDeadlineCoversTheTokenFetch(t *testing.T) {
	t.Parallel()

	g := &segmentGuard{
		response:   GuardResponse{Status: statusAllow},
		tokenDelay: 5 * time.Second,
	}
	srv := newSegmentServer(t, g)
	p := New(adapter.NewRegistry(), srv.URL, testClientTimeout, "test-client", "test-secret", nil,
		withBaseTransport(testTransport(t)))
	in := segmentInput(t, streamingSettings(map[string]any{"guard_timeout": "250ms"}))

	start := time.Now()
	verdict, err := p.InspectSegment(segmentTraceContext(), in,
		appplugins.StreamSegment{Seq: 1, Accumulated: "held text"})
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Nil(t, verdict, "a token that did not arrive in time is a failure the caller resolves")
	assert.Less(t, elapsed, 2*time.Second,
		"the token leg is bounded by streaming.guard_timeout too, not by TRUSTGUARD_TIMEOUT")
	assert.Empty(t, g.calls(), "evaluate is never reached without a token")
}

func TestInspectSegmentSkipsWithoutCallingTheGuard(t *testing.T) {
	t.Parallel()

	requestLeg := streamingSettings(nil)
	requestLeg["direction"] = legRequest

	tests := []struct {
		name     string
		settings map[string]any
		seg      appplugins.StreamSegment
	}{
		{"streaming disabled", map[string]any{"collector_id": testCollectorID},
			appplugins.StreamSegment{Seq: 1, Accumulated: "Hello world"}},
		{"policy excludes the response leg", requestLeg,
			appplugins.StreamSegment{Seq: 1, Accumulated: "Hello world"}},
		{"nothing produced yet", streamingSettings(nil), appplugins.StreamSegment{Seq: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			g := &segmentGuard{response: GuardResponse{Status: statusBlock}}
			p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
			verdict, err := p.InspectSegment(segmentTraceContext(), segmentInput(t, tt.settings), tt.seg)
			require.NoError(t, err)
			require.NotNil(t, verdict)
			assert.False(t, verdict.Block)
			assert.Empty(t, g.calls())
		})
	}
}

// TestStreamSettingsIsTheOptIn pins the half of the contract the caller cannot
// do for itself: the plugin is on every pre_response chain that names it, so
// the settings — not the type — decide whether a head gate exists, and the
// options come back with the answer so the caller never re-reads them.
func TestStreamSettingsIsTheOptIn(t *testing.T) {
	t.Parallel()
	p := newTestPlugin(t, adapter.NewRegistry(), "http://guard.local")

	requestLeg := streamingSettings(nil)
	requestLeg["direction"] = legRequest

	enabled, opts := p.StreamSettings(streamingSettings(map[string]any{
		"head_chars": 1024,
		"on_error":   onErrorFailClosed,
	}))
	assert.True(t, enabled)
	assert.Equal(t, appplugins.StreamOptions{HeadChars: 1024, OnError: onErrorFailClosed}, opts)

	inherited := streamingSettings(nil)
	inherited["on_error"] = onErrorFailClosed
	enabled, opts = p.StreamSettings(inherited)
	assert.True(t, enabled)
	assert.Equal(t, defaultStreamingHeadChars, opts.HeadChars)
	assert.Equal(t, onErrorFailClosed, opts.OnError,
		"streaming.on_error inherits the policy on_error, and the caller must be given what it inherited")

	for _, tt := range []struct {
		name     string
		settings map[string]any
	}{
		{"streaming disabled", map[string]any{"collector_id": testCollectorID}},
		{"policy excludes the response leg", requestLeg},
		{"settings that do not parse", map[string]any{"collector_id": "not-a-uuid"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			enabled, opts := p.StreamSettings(tt.settings)
			assert.False(t, enabled)
			assert.Zero(t, opts)
		})
	}
}

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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			verdict, err := segmentVerdict(tt.seg, &tt.resp)
			require.NoError(t, err)
			require.NotNil(t, verdict)
			assert.Equal(t, tt.want, *verdict)
		})
	}

	// A mask this plugin cannot apply is reported as an error here; the caller
	// resolves it by mode, cutting in a mode that blocks.
	for name, tc := range map[string]struct {
		seg  appplugins.StreamSegment
		resp GuardResponse
	}{
		"transform without a payload": {produced, GuardResponse{Status: statusTransform}},
		"transform with nothing accumulated": {toolCallOnly,
			GuardResponse{Status: statusTransform, TransformedPayload: map[string]any{"input": "[MASKED]"}}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			verdict, err := segmentVerdict(tc.seg, &tc.resp)
			require.ErrorIs(t, err, errTransformUnappliable)
			assert.Nil(t, verdict)
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
	// tokenStatus, when set, is how the token leg answers every call.
	tokenStatus int
	release     chan struct{}
	status      int
	response    GuardResponse
}

func (g *segmentGuard) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == tokenPath {
			if !g.hold(r, g.tokenDelay) {
				return
			}
			if g.tokenStatus != 0 {
				w.WriteHeader(g.tokenStatus)
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

// A 429 is the engine answering, and cuts. Rejected credentials and unavailable
// entitlements are failures of the guard and fail open, whatever streaming.on_error
// a stored policy still carries.
func TestInspectSegmentSortsAnswersFromFailures(t *testing.T) {
	t.Parallel()

	t.Run("rate limited", func(t *testing.T) {
		t.Parallel()
		g := &segmentGuard{status: http.StatusTooManyRequests}
		p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
		set := streamingSettings(map[string]any{"on_error": "fail_open"})
		verdict, err := p.InspectSegment(segmentTraceContext(), segmentInput(t, set),
			appplugins.StreamSegment{Seq: 1, Accumulated: "Hello world"})
		require.NoError(t, err)
		require.NotNil(t, verdict)
		assert.True(t, verdict.Block)
		assert.Equal(t, typeRateLimited, verdict.Type)
	})

	for name, status := range map[string]int{
		"forbidden":                  http.StatusForbidden,
		"unauthorized after refresh": http.StatusUnauthorized,
		"entitlements unavailable":   http.StatusServiceUnavailable,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			g := &segmentGuard{status: status}
			p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
			for _, stored := range []string{"fail_open", "fail_closed"} {
				set := streamingSettings(map[string]any{"on_error": stored})
				verdict, err := p.InspectSegment(segmentTraceContext(), segmentInput(t, set),
					appplugins.StreamSegment{Seq: 1, Accumulated: "Hello world"})
				require.NoError(t, err, stored)
				require.NotNil(t, verdict, stored)
				assert.False(t, verdict.Block, "a failure of the guard is not a finding and must not cut (%s)", stored)
			}
		})
	}
}

func TestInspectSegmentTransportFailureFailsOpenWhateverIsStored(t *testing.T) {
	t.Parallel()

	for _, onError := range []string{"fail_open", "fail_closed"} {
		t.Run(onError, func(t *testing.T) {
			t.Parallel()
			g := &segmentGuard{status: http.StatusInternalServerError}
			p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
			set := streamingSettings(map[string]any{"on_error": onError})
			verdict, err := p.InspectSegment(segmentTraceContext(), segmentInput(t, set),
				appplugins.StreamSegment{Seq: 2, Accumulated: "Hello world"})
			require.NoError(t, err, "a failure is resolved here, so the rest of the chain still inspects the block")
			require.NotNil(t, verdict)
			assert.False(t, verdict.Block)
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
	in := segmentInput(t, streamingSettings(map[string]any{"guard_timeout": "1ms", "on_error": "fail_closed"}))
	ctx := segmentTraceContext()

	start := time.Now()
	verdict, err := p.InspectSegment(ctx, in, appplugins.StreamSegment{Seq: 1, Accumulated: "held text"})
	elapsed := time.Since(start)
	require.NoError(t, err, "a block that runs out of time fails open")
	require.NotNil(t, verdict)
	assert.False(t, verdict.Block)
	assert.Greater(t, elapsed, 1500*time.Millisecond, "a stored guard_timeout of 1ms is ignored: the default 2s bound applies")
	assert.Less(t, elapsed, 5*time.Second,
		"a block is bounded by the default stream guard timeout, never by TRUSTGUARD_TIMEOUT")

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
	in := segmentInput(t, streamingSettings(nil))

	start := time.Now()
	verdict, err := p.InspectSegment(segmentTraceContext(), in,
		appplugins.StreamSegment{Seq: 1, Accumulated: "held text"})
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.NotNil(t, verdict, "a token that did not arrive in time is a failure that fails open")
	assert.False(t, verdict.Block)
	assert.Less(t, elapsed, 4*time.Second,
		"the token leg is bounded by the stream guard timeout too, not by TRUSTGUARD_TIMEOUT")
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
		{"streaming disabled", streamingSettings(map[string]any{"enabled": false}),
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
		"on_error":   "fail_closed",
	}))
	assert.True(t, enabled)
	assert.Equal(t, appplugins.StreamOptions{
		HeadChars:            1024,
		OnError:              "fail_open",
		MinCharsBetweenEvals: defaultStreamingMinCharsBetweenEvals,
		MaxHoldMS:            defaultStreamingMaxHoldMS,
		MaxAccumulatedBytes:  defaultStreamingMaxAccumulatedBytes,
	}, opts, "the block-loop knobs travel with the opt-in, so the caller never runs on defaults it was not given")

	stored := streamingSettings(nil)
	stored["on_error"] = "fail_closed"
	enabled, opts = p.StreamSettings(stored)
	assert.True(t, enabled)
	assert.Equal(t, defaultStreamingHeadChars, opts.HeadChars)
	assert.Equal(t, "fail_open", opts.OnError, "a stored on_error is ignored: the stream always fails open")

	// RUN-1712: a policy that says nothing about streaming is on, with the
	// defaults, because its direction already says it inspects the response.
	// Before this, the same policy streamed its responses uninspected while the
	// console told the operator both legs were covered.
	enabled, opts = p.StreamSettings(map[string]any{"collector_id": testCollectorID})
	assert.True(t, enabled, "an absent streaming block must mean on, not off")
	assert.Equal(t, defaultStreamingHeadChars, opts.HeadChars)
	assert.Equal(t, defaultStreamingMinCharsBetweenEvals, opts.MinCharsBetweenEvals)

	optedOut := streamingSettings(map[string]any{"enabled": false})

	for _, tt := range []struct {
		name     string
		settings map[string]any
	}{
		{"streaming explicitly disabled", optedOut},
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

// The aggregate is the only thing that makes a streamed block visible: without
// it a head-gate 403 publishes a plugin span carrying no guard data at all.
// It has to land exactly once, on the closing segment, and it has to survive
// every block that came before it.
func TestInspectSegmentWritesTheAggregateOnceOnClosing(t *testing.T) {
	t.Parallel()

	g := &segmentGuard{response: GuardResponse{Status: statusAllow}}
	p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
	event, span := newEvent()
	in := execInputWithEvent(policy.StagePreResponse, policy.ModeEnforce,
		streamingSettings(nil), segmentRequest(), nil, event)
	ctx := segmentTraceContext()

	for seq := 1; seq <= 3; seq++ {
		_, err := p.InspectSegment(ctx, in, appplugins.StreamSegment{
			Seq: seq, Final: seq == 3, Accumulated: "Hello world",
		})
		require.NoError(t, err)
	}
	require.Nil(t, span.PluginAttrsCopy().Extras,
		"a per-block write would be overwritten by the next block and is never made")

	verdict, err := p.InspectSegment(ctx, in, appplugins.StreamSegment{
		Seq: 3, Closing: true,
		Report: appplugins.StreamReport{
			Evals: 3, GuardCalls: 3, FinalPass: true,
			GuardLatency: 90 * time.Millisecond, GuardLatencyMax: 40 * time.Millisecond,
			AddedLatency: 130 * time.Millisecond,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, verdict)
	assert.False(t, verdict.Block, "the closing segment asks for no verdict")
	assert.Len(t, g.calls(), 3, "the closing segment never reaches the engine")

	attrs := span.PluginAttrsCopy()
	data, ok := attrs.Extras.(guardData)
	require.True(t, ok, "extras = %T, want guardData", attrs.Extras)
	require.NotNil(t, data.Streaming)
	assert.Equal(t, testStreamTraceID+streamIDSeparator+legResponse, data.Streaming.StreamID)
	assert.Equal(t, 3, data.Streaming.EvalsTotal)
	assert.Equal(t, 3, data.Streaming.GuardCalls)
	assert.True(t, data.Streaming.FinalPass)
	assert.Equal(t, int64(130), data.Streaming.AddedLatencyMs)
	assert.False(t, data.Skipped)
	assert.Equal(t, "allowed", attrs.Decision)
	assert.Equal(t, 90*time.Millisecond, span.Latency(),
		"the span latency is the chain time the client waited for, not the whole stream drain")
}

// A cut never reaches a final block, so the closing segment is the only thing
// that puts it on the event at all.
func TestInspectSegmentAggregateOnACut(t *testing.T) {
	t.Parallel()

	p := newTestPlugin(t, adapter.NewRegistry(), "")
	event, span := newEvent()
	in := execInputWithEvent(policy.StagePreResponse, policy.ModeEnforce,
		streamingSettings(nil), segmentRequest(), nil, event)

	_, err := p.InspectSegment(segmentTraceContext(), in, appplugins.StreamSegment{
		Seq: 5, Closing: true,
		Report: appplugins.StreamReport{Evals: 5, GuardCalls: 5, CutAtEval: 5, CutOffsetChars: 1840},
	})
	require.NoError(t, err)

	attrs := span.PluginAttrsCopy()
	data, ok := attrs.Extras.(guardData)
	require.True(t, ok, "extras = %T, want guardData", attrs.Extras)
	assert.Equal(t, "block", attrs.Decision)
	assert.Equal(t, 5, data.Streaming.CutAtEval)
	assert.Equal(t, 1840, data.Streaming.CutOffsetChars)
	assert.False(t, data.Streaming.FinalPass)
}

// A policy that never enabled streaming writes nothing: it is on the chain, so
// it is asked, but it has nothing to say about a stream it did not inspect.
func TestInspectSegmentClosingWritesNothingWhenStreamingIsOff(t *testing.T) {
	t.Parallel()

	p := newTestPlugin(t, adapter.NewRegistry(), "")
	event, span := newEvent()
	in := execInputWithEvent(policy.StagePreResponse, policy.ModeEnforce,
		streamingSettings(map[string]any{"enabled": false}), segmentRequest(), nil, event)

	_, err := p.InspectSegment(segmentTraceContext(), in,
		appplugins.StreamSegment{Closing: true, Report: appplugins.StreamReport{Evals: 2}})
	require.NoError(t, err)

	assert.Nil(t, span.PluginAttrsCopy().Extras)
}

// An observe-mode policy is what an operator runs to see what a policy would do
// before enabling it, so a decision it never made is the one thing its entry
// must never carry. The executor clears the cut from every entry but the one
// that made it; this pins what the console is then shown.
func TestInspectSegmentObserveModeReportsNoCutItDidNotMake(t *testing.T) {
	t.Parallel()

	p := newTestPlugin(t, adapter.NewRegistry(), "")
	event, span := newEvent()
	in := execInputWithEvent(policy.StagePreResponse, policy.ModeObserve,
		streamingSettings(nil), segmentRequest(), nil, event)

	_, err := p.InspectSegment(segmentTraceContext(), in, appplugins.StreamSegment{
		Seq: 5, Closing: true,
		Report: appplugins.StreamReport{
			Evals: 5, GuardCalls: 5, GuardLatency: 70 * time.Millisecond,
			AddedLatency: 240 * time.Millisecond,
		},
	})
	require.NoError(t, err)

	attrs := span.PluginAttrsCopy()
	data, ok := attrs.Extras.(guardData)
	require.True(t, ok, "extras = %T, want guardData", attrs.Extras)
	assert.Equal(t, "allowed", attrs.Decision,
		"an entry that cut nothing must not read as having blocked the response")
	assert.Zero(t, data.Streaming.CutAtEval)
	assert.Zero(t, data.Streaming.CutOffsetChars)
	assert.Equal(t, 5, data.Streaming.EvalsTotal,
		"what the stream cost still reaches an observing entry")
	assert.Equal(t, int64(240), data.Streaming.AddedLatencyMs)
	assert.Equal(t, 70*time.Millisecond, span.Latency(),
		"the observing entry is charged its own share of the hold")
}

func segmentInputIn(t *testing.T, mode policy.Mode) appplugins.ExecInput {
	t.Helper()
	return execInput(policy.StagePreResponse, mode, streamingSettings(nil), segmentRequest(), nil)
}

// A 413 is TrustGuard refusing the body for its size: the request's own content,
// so a mode that blocks cuts the stream, carrying the failure the executor
// records, while observe and every availability failure release the block.
func TestInspectSegmentPayloadTooLargeByMode(t *testing.T) {
	t.Parallel()

	t.Run("enforce cuts", func(t *testing.T) {
		t.Parallel()
		g := &segmentGuard{status: http.StatusRequestEntityTooLarge}
		p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
		verdict, err := p.InspectSegment(segmentTraceContext(), segmentInputIn(t, policy.ModeEnforce),
			appplugins.StreamSegment{Seq: 1, Accumulated: "Hello world"})
		require.NoError(t, err)
		require.NotNil(t, verdict)
		assert.True(t, verdict.Block)
		assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, verdict.Type)
		require.NotNil(t, verdict.Failure)
		assert.Equal(t, appplugins.FailureInputTooLarge, verdict.Failure.Reason)
		assert.Equal(t, appplugins.DetailPayloadTooLarge, verdict.Failure.Detail)
		assert.Equal(t, appplugins.FailureClassInput, verdict.Failure.Class)
	})
	t.Run("observe releases the block", func(t *testing.T) {
		t.Parallel()
		g := &segmentGuard{status: http.StatusRequestEntityTooLarge}
		p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
		verdict, err := p.InspectSegment(segmentTraceContext(), segmentInputIn(t, policy.ModeObserve),
			appplugins.StreamSegment{Seq: 1, Accumulated: "Hello world"})
		require.NoError(t, err)
		require.NotNil(t, verdict)
		assert.False(t, verdict.Block)
		assert.Nil(t, verdict.Failure)
	})
	t.Run("an availability failure releases the block in enforce", func(t *testing.T) {
		t.Parallel()
		g := &segmentGuard{status: http.StatusInternalServerError}
		p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
		verdict, err := p.InspectSegment(segmentTraceContext(), segmentInputIn(t, policy.ModeEnforce),
			appplugins.StreamSegment{Seq: 1, Accumulated: "Hello world"})
		require.NoError(t, err)
		require.NotNil(t, verdict)
		assert.False(t, verdict.Block)
	})
}

// A client padding a stream must not retire the inspection: an input failure
// never extends the run that stops this policy calling TrustGuard, where the
// same number of availability failures does.
func TestInspectSegmentInputFailuresDoNotRetireTheStream(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		status      int
		wantRetired bool
	}{
		"payload too large": {http.StatusRequestEntityTooLarge, false},
		"server error":      {http.StatusInternalServerError, true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			g := &segmentGuard{status: tc.status}
			p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
			in := segmentInputIn(t, policy.ModeObserve)
			ctx := segmentTraceContext()
			for seq := 1; seq <= streamRetireAfter+2; seq++ {
				_, err := p.InspectSegment(ctx, in, appplugins.StreamSegment{Seq: seq, Accumulated: "Hello world"})
				require.NoError(t, err)
			}
			assert.Equal(t, tc.wantRetired, p.streamRetired(ctx, in, appplugins.StreamSegment{Seq: 1, Accumulated: "x"}))
			if tc.wantRetired {
				assert.Len(t, g.calls(), streamRetireAfter)
			} else {
				assert.Len(t, g.calls(), streamRetireAfter+2)
			}
		})
	}
}

// A mask TrustGuard asked for that cannot be written into the stream is a mask
// over a confirmed finding: a mode that blocks cuts with the finding's own block
// and the failure that records it blocked and degraded; observe releases.
func TestInspectSegmentUnappliableTransformCutsInEnforce(t *testing.T) {
	t.Parallel()

	t.Run("enforce", func(t *testing.T) {
		t.Parallel()
		g := &segmentGuard{response: GuardResponse{Status: statusTransform}}
		p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
		verdict, err := p.InspectSegment(segmentTraceContext(), segmentInputIn(t, policy.ModeEnforce),
			appplugins.StreamSegment{Seq: 1, Accumulated: "Hello world"})
		require.NoError(t, err)
		require.NotNil(t, verdict)
		assert.True(t, verdict.Block)
		assert.Equal(t, typeBlocked, verdict.Type)
		assert.False(t, verdict.HasTransform)
		require.NotNil(t, verdict.Failure)
		assert.Equal(t, appplugins.DetailAnonymizeNoOutput, verdict.Failure.Detail)
	})
	t.Run("observe", func(t *testing.T) {
		t.Parallel()
		g := &segmentGuard{response: GuardResponse{Status: statusTransform}}
		p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
		verdict, err := p.InspectSegment(segmentTraceContext(), segmentInputIn(t, policy.ModeObserve),
			appplugins.StreamSegment{Seq: 1, Accumulated: "Hello world"})
		require.NoError(t, err)
		require.NotNil(t, verdict)
		assert.False(t, verdict.Block)
	})
}

// The closing write of a cut that is a failure: an input failure is failed_closed,
// a mask over a finding stays blocked and degraded in the plugin's own words.
func TestInspectSegmentClosingRecordsACutThatIsAFailure(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		report       appplugins.StreamReport
		wantDecision string
		wantReason   string
		wantDegraded string
	}{
		"payload too large": {
			report: appplugins.StreamReport{Evals: 2, CutAtEval: 2, CutOnFailure: true,
				FailureReason: appplugins.FailureInputTooLarge, FailureDetail: appplugins.DetailPayloadTooLarge,
				FailureClass: appplugins.FailureClassInput},
			wantDecision: decisionFailedClosed, wantReason: failureReasonPayloadTooLarge,
		},
		"mask over a finding": {
			report: appplugins.StreamReport{Evals: 2, CutAtEval: 2, CutOnFailure: true,
				FailureReason: appplugins.FailureVerdictIncomplete, FailureDetail: appplugins.DetailAnonymizeNoOutput,
				FailureClass: appplugins.FailureClassInput},
			wantDecision: decisionBlocked, wantReason: failureReasonTransformFailed, wantDegraded: reasonTransformNoPayload,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p := newTestPlugin(t, adapter.NewRegistry(), "")
			event, span := newEvent()
			in := execInputWithEvent(policy.StagePreResponse, policy.ModeEnforce, streamingSettings(nil), segmentRequest(), nil, event)

			_, err := p.InspectSegment(segmentTraceContext(), in, appplugins.StreamSegment{Seq: 2, Closing: true, Report: tc.report})
			require.NoError(t, err)

			data, ok := span.PluginAttrsCopy().Extras.(guardData)
			require.True(t, ok)
			assert.Equal(t, tc.wantDecision, data.Decision)
			assert.Equal(t, tc.wantReason, data.FailureReason)
			assert.Equal(t, "input", data.FailureClass)
			assert.Equal(t, tc.wantDegraded != "", data.Degraded)
			assert.Equal(t, tc.wantDegraded, data.DegradedReason)
			assert.False(t, data.FailedOpen)
		})
	}
}

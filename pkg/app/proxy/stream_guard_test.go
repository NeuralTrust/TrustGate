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

package proxy

import (
	"context"
	"errors"
	"io"
	"iter"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newGuardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// scriptedRunner calls probe at the instant it is consulted, so a test can
// assert what the guard had cleared before the verdict and not only after it.
type scriptedRunner struct {
	outcome *appplugins.SegmentOutcome
	err     error
	latency time.Duration
	probe   func()

	calls    int
	segments []appplugins.StreamSegment
	stages   []policy.Stage
	// closings captures the segments that ask for no verdict, so calls and
	// segments keep meaning "blocks the guard wanted inspected" and the
	// single-write guarantee is assertable as len(closings) == 1.
	closings []appplugins.StreamSegment
}

func (r *scriptedRunner) RunStreamSegment(
	_ context.Context,
	in appplugins.StageInput,
	seg appplugins.StreamSegment,
) (*appplugins.SegmentOutcome, error) {
	if seg.Closing {
		r.closings = append(r.closings, seg)
		return &appplugins.SegmentOutcome{}, nil
	}
	r.calls++
	r.segments = append(r.segments, seg)
	r.stages = append(r.stages, in.Stage)
	if r.probe != nil {
		r.probe()
	}
	if r.latency > 0 {
		time.Sleep(r.latency)
	}
	return r.outcome, r.err
}

func stageInputFixture() appplugins.StageInput {
	return appplugins.StageInput{
		Stage:    policy.StagePreResponse,
		Request:  &infracontext.RequestContext{Provider: "openai"},
		Response: &infracontext.ResponseContext{},
	}
}

// checkInvariant asserts releasedIdx <= clearedIdx <= len(produced). It uses
// assert rather than require because it also runs inside the pull coroutine
// that drives the source, where FailNow would abort the wrong goroutine.
func checkInvariant(t *testing.T, g *streamGuard) {
	t.Helper()
	assert.LessOrEqual(t, g.releasedIdx, g.clearedIdx, "released ran past cleared")
	assert.LessOrEqual(t, g.clearedIdx, len(g.produced), "cleared ran past produced")
}

func invariantSource(t *testing.T, g *streamGuard, lines []string, srcErr error) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		for _, line := range lines {
			checkInvariant(t, g)
			if !yield([]byte(line), nil) {
				return
			}
		}
		checkInvariant(t, g)
		if srcErr != nil {
			yield(nil, srcErr)
		}
	}
}

func collectGuardOutput(t *testing.T, g *streamGuard, out iter.Seq2[[]byte, error]) ([]string, error) {
	t.Helper()
	var got []string
	var seen error
	for line, err := range out {
		checkInvariant(t, g)
		if err != nil {
			seen = err
			continue
		}
		got = append(got, string(line))
	}
	checkInvariant(t, g)
	return got, seen
}

func openAIStreamLines() []string {
	return []string{
		`data: {"id":"c1","model":"gpt-5","choices":[{"index":0,"delta":{"role":"assistant"}}]}`, "",
		`data: {"id":"c1","choices":[{"index":0,"delta":{"content":"Hello"}}]}`, "",
		`data: {"id":"c1","choices":[{"index":0,"delta":{"content":" world"}}]}`, "",
		`data: {"id":"c1","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`, "",
		`data: {"id":"c1","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}`, "",
		"data: [DONE]", "",
	}
}

func anthropicStreamLines() []string {
	return []string{
		"event: message_start",
		`data: {"type":"message_start","message":{"id":"msg_1","model":"claude-sonnet-4"}}`, "",
		"event: content_block_delta",
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hola"}}`, "",
		"event: message_stop",
		`data: {"type":"message_stop"}`, "",
	}
}

type guardCase struct {
	name          string
	format        adapter.Format
	lines         []string
	srcErr        error
	failCodec     bool
	cfg           streamGuardConfig
	outcome       *appplugins.SegmentOutcome
	runErr        error
	latency       time.Duration
	wantCalls     int
	wantBlocked   bool
	wantBodyIsSet bool
	wantOut       []string
	wantAccum     string
	wantFinal     bool
}

func guardCases() []guardCase {
	return []guardCase{
		{
			name:      "clean head releases the whole stream",
			format:    adapter.FormatOpenAI,
			lines:     openAIStreamLines(),
			latency:   2 * time.Millisecond,
			wantCalls: 1,
			wantOut:   openAIStreamLines(),
			wantAccum: "Hello world",
			wantFinal: true,
		},
		{
			name:      "head closes on head_chars and the tail passes through",
			format:    adapter.FormatOpenAI,
			lines:     openAIStreamLines(),
			cfg:       streamGuardConfig{headChars: 3},
			wantCalls: 1,
			wantOut:   openAIStreamLines(),
			wantAccum: "Hello",
		},
		{
			name:      "response shorter than head_chars is inspected once, as final",
			format:    adapter.FormatOpenAI,
			lines:     []string{`data: {"id":"c","choices":[{"index":0,"delta":{"content":"ok"}}]}`, ""},
			wantCalls: 1,
			wantOut:   []string{`data: {"id":"c","choices":[{"index":0,"delta":{"content":"ok"}}]}`, ""},
			wantAccum: "ok",
			wantFinal: true,
		},
		{
			name:        "head-gate block writes nothing",
			format:      adapter.FormatOpenAI,
			lines:       openAIStreamLines(),
			outcome:     &appplugins.SegmentOutcome{Block: true, Type: "guardrail_violation", Message: "nope"},
			wantCalls:   1,
			wantBlocked: true,
		},
		{
			// A masking policy must not become a no-op on a streamed response.
			// A verdict that leaves the accumulated buffer byte-identical
			// masked something the buffer does not carry, so there is nothing
			// for the guard to rewrite and releasing the head would release the
			// flagged content unmasked.
			name:        "a transform the buffer does not carry escalates instead of releasing unmasked text",
			format:      adapter.FormatOpenAI,
			lines:       openAIStreamLines(),
			outcome:     &appplugins.SegmentOutcome{HasTransform: true, Transformed: "Hello world"},
			wantCalls:   1,
			wantBlocked: true,
		},
		{
			name:          "a blocked head speaks the caller's dialect",
			format:        adapter.FormatAnthropic,
			lines:         anthropicStreamLines(),
			outcome:       &appplugins.SegmentOutcome{Block: true, Message: "nope"},
			wantCalls:     1,
			wantBlocked:   true,
			wantBodyIsSet: true,
		},
		{
			name:      "fail_open releases the head when the guard call fails",
			format:    adapter.FormatOpenAI,
			lines:     openAIStreamLines(),
			runErr:    errors.New("guard timeout"),
			cfg:       streamGuardConfig{onError: streamFailOpen},
			wantCalls: 1,
			wantOut:   openAIStreamLines(),
			wantAccum: "Hello world",
			wantFinal: true,
		},
		{
			name:        "fail_closed blocks when the guard call fails",
			format:      adapter.FormatOpenAI,
			lines:       openAIStreamLines(),
			runErr:      errors.New("guard timeout"),
			cfg:         streamGuardConfig{onError: streamFailClosed},
			wantCalls:   1,
			wantBlocked: true,
		},
		{
			name:      "a classification failure still releases the event's lines",
			format:    adapter.FormatOpenAI,
			lines:     openAIStreamLines(),
			failCodec: true,
			wantCalls: 1,
			wantOut:   openAIStreamLines(),
			wantFinal: true,
		},
		{
			name:      "an undecodable head holds nothing back on a multi-line dialect",
			format:    adapter.FormatAnthropic,
			lines:     anthropicStreamLines(),
			failCodec: true,
			wantCalls: 1,
			wantOut:   anthropicStreamLines(),
			wantFinal: true,
		},
	}
}

func TestStreamGuard_HeadGate(t *testing.T) {
	t.Parallel()
	for _, tc := range guardCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runner := &scriptedRunner{outcome: tc.outcome, err: tc.runErr, latency: tc.latency}
			var codec guardCodec = adapter.NewRegistry()
			if tc.failCodec {
				codec = failingCodec{}
			}
			g := newStreamGuard(runner, codec, tc.format, stageInputFixture(), tc.cfg, newGuardLogger())
			runner.probe = func() { checkInvariant(t, g) }

			out, pe := g.Run(context.Background(), invariantSource(t, g, tc.lines, tc.srcErr))
			checkInvariant(t, g)
			require.Equal(t, tc.wantCalls, runner.calls)

			if tc.wantBlocked {
				require.NotNil(t, pe)
				require.Equal(t, http.StatusForbidden, pe.StatusCode)
				require.Equal(t, tc.wantBodyIsSet, pe.Body != nil)
				require.Zero(t, g.releasedIdx, "a head-gate block must have written nothing")
				drained, _ := collectGuardOutput(t, g, out)
				require.Zero(t, g.releasedIdx, "draining the remainder must not release held events")
				require.NotContains(t, drained, tc.lines[0], "the head must never reach the client")
				return
			}

			require.Nil(t, pe)
			got, err := collectGuardOutput(t, g, out)
			require.NoError(t, err)
			require.Equal(t, tc.wantOut, got, "released lines must reproduce the source byte for byte")
			require.Equal(t, g.clearedIdx, g.releasedIdx, "a fully consumed stream releases everything it cleared")

			if tc.wantCalls > 0 {
				seg := runner.segments[0]
				require.Equal(t, 1, seg.Seq)
				require.Equal(t, tc.wantAccum, seg.Accumulated)
				require.Equal(t, seg.Text, seg.Accumulated, "the head block and the cumulative prefix are the same text")
				require.Equal(t, tc.wantFinal, seg.Final)
				require.Equal(t, policy.StagePreResponse, runner.stages[0])
			}
		})
	}
}

// TestStreamGuard_PreludeIsClearedWithoutHoldingTheVerdict pins the fast-path.
// An opaque event that opens a block carries no inspectable text, so it is
// counted as cleared while the block still has no text and a wholly opaque
// head needs no guard call at all. Cleared is not released: the event reaches
// the client in replay, strictly after the verdict, like every other one.
func TestStreamGuard_PreludeIsClearedWithoutHoldingTheVerdict(t *testing.T) {
	t.Parallel()
	runner := &scriptedRunner{}
	g := newStreamGuard(runner, adapter.NewRegistry(), adapter.FormatAnthropic, stageInputFixture(),
		streamGuardConfig{}, newGuardLogger())

	var clearedAtCall, producedAtCall, releasedAtCall int
	runner.probe = func() {
		clearedAtCall, producedAtCall, releasedAtCall = g.clearedIdx, len(g.produced), g.releasedIdx
		checkInvariant(t, g)
	}
	_, pe := g.Run(context.Background(), invariantSource(t, g, anthropicStreamLines(), nil))

	require.Nil(t, pe)
	require.Equal(t, 1, clearedAtCall, "the message_start event is cleared before the verdict")
	require.Equal(t, 3, producedAtCall)
	require.Zero(t, releasedAtCall, "cleared is not released: nothing reaches the client before the verdict")
	require.Equal(t, unitOpaque, g.produced[0].unit)
}

// TestStreamGuard_TerminalIsHeldBehindTheVerdict pins the other half: without
// it the client reaches end-of-stream before the last text has cleared.
func TestStreamGuard_TerminalIsHeldBehindTheVerdict(t *testing.T) {
	t.Parallel()
	runner := &scriptedRunner{}
	g := newStreamGuard(runner, adapter.NewRegistry(), adapter.FormatOpenAI, stageInputFixture(),
		streamGuardConfig{}, newGuardLogger())

	var clearedAtCall, producedAtCall int
	runner.probe = func() {
		clearedAtCall, producedAtCall = g.clearedIdx, len(g.produced)
	}
	_, pe := g.Run(context.Background(), invariantSource(t, g, openAIStreamLines(), nil))

	require.Nil(t, pe)
	require.Equal(t, unitTerminal, g.produced[producedAtCall-1].unit)
	require.Less(t, clearedAtCall, producedAtCall, "the terminal event must still be held at the verdict")
}

// TestStreamGuard_SourceErrorReachesTheClientAfterTheHead keeps a mid-stream
// error on the wire: it is terminal by convention, but the text it follows has
// still been verified and must still be written.
func TestStreamGuard_SourceErrorReachesTheClientAfterTheHead(t *testing.T) {
	t.Parallel()
	runner := &scriptedRunner{}
	lines := []string{`data: {"id":"c","choices":[{"index":0,"delta":{"content":"half"}}]}`, ""}
	g := newStreamGuard(runner, adapter.NewRegistry(), adapter.FormatOpenAI, stageInputFixture(),
		streamGuardConfig{}, newGuardLogger())

	upstream := errors.New("upstream stream terminated")
	out, pe := g.Run(context.Background(), invariantSource(t, g, lines, upstream))

	require.Nil(t, pe)
	got, err := collectGuardOutput(t, g, out)
	require.ErrorIs(t, err, upstream)
	require.Equal(t, lines, got)
	require.True(t, runner.segments[0].Final, "an aborted stream has no later block")
}

// TestStreamGuard_ToolCallArgumentsAreWholeBySegment proves the guard reads the
// arguments a tool call was streamed in, not the fragments they arrived as.
func TestStreamGuard_ToolCallArgumentsAreWholeBySegment(t *testing.T) {
	t.Parallel()
	runner := &scriptedRunner{}
	lines := []string{
		"event: response.function_call_arguments.delta",
		`data: {"type":"response.function_call_arguments.delta","output_index":0,"delta":"{\"city\":"}`, "",
		"event: response.function_call_arguments.delta",
		`data: {"type":"response.function_call_arguments.delta","output_index":0,"delta":"\"Paris\"}"}`, "",
		"event: response.completed",
		`data: {"type":"response.completed","response":{"id":"resp_2","model":"gpt-5"}}`, "",
	}
	g := newStreamGuard(runner, adapter.NewRegistry(), adapter.FormatOpenAIResponses, stageInputFixture(),
		streamGuardConfig{}, newGuardLogger())

	out, pe := g.Run(context.Background(), invariantSource(t, g, lines, nil))
	require.Nil(t, pe)
	got, err := collectGuardOutput(t, g, out)
	require.NoError(t, err)
	require.Equal(t, lines, got)

	calls := runner.segments[0].ToolCalls
	require.Len(t, calls, 1)
	require.Equal(t, `{"city":"Paris"}`, calls[0].Arguments)
}

// TestStreamGuard_HeadStopsAtTheHeldBytesCeiling pins the byte ceiling. On a
// stream the codec cannot decode, chars never advances, so head_chars alone
// never closes the block: without the ceiling the head would hold the whole
// response on the live request path and TTFB would become full generation
// time. The stream still reaches the client byte for byte.
func TestStreamGuard_HeadStopsAtTheHeldBytesCeiling(t *testing.T) {
	t.Parallel()
	filler := `data: {"pad":"` + strings.Repeat("a", 8<<10) + `"}`
	lines := make([]string, 0, 2*128)
	for range 128 {
		lines = append(lines, filler, "")
	}
	require.Greater(t, len(filler)*128, 3*maxHeadHeldBytes, "the source must outrun the ceiling by a wide margin")

	runner := &scriptedRunner{}
	g := newStreamGuard(runner, failingCodec{}, adapter.FormatOpenAI, stageInputFixture(),
		streamGuardConfig{}, newGuardLogger())

	out, pe := g.Run(context.Background(), invariantSource(t, g, lines, nil))
	require.Nil(t, pe)
	require.Zero(t, g.chars, "an undecodable stream yields no inspectable text, so head_chars can never close the block")
	require.LessOrEqual(t, g.held, maxHeadHeldBytes+len(filler),
		"the ceiling is tested before each pull, so it is exceeded by at most one line")
	require.False(t, g.terminal)
	require.False(t, g.exhausted, "the head must stop long before the end of the source")

	got, err := collectGuardOutput(t, g, out)
	require.NoError(t, err)
	require.Equal(t, lines, got)
}

func TestStreamGuardConfig_Defaults(t *testing.T) {
	t.Parallel()
	cfg := streamGuardConfig{}.withDefaults()
	require.Equal(t, defaultHeadChars, cfg.headChars)
	require.Equal(t, streamFailOpen, cfg.onError, "the head inherits the policy default, which is fail_open")

	closed := streamGuardConfig{headChars: 16, onError: streamFailClosed}.withDefaults()
	require.Equal(t, 16, closed.headChars)
	require.Equal(t, streamFailClosed, closed.onError)
}

// fakeStreamClock advances a fixed step on every read, so block cadence is a
// function of the event count and never of how fast the machine running the
// test happens to be.
type fakeStreamClock struct {
	now  time.Time
	step time.Duration
}

func (c *fakeStreamClock) Now() time.Time {
	c.now = c.now.Add(c.step)
	return c.now
}

// flakyCodec decodes a fixed number of chunks and then fails, so a
// classification failure can be placed inside the block loop rather than at
// the head gate.
type flakyCodec struct {
	inner guardCodec
	ok    int
}

func (c *flakyCodec) EncodeStreamChunkFor(
	canonical *adapter.CanonicalStreamChunk,
	source adapter.Format,
) ([][]byte, error) {
	return c.inner.EncodeStreamChunkFor(canonical, source)
}

func (c *flakyCodec) DecodeStreamChunkFor(
	chunk []byte,
	target adapter.Format,
) (*adapter.CanonicalStreamChunk, error) {
	if c.ok > 0 {
		c.ok--
		return c.inner.DecodeStreamChunkFor(chunk, target)
	}
	return nil, errors.New("codec rejected the chunk")
}

func textStreamLines(chunks ...string) []string {
	lines := make([]string, 0, 2*len(chunks)+2)
	for _, chunk := range chunks {
		lines = append(lines, `data: {"id":"c1","choices":[{"index":0,"delta":{"content":"`+chunk+`"}}]}`, "")
	}
	return append(lines, "data: [DONE]", "")
}

// loopGuard builds a guard whose head closes on the first text event, so every
// case below exercises the block loop rather than the gate B5 already covers.
func loopGuard(t *testing.T, runner segmentRunner, codec guardCodec, cfg streamGuardConfig) *streamGuard {
	t.Helper()
	cfg.headChars = 1
	return newStreamGuard(runner, codec, adapter.FormatOpenAI, stageInputFixture(), cfg, newGuardLogger())
}

// recordAdmitted snapshots, at the instant each call is consulted, the text of
// every event the guard had admitted by then. That is the axis the prefix
// assertion cannot see on its own, and the one the evasion hole in spike §5.1b
// lives on: released text is always a byte-prefix of produced text, so a
// payload rebuilt from produced[:releasedIdx] satisfies HasPrefix on every
// consecutive pair while lagging a whole block behind what the guard has read.
func recordAdmitted(g *streamGuard, runner *scriptedRunner) *[]string {
	admitted := new([]string)
	inner := runner.probe
	runner.probe = func() {
		var produced strings.Builder
		for _, ev := range g.produced {
			produced.WriteString(ev.text)
		}
		*admitted = append(*admitted, produced.String())
		if inner != nil {
			inner()
		}
	}
	return admitted
}

// assertContiguousPrefixes is the regression guard for the evasion hole in
// spike §5.1b. admitted[i] is the text of every event the guard had admitted
// when call i+1 was issued.
//
// The prefix pair alone does not guard this. It closes the sliding-window
// mutation, but a payload accumulated from released rather than produced text
// passes it untouched, because released text is a byte-prefix of produced text
// by construction — so the pair holds on every call while the payload lags a
// block behind and a finding split across the block in flight and the block
// being inspected is read by no call at all. The equality against admitted is
// what closes that axis; the last one states it for the whole stream.
//
// Two things cannot be combined with this, and both are by design rather than
// defects. The cap is the first: once window returns a tail, payload[i] stops
// being a prefix of payload[i+1] and the payload stops being everything
// admitted — overlapping tails still expose cross-block findings within
// max_accumulated_bytes, which is what Truncated and degraded_reason:
// accumulation_cap announce. A transform rewrite is the second: it replaces
// text already carried by an earlier payload, so the buffer the next call
// accumulates onto is not an extension of the last one but a correction of it,
// which is the whole point of masking in place. Each gets a guard clause, so a
// test that combines them gets a message here rather than an unexplained
// failure.
func assertContiguousPrefixes(
	t *testing.T,
	segs []appplugins.StreamSegment,
	admitted []string,
	rewritten bool,
) {
	t.Helper()
	require.NotEmpty(t, segs)
	require.False(t, rewritten, "prefix contiguity does not survive a transform rewrite")
	require.Len(t, admitted, len(segs), "one admitted snapshot per guard call")
	for i := range segs {
		require.Equal(t, i+1, segs[i].Seq, "seq must number the calls in order")
		require.False(t, segs[i].Truncated, "prefix contiguity does not survive the cap")
		require.Equal(t, admitted[i], segs[i].Accumulated,
			"payload %d omits text the guard had already admitted when it was issued", i+1)
		if i == 0 {
			continue
		}
		require.True(t, strings.HasPrefix(segs[i].Accumulated, segs[i-1].Accumulated),
			"payload %d is not a contiguous prefix of payload %d", i, i+1)
	}
	last := len(segs) - 1
	require.Equal(t, admitted[last], segs[last].Accumulated,
		"the last payload must carry the whole produced text, not the text released before it")
}

// TestStreamGuard_BlockLoopCadenceAndOrderedRelease pins the three properties
// that make the loop a loop: the clock closes blocks, the payload grows as a
// contiguous prefix, and the wire is reproduced byte for byte in arrival
// order. With maxHold at three clock steps the gate closes every third event.
func TestStreamGuard_BlockLoopCadenceAndOrderedRelease(t *testing.T) {
	t.Parallel()
	lines := textStreamLines("a1", "b2", "c3", "d4", "e5", "f6", "g7")
	runner := &scriptedRunner{}
	clock := &fakeStreamClock{step: 100 * time.Millisecond}
	g := loopGuard(t, runner, adapter.NewRegistry(), streamGuardConfig{
		minChars: 1 << 20,
		maxHold:  300 * time.Millisecond,
	})
	g.now = clock.Now
	runner.probe = func() { checkInvariant(t, g) }
	admitted := recordAdmitted(g, runner)

	out, pe := g.Run(context.Background(), invariantSource(t, g, lines, nil))
	require.Nil(t, pe)
	got, err := collectGuardOutput(t, g, out)
	require.NoError(t, err)
	require.Equal(t, lines, got, "released lines must reproduce the source byte for byte, in order")
	require.Equal(t, len(g.produced), g.releasedIdx, "a clean stream releases everything it produced")

	require.Equal(t, 4, runner.calls, "the head, two clock-closed blocks and the terminal block")
	assertContiguousPrefixes(t, runner.segments, *admitted, false)
	require.Equal(t, []string{"a1", "b2c3d4", "e5f6g7", ""}, blockDeltas(runner.segments))
	require.Equal(t, "a1b2c3d4e5f6g7", runner.segments[3].Accumulated)
}

func blockDeltas(segs []appplugins.StreamSegment) []string {
	out := make([]string, 0, len(segs))
	for _, seg := range segs {
		out = append(out, seg.Text)
	}
	return out
}

// openAIMultiChoiceStreamLines is what n>1 looks like on the wire: one
// finish-reason chunk per choice and no data: [DONE] at all, so the stream
// carries three terminal events and the latch never sees the sentinel that
// makes the two-terminal case obvious.
func openAIMultiChoiceStreamLines() []string {
	return []string{
		`data: {"id":"c1","choices":[{"index":0,"delta":{"content":"Hello"}}]}`, "",
		`data: {"id":"c1","choices":[{"index":1,"delta":{"content":"Hola"}}]}`, "",
		`data: {"id":"c1","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`, "",
		`data: {"id":"c1","choices":[{"index":1,"delta":{},"finish_reason":"stop"}]}`, "",
		`data: {"id":"c1","choices":[{"index":2,"delta":{},"finish_reason":"stop"}]}`, "",
	}
}

// TestStreamGuard_FinalityIsLatchedAcrossRepeatedTerminals pins B7.1's second
// half. unitTerminal is neither unique per stream nor per choice: OpenAI emits
// the finish-reason chunk and then data: [DONE], and with n>1 it emits one
// finish-reason chunk per choice — three terminals on a stream a client reads
// without any [DONE] semantics at all. The later terminal events must still
// reach the client, but they open no second final segment and cost no second
// call.
func TestStreamGuard_FinalityIsLatchedAcrossRepeatedTerminals(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		lines     []string
		wantAccum string
	}{
		{
			name:      "the finish-reason chunk and then data: [DONE]",
			lines:     openAIStreamLines(),
			wantAccum: "Hello world",
		},
		{
			name:      "n>1 emits one finish-reason chunk per choice",
			lines:     openAIMultiChoiceStreamLines(),
			wantAccum: "HelloHola",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runner := &scriptedRunner{}
			clock := &fakeStreamClock{step: 100 * time.Millisecond}
			g := loopGuard(t, runner, adapter.NewRegistry(), streamGuardConfig{
				minChars: 1 << 20,
				maxHold:  time.Hour,
			})
			g.now = clock.Now
			admitted := recordAdmitted(g, runner)

			out, pe := g.Run(context.Background(), invariantSource(t, g, tc.lines, nil))
			require.Nil(t, pe)
			got, err := collectGuardOutput(t, g, out)
			require.NoError(t, err)
			require.Equal(t, tc.lines, got, "every terminal event still reaches the client")

			require.Equal(t, 2, runner.calls, "a later terminal event opens no second segment")
			finals := 0
			for _, seg := range runner.segments {
				if seg.Final {
					finals++
				}
			}
			require.Equal(t, 1, finals, "Final is latched once per stream")
			require.True(t, runner.segments[1].Final)
			require.Equal(t, tc.wantAccum, runner.segments[1].Accumulated)
			assertContiguousPrefixes(t, runner.segments, *admitted, false)
		})
	}
}

// TestStreamGuard_AccumulationCapWindowsOnARuneBoundary pins B7.4. Above the
// cap the payload stops being the whole prefix, so it must say so — and it
// must never open mid-character, which a plain byte cut of CJK text does on
// two bytes out of three.
func TestStreamGuard_AccumulationCapWindowsOnARuneBoundary(t *testing.T) {
	t.Parallel()
	lines := textStreamLines("日本語", "日本語", "日本語", "日本語")
	runner := &scriptedRunner{}
	g := loopGuard(t, runner, adapter.NewRegistry(), streamGuardConfig{
		minChars:      1,
		maxAccumBytes: 10,
	})

	out, pe := g.Run(context.Background(), invariantSource(t, g, lines, nil))
	require.Nil(t, pe)
	got, err := collectGuardOutput(t, g, out)
	require.NoError(t, err)
	require.Equal(t, lines, got, "a capped payload degrades the inspection, never the wire")

	require.Equal(t, degradeAccumulationCap, g.degradedReason, "the degrade is recorded, never silent")
	truncated := 0
	for i, seg := range runner.segments {
		require.LessOrEqual(t, payloadBytes(seg), 10, "payload %d exceeded the cap", i)
		require.True(t, utf8.ValidString(seg.Accumulated), "payload %d opens mid-rune", i)
		if seg.Truncated {
			truncated++
			require.True(t, strings.HasSuffix("日本語日本語日本語日本語", seg.Accumulated),
				"a capped payload is the tail of the produced text")
		}
	}
	require.Positive(t, truncated, "the envelope must carry the truncation the engine cannot infer")
	require.Equal(t, maxAccumulatedCeiling,
		streamGuardConfig{maxAccumBytes: 4 << 20}.withDefaults().maxAccumBytes,
		"no configuration may send more than 1 MiB: the engine's detectAll returns nil above it, silently")
}

// payloadBytes is everything one call puts in front of the engine.
// segmentPayload folds the three fields into a single CanonicalResponse, so
// this sum, not any one field, is what max_accumulated_bytes has to bound.
func payloadBytes(seg appplugins.StreamSegment) int {
	n := len(seg.Accumulated) + len(seg.Reasoning)
	for _, call := range seg.ToolCalls {
		n += len(call.Arguments)
	}
	return n
}

// TestStreamGuard_AccumulationCapIsASumAcrossThePayload is the other half of
// B7.4's AC, and the one a per-field cap silently fails. The text, the
// reasoning and every tool call reach the engine as one CanonicalResponse, so
// capping each field on its own — and tool calls not at all — bounds nothing:
// at max_accumulated_bytes' own configuration ceiling a reasoning model sends
// 2 MiB, and at the 256 KiB default an agentic stream crosses 1 MiB on
// arguments alone. Above 1 MiB detectAll returns nil and says nothing, so the
// payload is never inspected and the response looks clean.
func TestStreamGuard_AccumulationCapIsASumAcrossThePayload(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		text      int
		reasoning int
		arguments []int
	}{
		{
			name:      "a reasoning model at the configuration ceiling",
			text:      1 << 20,
			reasoning: 1 << 20,
		},
		{
			name:      "an agentic stream whose tool calls carry the bulk",
			text:      4 << 10,
			arguments: []int{600 << 10, 600 << 10},
		},
		{
			name:      "all three at once",
			text:      1 << 20,
			reasoning: 1 << 20,
			arguments: []int{1 << 20, 1 << 20},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := newStreamGuard(&scriptedRunner{}, adapter.NewRegistry(), adapter.FormatOpenAI,
				stageInputFixture(), streamGuardConfig{maxAccumBytes: maxAccumulatedCeiling}, newGuardLogger())
			g.text.WriteString(strings.Repeat("a", tc.text))
			g.reasoning.WriteString(strings.Repeat("r", tc.reasoning))
			for i, n := range tc.arguments {
				g.tools.merge([]adapter.StreamToolCallDelta{
					{Index: i, Name: "lookup", ArgumentsDelta: strings.Repeat("x", n)},
				})
			}

			seg := g.nextSegment()

			require.LessOrEqual(t, payloadBytes(seg), maxAccumulatedCeiling,
				"the whole payload is what the engine's 1 MiB silence measures, not one field of it")
			require.True(t, seg.Truncated, "the envelope must carry the truncation the engine cannot infer")
			require.Equal(t, degradeAccumulationCap, g.degradedReason, "the degrade is recorded, never silent")
			require.NotEmpty(t, seg.Accumulated, "the produced text is never starved to make room for the rest")
			require.True(t, strings.HasSuffix(g.text.String(), seg.Accumulated),
				"a capped payload is the tail of the produced text")
			require.Len(t, seg.ToolCalls, len(tc.arguments))
			for i, call := range seg.ToolCalls {
				require.NotEmpty(t, call.Arguments, "tool call %d was starved to nothing", i)
			}
		})
	}
}

// TestStreamGuard_ThreeConsecutiveFailuresRetireTheLoop pins B7.5. fail_open
// releases each failed block, and once the guard has failed three times in a
// row the loop stops paying the latency: it releases everything and leaves the
// audit to the buffered post_response pass.
func TestStreamGuard_ThreeConsecutiveFailuresRetireTheLoop(t *testing.T) {
	t.Parallel()
	lines := textStreamLines("a1", "b2", "c3", "d4", "e5")
	runner := &scriptedRunner{err: errors.New("guard timeout")}
	g := loopGuard(t, runner, adapter.NewRegistry(), streamGuardConfig{
		minChars: 1,
		onError:  streamFailOpen,
	})

	out, pe := g.Run(context.Background(), invariantSource(t, g, lines, nil))
	require.Nil(t, pe)
	got, err := collectGuardOutput(t, g, out)
	require.NoError(t, err)
	require.Equal(t, lines, got, "fail_open keeps streaming")

	require.Equal(t, maxConsecutiveFailures, runner.calls, "the loop stops calling after three failures in a row")
	require.Equal(t, degradeGuardTimeout, g.degradedReason)
	require.Equal(t, fallbackSegmentationUnavail, g.fallbackReason)
	require.Equal(t, len(g.produced), g.releasedIdx)
}

// TestStreamGuard_DisconnectStopsCalling pins B7.6. There is no cancellation
// on disconnect — c.UserContext() is not cancelled and fasthttp's
// RequestCtx.Done() fires only on shutdown — so propagation is pull-based and
// the assertion is that no further call is issued, not that one is cancelled.
//
// The consumer is pulled past two block boundaries before it leaves, so the
// loop is demonstrably running and issuing calls when it does. Leaving inside
// the head's own release instead would prove nothing about B7.6: flush would
// return false before blockLoop was ever entered, and the call count would
// hold because the loop never ran.
func TestStreamGuard_DisconnectStopsCalling(t *testing.T) {
	t.Parallel()
	runner := &scriptedRunner{}
	g := loopGuard(t, runner, adapter.NewRegistry(), streamGuardConfig{minChars: 1})

	out, pe := g.Run(context.Background(), invariantSource(t, g, textStreamLines("a1", "b2", "c3", "d4", "e5"), nil))
	require.Nil(t, pe)
	require.Equal(t, 1, runner.calls, "only the head call has been issued so far")

	// Two lines per event: the head's own release, then the two blocks the
	// loop closed and cleared after it, so the consumer leaves mid-release of
	// the third with d4 and e5 still unpulled.
	const pullUntil = 6
	pulled := 0
	for range out {
		pulled++
		if pulled == pullUntil {
			break
		}
	}
	require.Equal(t, pullUntil, pulled)

	require.Equal(t, 3, runner.calls,
		"the head and one call per block the loop closed, and none for what the consumer never pulled")
	require.Less(t, g.releasedIdx, len(g.produced), "the consumer left with the stream unfinished")
	require.False(t, g.final(), "the loop stopped well before the terminal event")
}

// TestStreamGuard_ACancelledParentRetiresTheLoop is the other half of B7.6:
// the per-stream context is checked immediately before each call, so a
// request whose context is already gone releases what it holds instead of
// spending a round trip on a verdict nobody will read.
func TestStreamGuard_ACancelledParentRetiresTheLoop(t *testing.T) {
	t.Parallel()
	lines := textStreamLines("a1", "b2", "c3")
	runner := &scriptedRunner{}
	g := loopGuard(t, runner, adapter.NewRegistry(), streamGuardConfig{minChars: 1})

	ctx, cancel := context.WithCancel(context.Background())
	out, pe := g.Run(ctx, invariantSource(t, g, lines, nil))
	require.Nil(t, pe)
	cancel()

	got, err := collectGuardOutput(t, g, out)
	require.NoError(t, err)
	require.Equal(t, lines, got)
	require.Equal(t, 1, runner.calls, "only the head call, issued before the cancellation")
	require.Equal(t, fallbackClientDisconnected, g.fallbackReason)
}

// TestStreamGuard_ClassificationFailureInTheLoopStillReleases carries B5.4's
// contract into the block loop: segmenter.feed hands back the event and the
// error, so the loop records the failure and keeps releasing the original
// bytes. A reflexive early return on the error would drop wire bytes.
func TestStreamGuard_ClassificationFailureInTheLoopStillReleases(t *testing.T) {
	t.Parallel()
	lines := textStreamLines("a1", "b2", "c3")
	runner := &scriptedRunner{}
	codec := &flakyCodec{inner: adapter.NewRegistry(), ok: 1}
	g := loopGuard(t, runner, codec, streamGuardConfig{minChars: 1})

	out, pe := g.Run(context.Background(), invariantSource(t, g, lines, nil))
	require.Nil(t, pe)
	got, err := collectGuardOutput(t, g, out)
	require.NoError(t, err)
	require.Equal(t, lines, got, "an undecodable event is released byte for byte")
	require.Equal(t, "a1", runner.segments[len(runner.segments)-1].Accumulated,
		"what the codec could not decode contributes no inspectable text")
}

// TestStreamGuard_StopsTheStreamOnWhatItCannotDegrade records where B7 stops
// and B8 starts. A verdict that says block, a transform the buffer rewrite
// cannot apply, and a fail_closed policy are the three things the loop cannot
// answer by releasing text, so the held events are not written and no further
// call is issued.
//
// Each of the three ends the stream on the same terminator, and each says why
// on the error channel: they are different incidents to a client deciding
// whether to retry, and the finish reason — the one slot every dialect
// has — is not where that difference fits.
func TestStreamGuard_StopsTheStreamOnWhatItCannotDegrade(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		outcome     *appplugins.SegmentOutcome
		err         error
		onError     streamOnError
		wantMessage string
	}{
		{
			name:        "block verdict",
			outcome:     &appplugins.SegmentOutcome{Block: true, Type: "guardrail_violation", Message: "nope"},
			wantMessage: "nope",
		},
		{
			name:        "block verdict without a message of its own",
			outcome:     &appplugins.SegmentOutcome{Block: true, Type: "guardrail_violation"},
			wantMessage: streamBlockMessage,
		},
		{
			name:        "a transform the rewrite cannot apply escalates to a block",
			outcome:     &appplugins.SegmentOutcome{HasTransform: true, Transformed: "x"},
			wantMessage: streamMaskedMessage,
		},
		{
			name:        "fail_closed on a failing call",
			err:         errors.New("guard timeout"),
			onError:     streamFailClosed,
			wantMessage: streamUnverifiableMessage,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			lines := textStreamLines("a1", "b2", "c3", "d4")
			runner := &scriptedRunner{}
			g := loopGuard(t, runner, adapter.NewRegistry(), streamGuardConfig{minChars: 1, onError: tc.onError})
			runner.probe = func() {
				if runner.calls == 2 {
					runner.outcome, runner.err = tc.outcome, tc.err
				}
			}

			out, pe := g.Run(context.Background(), invariantSource(t, g, lines, nil))
			require.Nil(t, pe, "past the head the status is already committed")
			got, err := collectGuardOutput(t, g, out)
			require.NoError(t, err)
			require.Equal(t, lines[:2], got[:2], "only the block the head cleared reaches the client")
			require.Equal(t, openAICutLines(tc.wantMessage), got[2:], "every stop ends on the same terminator")
			require.Equal(t, 2, runner.calls, "a stop issues no further calls")
			require.True(t, g.stopped)
			checkInvariant(t, g)
		})
	}
}

// openAICutLines is what a cut puts on an OpenAI-chat wire: the finish-reason
// chunk, then the blocked event, then the [DONE] sentinel an OpenAI-wire client
// reads end-of-stream from and from nothing else. The chunk carries the id of
// the stream it ends because strict client validators reject one without it.
func openAICutLines(message string) []string {
	return []string{
		`data: {"id":"c1","object":"chat.completion.chunk","choices":` +
			`[{"index":0,"delta":{},"finish_reason":"content_filter"}]}`, "",
		`data: {"error":{"message":` + strconv.Quote(message) + `,"type":"content_filter"}}`, "",
		"data: [DONE]", "",
	}
}

// TestStreamGuard_CutRegimeIsDecidedBySeq is the boundary between the two
// regimes. The same verdict over the same stream is a real 403 with an empty
// body while it lands on the head block, and a 200 that ends on a terminator
// once a byte has been released — because by then the status is on the wire
// and the only honest ending left is one the dialect can express.
func TestStreamGuard_CutRegimeIsDecidedBySeq(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		blockOn  int
		wantCut  bool
		wantHead bool
	}{
		{name: "the head block is a status code", blockOn: 1, wantHead: true},
		{name: "a later block is a terminator", blockOn: 2, wantCut: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			lines := textStreamLines("a1", "b2", "c3")
			runner := &scriptedRunner{}
			g := loopGuard(t, runner, adapter.NewRegistry(), streamGuardConfig{minChars: 1})
			runner.probe = func() {
				if runner.calls == tc.blockOn {
					runner.outcome = &appplugins.SegmentOutcome{Block: true, Message: "nope"}
				}
			}

			out, pe := g.Run(context.Background(), invariantSource(t, g, lines, nil))
			got, _ := collectGuardOutput(t, g, out)

			if tc.wantHead {
				require.NotNil(t, pe)
				require.Equal(t, http.StatusForbidden, pe.StatusCode)
				require.Zero(t, g.releasedIdx, "a head-gate block writes nothing at all")
				return
			}
			require.Nil(t, pe)
			require.True(t, tc.wantCut)
			require.Equal(t, lines[:2], got[:2])
			require.Equal(t, openAICutLines("nope"), got[2:])
			require.Equal(t, tc.blockOn, runner.calls)
		})
	}
}

// TestStreamGuard_CutGoesForwardAtTheReleasePointer pins B8.3. The payload is
// cumulative, so the verdict that stops the stream can name text released two
// blocks ago; there is no retraction on a wire the client has read, so the cut
// goes forward. What it must not do is release the block it was inspecting when
// the verdict landed — that is the text the verdict was about.
func TestStreamGuard_CutGoesForwardAtTheReleasePointer(t *testing.T) {
	t.Parallel()
	lines := textStreamLines("a1", "b2", "c3", "d4", "e5")
	runner := &scriptedRunner{}
	g := loopGuard(t, runner, adapter.NewRegistry(), streamGuardConfig{minChars: 1})
	runner.probe = func() {
		if runner.calls == 3 {
			runner.outcome = &appplugins.SegmentOutcome{Block: true, Message: "nope"}
		}
	}

	out, pe := g.Run(context.Background(), invariantSource(t, g, lines, nil))
	require.Nil(t, pe)
	got, err := collectGuardOutput(t, g, out)
	require.NoError(t, err)

	require.Equal(t, lines[:4], got[:4], "the two cleared blocks are released byte for byte")
	require.Equal(t, openAICutLines("nope"), got[4:])
	require.Equal(t, 2, g.releasedIdx, "the block under inspection is never released")
	require.Less(t, g.releasedIdx, len(g.produced))
	require.Equal(t, g.releasedIdx, g.clearedIdx, "a cut clears nothing it did not already release")
	for i, ev := range g.produced[g.releasedIdx:] {
		require.Nil(t, ev.lines, "held event %d kept its wire bytes after the cut", i)
	}
}

// TestStreamGuard_CutDrainsTheRestOfTheUpstream pins B8.4. Usage rides the last
// chunk and observeChunk runs inside adaptStream, upstream of the guard, so a
// line that is read is a line that is accounted even though the client will
// never see it: the drain is what keeps req.Metadata["usage"] populated and the
// token_rate_limiter charging a cut stream.
func TestStreamGuard_CutDrainsTheRestOfTheUpstream(t *testing.T) {
	t.Parallel()
	lines := textStreamLines("a1", "b2", "c3", "d4", "e5")
	runner := &scriptedRunner{}
	g := loopGuard(t, runner, adapter.NewRegistry(), streamGuardConfig{minChars: 1})
	runner.probe = func() {
		if runner.calls == 2 {
			runner.outcome = &appplugins.SegmentOutcome{Block: true}
		}
	}

	pulled := 0
	source := func(yield func([]byte, error) bool) {
		for _, line := range lines {
			pulled++
			if !yield([]byte(line), nil) {
				return
			}
		}
	}
	var drained iter.Seq2[[]byte, error]
	g.drain = func(rest iter.Seq2[[]byte, error]) { drained = rest }

	out, pe := g.Run(context.Background(), source)
	require.Nil(t, pe)
	_, err := collectGuardOutput(t, g, out)
	require.NoError(t, err)

	require.NotNil(t, drained, "a cut must hand the rest of the upstream to the drain")
	require.True(t, g.handedOff, "the pull coroutine belongs to the drain, and stopping it twice truncates it")
	require.Less(t, pulled, len(lines), "the cut left the upstream unfinished")

	// Consumed the way drainStream consumes it, which stops at the first line
	// it is handed: the drain has to do its reading rather than yield it.
	for range drained {
		break
	}
	require.Equal(t, len(lines), pulled,
		"the drain must reach the end of the stream, where the usage chunk is")
}

// TestStreamGuard_CutWithoutADrainStillCuts keeps the drain optional. It is an
// accounting concern; a guard built without one enforces exactly the same.
func TestStreamGuard_CutWithoutADrainStillCuts(t *testing.T) {
	t.Parallel()
	runner := &scriptedRunner{}
	g := loopGuard(t, runner, adapter.NewRegistry(), streamGuardConfig{minChars: 1})
	runner.probe = func() {
		if runner.calls == 2 {
			runner.outcome = &appplugins.SegmentOutcome{Block: true, Message: "nope"}
		}
	}

	out, pe := g.Run(context.Background(), invariantSource(t, g, textStreamLines("a1", "b2", "c3"), nil))
	require.Nil(t, pe)
	got, err := collectGuardOutput(t, g, out)
	require.NoError(t, err)
	require.Equal(t, openAICutLines("nope"), got[2:])
	require.False(t, g.handedOff, "with no drain the guard keeps the coroutine and closes it itself")
}

// TestStreamGuard_WorstCaseBlockHoldFitsTheWriteDeadline states the constraint
// the design leaves implicit: fasthttp sets the write deadline once per
// response, so SERVER_WRITE_TIMEOUT (60s by default, unset in gitops) covers
// the whole streamed body and every per-block hold eats into it.
func TestStreamGuard_WorstCaseBlockHoldFitsTheWriteDeadline(t *testing.T) {
	t.Parallel()
	const serverWriteTimeout = 60 * time.Second
	const maxGuardTimeout = 10 * time.Second
	const maxConfiguredHold = 5 * time.Second

	cfg := streamGuardConfig{maxHold: maxConfiguredHold}.withDefaults()
	require.Equal(t, maxConfiguredHold, cfg.maxHold)
	require.Less(t, cfg.maxHold+maxGuardTimeout, serverWriteTimeout/3,
		"one block's worst case is a full hold plus a full guard timeout, and the client trails by one of those")
}

// dialectGuard is loopGuard for a source dialect other than OpenAI-chat: the
// head closes on the first event that carries text, so the cut lands in the
// block loop rather than on the gate.
func dialectGuard(t *testing.T, runner segmentRunner, format adapter.Format) *streamGuard {
	t.Helper()
	return newStreamGuard(runner, adapter.NewRegistry(), format, stageInputFixture(),
		streamGuardConfig{headChars: 1, minChars: 1}, newGuardLogger())
}

// blockOnCall scripts the runner to answer the n-th call with a block, which is
// what puts the cut mid-stream instead of on the head block.
func blockOnCall(runner *scriptedRunner, n int, message string) {
	runner.probe = func() {
		if runner.calls == n {
			runner.outcome = &appplugins.SegmentOutcome{Block: true, Message: message}
		}
	}
}

// splitAtCut divides what the client received into the upstream prefix the
// guard released byte for byte and the terminator it synthesised after it. The
// boundary is stated rather than searched for: a terminator opens with lines an
// upstream emits too — content_block_stop is one — so scanning for the first
// difference would put the cut in the wrong place on exactly the dialects this
// is here to check.
func splitAtCut(t *testing.T, got, source []string, released int) ([]string, []string) {
	t.Helper()
	require.GreaterOrEqual(t, len(got), released)
	require.Equal(t, source[:released], got[:released],
		"the released prefix reproduces the upstream byte for byte")
	return got[:released], got[released:]
}

func anthropicTwoBlockStreamLines() []string {
	return []string{
		"event: message_start",
		`data: {"type":"message_start","message":{"id":"msg_1","model":"claude-sonnet-4-5"}}`, "",
		"event: content_block_start",
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}`, "",
		"event: content_block_delta",
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"let me see"}}`, "",
		"event: content_block_stop",
		`data: {"type":"content_block_stop","index":0}`, "",
		"event: content_block_start",
		`data: {"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}`, "",
		"event: content_block_delta",
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"Hola"}}`, "",
		"event: content_block_delta",
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":" mundo"}}`, "",
		"event: message_delta",
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"}}`, "",
		"event: message_stop",
		`data: {"type":"message_stop"}`, "",
	}
}

func responsesMessageStreamLines() []string {
	return []string{
		"event: response.output_item.added",
		`data: {"type":"response.output_item.added","output_index":0,` +
			`"item":{"id":"msg_1","type":"message","role":"assistant"}}`, "",
		"event: response.output_text.delta",
		`data: {"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"Hello"}`, "",
		"event: response.output_text.delta",
		`data: {"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":" world"}`, "",
		"event: response.completed",
		`data: {"type":"response.completed","response":{"id":"resp_1","model":"gpt-5"}}`, "",
	}
}

func geminiStreamLines() []string {
	return []string{
		`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"Hola"}]}}]}`, "",
		`data: {"candidates":[{"content":{"role":"model","parts":[{"text":" mundo"}]}}]}`, "",
		`data: {"candidates":[{"content":{"role":"model","parts":[]},"finishReason":"STOP"}]}`, "",
	}
}

func cohereStreamLines() []string {
	return []string{
		"event: content-delta",
		`data: {"type":"content-delta","delta":{"message":{"content":{"type":"text","text":"Hola"}}}}`, "",
		"event: content-delta",
		`data: {"type":"content-delta","delta":{"message":{"content":{"type":"text","text":" mundo"}}}}`, "",
		"event: message-end",
		`data: {"type":"message-end","delta":{"finish_reason":"COMPLETE"}}`, "",
	}
}

// TestStreamGuard_CutSpeaksTheCallersDialect is what the whole of Track A was
// for. A cut after the status is committed can only be read as a content filter
// if the terminator says so in the dialect the client speaks: on Anthropic the
// alternative is stop_reason end_turn, which is a normal ending and worse than
// not cutting at all.
//
// The finish-reason terminator comes first and the error event after it. The
// other order — or the error event alone — leaves an Anthropic content block
// and a Responses output item open for good.
func TestStreamGuard_CutSpeaksTheCallersDialect(t *testing.T) {
	t.Parallel()
	const message = "nope"
	tests := []struct {
		name         string
		format       adapter.Format
		lines        []string
		wantReleased int
		wantTail     []string
	}{
		{
			name:         "openai chat",
			format:       adapter.FormatOpenAI,
			lines:        textStreamLines("a1", "b2", "c3"),
			wantReleased: 2,
			wantTail:     openAICutLines(message),
		},
		{
			name:         "anthropic",
			format:       adapter.FormatAnthropic,
			lines:        anthropicTwoBlockStreamLines(),
			wantReleased: 9,
			wantTail: []string{
				"event: content_block_stop",
				`data: {"type":"content_block_stop","index":0}`, "",
				"event: message_delta",
				`data: {"type":"message_delta","delta":{"stop_reason":"refusal","stop_sequence":null,` +
					`"stop_details":{"type":"refusal"}},"usage":{"input_tokens":0,"output_tokens":0}}`, "",
				"event: message_stop",
				`data: {"type":"message_stop"}`, "",
			},
		},
		{
			name:         "gemini",
			format:       adapter.FormatGemini,
			lines:        geminiStreamLines(),
			wantReleased: 2,
			wantTail: []string{
				`data: {"candidates":[{"content":{"role":"model","parts":[]},"finishReason":"PROHIBITED_CONTENT"}]}`, "",
				`data: {"error":{"code":403,"message":"nope","status":"PERMISSION_DENIED"}}`, "",
			},
		},
		{
			// Cohere gets the terminator alone. Its streamed-response union has
			// no error member, so StreamBlockedEvent would fall through to the
			// OpenAI-shaped default — an object with no "type" discriminant on
			// a wire whose SDK parses every event as a StreamedChatResponseV2.
			// ERROR on message-end is the whole signal there.
			name:         "cohere",
			format:       adapter.FormatCohere,
			lines:        cohereStreamLines(),
			wantReleased: 3,
			wantTail: []string{
				"event: message-end",
				`data: {"type":"message-end","delta":{"finish_reason":"ERROR"}}`, "",
			},
		},
		{
			// Mistral speaks the OpenAI-chat wire but normalizeFormat does not
			// fold it into FormatOpenAI, so a gate written as IsSameWireFormat
			// leaves a Mistral client waiting for a [DONE] that never comes.
			name:         "mistral",
			format:       adapter.FormatMistral,
			lines:        textStreamLines("a1", "b2", "c3"),
			wantReleased: 2,
			wantTail:     openAICutLines(message),
		},
		{
			name:         "openai responses",
			format:       adapter.FormatOpenAIResponses,
			lines:        responsesMessageStreamLines(),
			wantReleased: 6,
			wantTail: []string{
				"event: response.output_text.done",
				`data: {"type":"response.output_text.done","output_index":0,"content_index":0}`, "",
				"event: response.content_part.done",
				`data: {"type":"response.content_part.done","output_index":0,"content_index":0,` +
					`"part":{"type":"output_text","text":""}}`, "",
				"event: response.output_item.done",
				`data: {"type":"response.output_item.done","output_index":0,` +
					`"item":{"id":"msg_1","type":"message","role":"assistant",` +
					`"status":"incomplete","content":[]}}`, "",
				"event: response.incomplete",
				`data: {"type":"response.incomplete","response":{"incomplete_details":` +
					`{"reason":"content_filter"},"object":"response","output":[],"status":"incomplete"}}`, "",
				"event: error",
				`data: {"type":"error","code":"content_filter","message":"nope","param":null}`, "",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runner := &scriptedRunner{}
			g := dialectGuard(t, runner, tc.format)
			blockOnCall(runner, 2, message)

			out, pe := g.Run(context.Background(), invariantSource(t, g, tc.lines, nil))
			require.Nil(t, pe)
			got, err := collectGuardOutput(t, g, out)
			require.NoError(t, err)

			_, tail := splitAtCut(t, got, tc.lines, tc.wantReleased)
			require.Equal(t, tc.wantTail, tail)
			require.Equal(t, 2, runner.calls, "a cut issues no further calls")
		})
	}
}

// encodeFailingCodec decodes normally and cannot encode, which is the only way
// a cut reaches the wire without a terminator in front of it.
type encodeFailingCodec struct{ guardCodec }

func (encodeFailingCodec) EncodeStreamChunkFor(
	*adapter.CanonicalStreamChunk,
	adapter.Format,
) ([][]byte, error) {
	return nil, errors.New("no encoder")
}

// TestStreamGuard_CutWithoutATerminatorSendsNoBlockedEventAlone holds
// StreamBlockedEvent to its own contract. It is the secondary signal and the
// terminator is the primary one; on Anthropic and Responses an error event with
// no terminator in front of it leaves the content block and the output item the
// cut interrupted open for good, which is worse than a stream that simply ends.
func TestStreamGuard_CutWithoutATerminatorSendsNoBlockedEventAlone(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		format       adapter.Format
		lines        []string
		wantReleased int
		wantTail     []string
	}{
		{
			name:         "a dialect whose wire ends on a sentinel still gets it",
			format:       adapter.FormatOpenAI,
			lines:        textStreamLines("a1", "b2", "c3"),
			wantReleased: 2,
			wantTail:     []string{"data: [DONE]", ""},
		},
		{
			name:         "a dialect with no sentinel gets nothing at all",
			format:       adapter.FormatAnthropic,
			lines:        anthropicTwoBlockStreamLines(),
			wantReleased: 9,
			wantTail:     []string{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runner := &scriptedRunner{}
			g := newStreamGuard(runner, encodeFailingCodec{adapter.NewRegistry()}, tc.format,
				stageInputFixture(), streamGuardConfig{headChars: 1, minChars: 1}, newGuardLogger())
			blockOnCall(runner, 2, "nope")

			out, pe := g.Run(context.Background(), invariantSource(t, g, tc.lines, nil))
			require.Nil(t, pe)
			got, err := collectGuardOutput(t, g, out)
			require.NoError(t, err)

			_, tail := splitAtCut(t, got, tc.lines, tc.wantReleased)
			require.Equal(t, tc.wantTail, tail)
			for _, line := range tail {
				require.NotContains(t, line, "content_filter",
					"the blocked event must not travel without the terminator it qualifies")
			}
			require.True(t, g.stopped)
		})
	}
}

// steppedDialectGuard is dialectGuard on a clock that jumps a whole max_hold
// between reads, so in the block loop every event closes its own block. It is
// how a case puts a chosen event at the end of the released prefix: blocks
// otherwise close on chars, and only a text event carries any, so a prefix
// ending on a structural event is unreachable without it.
func steppedDialectGuard(t *testing.T, runner segmentRunner, format adapter.Format) *streamGuard {
	t.Helper()
	g := dialectGuard(t, runner, format)
	clock := &fakeStreamClock{now: time.Now(), step: time.Second}
	g.now = clock.Now
	return g
}

// anthropicSecondBlockStreamLines closes the thinking block and opens the text
// one before the head fills, so the released prefix ends with block 1 open and
// index 1 is the honest answer rather than a coincidence.
func anthropicSecondBlockStreamLines() []string {
	return []string{
		"event: message_start",
		`data: {"type":"message_start","message":{"id":"msg_1","model":"claude-sonnet-4-5"}}`, "",
		"event: content_block_start",
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}`, "",
		"event: content_block_stop",
		`data: {"type":"content_block_stop","index":0}`, "",
		"event: content_block_start",
		`data: {"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}`, "",
		"event: content_block_delta",
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"Hola"}}`, "",
		"event: content_block_delta",
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":" mundo"}}`, "",
		"event: message_delta",
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"}}`, "",
		"event: message_stop",
		`data: {"type":"message_stop"}`, "",
	}
}

// anthropicClosedBlockStreamLines ends its only content block and then carries
// on with a message_delta that has usage on it. That event is the point: it is
// the first thing after the stop that is not opaque, so the prefix the guard
// releases stops exactly at the stop rather than running on into whatever the
// upstream opens next.
func anthropicClosedBlockStreamLines() []string {
	return []string{
		"event: message_start",
		`data: {"type":"message_start","message":{"id":"msg_1","model":"claude-sonnet-4-5"}}`, "",
		"event: content_block_start",
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`, "",
		"event: content_block_delta",
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hola"}}`, "",
		"event: content_block_stop",
		`data: {"type":"content_block_stop","index":0}`, "",
		"event: message_delta",
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}`, "",
		"event: message_stop",
		`data: {"type":"message_stop"}`, "",
	}
}

// TestStreamGuard_CutClosesTheContentBlockTheClientSawOpen pins B8.8, read off
// the released prefix rather than off what the guard has admitted. A cut drops
// produced[releasedIdx:], so a running index advanced at admit time names the
// block a held event opened — one the client was never shown — while the block
// it is actually looking at stays open. That is the defect A2.2 exists to
// remove, shifted by whatever the guard was holding.
//
// The three cases are the three answers: the block the prefix ends inside, the
// block a later start legitimately makes current, and no block at all when the
// prefix already ended on a stop.
func TestStreamGuard_CutClosesTheContentBlockTheClientSawOpen(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		lines        []string
		stepped      bool
		blockOn      int
		wantReleased int
		wantOpen     bool
		wantIndex    int
	}{
		{
			// The held events close block 0, open block 1 and write into it.
			// None of that reached the client: from its seat block 0 is open.
			name:         "the released prefix ends inside the first block",
			lines:        anthropicTwoBlockStreamLines(),
			blockOn:      2,
			wantReleased: 9,
			wantOpen:     true,
			wantIndex:    0,
		},
		{
			name:         "the released prefix ends after the second block opened",
			lines:        anthropicSecondBlockStreamLines(),
			blockOn:      2,
			wantReleased: 15,
			wantOpen:     true,
			wantIndex:    1,
		},
		{
			// The client saw the upstream close block 0 itself. A terminator
			// that stopped it again asks the SDK to apply a stop with no open
			// block left to apply it to.
			name:         "the released prefix ends on the upstream's own stop",
			lines:        anthropicClosedBlockStreamLines(),
			stepped:      true,
			blockOn:      2,
			wantReleased: 12,
			wantOpen:     false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runner := &scriptedRunner{}
			g := dialectGuard(t, runner, adapter.FormatAnthropic)
			if tc.stepped {
				g = steppedDialectGuard(t, runner, adapter.FormatAnthropic)
			}
			blockOnCall(runner, tc.blockOn, "nope")

			out, pe := g.Run(context.Background(), invariantSource(t, g, tc.lines, nil))
			require.Nil(t, pe)
			got, err := collectGuardOutput(t, g, out)
			require.NoError(t, err)

			require.Equal(t, tc.wantOpen, g.released.blockOpen,
				"the anchor must follow open and closed, not the last index it saw")
			_, tail := splitAtCut(t, got, tc.lines, tc.wantReleased)
			if !tc.wantOpen {
				for _, line := range tail {
					require.NotContains(t, line, "content_block_stop",
						"the client already saw this block closed")
				}
				return
			}
			require.Equal(t, tc.wantIndex, g.released.blockIndex)
			require.Contains(t, tail,
				`data: {"type":"content_block_stop","index":`+strconv.Itoa(tc.wantIndex)+`}`,
				"the terminator must close the block the client saw open")
			for i := range tc.wantIndex + 2 {
				if i == tc.wantIndex {
					continue
				}
				require.NotContains(t, tail,
					`data: {"type":"content_block_stop","index":`+strconv.Itoa(i)+`}`,
					"no other block is the client's open one")
			}
		})
	}
}

// responsesItemStreamLines opens one output item of the given kind at the given
// output index and streams two deltas into it. Both kinds open the same way and
// at whatever index the caller's own output has reached, which is why a cut
// cannot infer either.
func responsesItemStreamLines(outputIndex int, kind string) []string {
	idx := strconv.Itoa(outputIndex)
	if kind == "function_call" {
		return []string{
			"event: response.output_item.added",
			`data: {"type":"response.output_item.added","output_index":` + idx +
				`,"item":{"id":"fc_1","call_id":"call_1","type":"function_call","name":"lookup"}}`, "",
			"event: response.function_call_arguments.delta",
			`data: {"type":"response.function_call_arguments.delta","output_index":` + idx + `,"delta":"{\"city\":"}`, "",
			"event: response.function_call_arguments.delta",
			`data: {"type":"response.function_call_arguments.delta","output_index":` + idx + `,"delta":"\"Paris\"}"}`, "",
			"event: response.completed",
			`data: {"type":"response.completed","response":{}}`, "",
		}
	}
	return []string{
		"event: response.output_item.added",
		`data: {"type":"response.output_item.added","output_index":` + idx +
			`,"item":{"id":"msg_1","type":"message","role":"assistant"}}`, "",
		"event: response.output_text.delta",
		`data: {"type":"response.output_text.delta","output_index":` + idx + `,"content_index":0,"delta":"Hello"}`, "",
		"event: response.output_text.delta",
		`data: {"type":"response.output_text.delta","output_index":` + idx + `,"content_index":0,"delta":" world"}`, "",
		"event: response.completed",
		`data: {"type":"response.completed","response":{}}`, "",
	}
}

// TestStreamGuard_CutClosesTheOpenResponsesItem pins B8.9, the same axis one
// dialect over: Responses numbers output items rather than content blocks, and
// a message item and a function_call item both open at output index 0. A cut
// that closed index 0 blind would leave the real item unterminated and close
// one that was never added, so the guard carries which item the client saw
// opened and what kind it is — with the identity fields the SDK types require,
// because a close missing them raises a validation error instead of delivering
// the refusal.
func TestStreamGuard_CutClosesTheOpenResponsesItem(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		lines     []string
		wantClose []string
	}{
		{
			name:  "a message item at an output index the encoder does not control",
			lines: responsesItemStreamLines(2, "message"),
			wantClose: []string{
				`data: {"type":"response.output_text.done","output_index":2,"content_index":0}`,
				`data: {"type":"response.content_part.done","output_index":2,"content_index":0,` +
					`"part":{"type":"output_text","text":""}}`,
				`data: {"type":"response.output_item.done","output_index":2,` +
					`"item":{"id":"msg_1","type":"message","role":"assistant",` +
					`"status":"incomplete","content":[]}}`,
			},
		},
		{
			// The arguments rode function_call_arguments.delta and there is no
			// text part to close; .done would assert a complete argument string,
			// which a cut has not produced. The item still has to say arguments
			// is "" rather than omit it.
			name:  "a function call at the same index a message opens at",
			lines: responsesItemStreamLines(0, "function_call"),
			wantClose: []string{
				`data: {"type":"response.output_item.done","output_index":0,` +
					`"item":{"id":"fc_1","type":"function_call","call_id":"call_1",` +
					`"name":"lookup","arguments":"","status":"incomplete"}}`,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runner := &scriptedRunner{}
			g := dialectGuard(t, runner, adapter.FormatOpenAIResponses)
			blockOnCall(runner, 2, "nope")

			out, pe := g.Run(context.Background(), invariantSource(t, g, tc.lines, nil))
			require.Nil(t, pe)
			got, err := collectGuardOutput(t, g, out)
			require.NoError(t, err)

			_, tail := splitAtCut(t, got, tc.lines, 6)
			for _, want := range tc.wantClose {
				require.Contains(t, tail, want)
			}
			require.Equal(t, len(tc.wantClose)*3+6, len(tail),
				"the close events, the terminator and the blocked event, and nothing else")
		})
	}
}

// responsesInterruptedItemStreamLines has the upstream close item 0 partway
// through and keep writing into it. Where that close falls relative to the
// release pointer is the whole question: held, the client never saw it and the
// item is still open to it; released, the client saw it and a second close is a
// close of nothing.
func responsesInterruptedItemStreamLines() []string {
	return []string{
		"event: response.output_item.added",
		`data: {"type":"response.output_item.added","output_index":0,` +
			`"item":{"id":"msg_1","type":"message","role":"assistant"}}`, "",
		"event: response.output_text.delta",
		`data: {"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"Hello"}`, "",
		"event: response.output_item.done",
		`data: {"type":"response.output_item.done","output_index":0,"item":{"type":"message"}}`, "",
		"event: response.output_text.delta",
		`data: {"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":" world"}`, "",
		"event: response.completed",
		`data: {"type":"response.completed","response":{}}`, "",
	}
}

// TestStreamGuard_CutClosesTheItemOnlyWhileTheClientHasItOpen is the other half
// of B8.9, and the case an admit-time anchor gets exactly backwards. The same
// upstream is cut in two places: with output_item.done still held, the client
// has item 0 open and the cut owes it a close; with output_item.done released,
// the client watched the upstream close it and closing it again terminates an
// item nobody has open.
func TestStreamGuard_CutClosesTheItemOnlyWhileTheClientHasItOpen(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		stepped      bool
		blockOn      int
		wantReleased int
		wantClose    bool
	}{
		{
			name:         "the upstream's close is among the events the cut drops",
			blockOn:      2,
			wantReleased: 6,
			wantClose:    true,
		},
		{
			name:         "the upstream's close is inside the released prefix",
			stepped:      true,
			blockOn:      3,
			wantReleased: 9,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			lines := responsesInterruptedItemStreamLines()
			runner := &scriptedRunner{}
			g := dialectGuard(t, runner, adapter.FormatOpenAIResponses)
			if tc.stepped {
				g = steppedDialectGuard(t, runner, adapter.FormatOpenAIResponses)
			}
			blockOnCall(runner, tc.blockOn, "nope")

			out, pe := g.Run(context.Background(), invariantSource(t, g, lines, nil))
			require.Nil(t, pe)
			got, err := collectGuardOutput(t, g, out)
			require.NoError(t, err)

			_, tail := splitAtCut(t, got, lines, tc.wantReleased)
			if !tc.wantClose {
				require.Nil(t, g.released.openItem, "the client saw the upstream close its own item")
				for _, line := range tail {
					require.NotContains(t, line, "response.output_item.done",
						"closing an item nobody has open is worse than closing nothing")
				}
				return
			}
			require.NotNil(t, g.released.openItem, "the client never saw the close")
			require.Contains(t, tail,
				`data: {"type":"response.output_item.done","output_index":0,`+
					`"item":{"id":"msg_1","type":"message","role":"assistant",`+
					`"status":"incomplete","content":[]}}`)
		})
	}
}

// The aggregate is written from the closing segment, so the guard owes exactly
// one of those on every path a stream can end on — including the paths that
// never reach a final block, which are precisely the ones worth measuring. One
// too few and a cut is invisible; one too many and SetExtras overwrites a
// complete account with a partial one.
func TestStreamGuard_ClosesTheStreamExactlyOnce(t *testing.T) {
	t.Parallel()

	block := &appplugins.SegmentOutcome{Block: true, Type: "jailbreak", Message: "cut"}

	tests := []struct {
		name     string
		lines    []string
		cfg      streamGuardConfig
		outcome  *appplugins.SegmentOutcome
		runErr   error
		stopAt   int
		wantCut  int
		wantFall string
		wantFin  bool
	}{
		{
			name:    "a stream that ends on its own",
			lines:   openAIStreamLines(),
			wantFin: true,
		},
		{
			name:    "a head-gate block, where nothing was ever written",
			lines:   openAIStreamLines(),
			outcome: block,
			wantCut: 1,
			wantFin: true,
		},
		{
			name:    "a mid-stream cut, which never reaches a final block",
			lines:   textStreamLines("alpha", "bravo", "charlie", "delta", "echo", "foxtrot"),
			cfg:     streamGuardConfig{headChars: 1, minChars: 1},
			outcome: block,
			wantCut: 1,
		},
		{
			name:     "a client that stopped pulling",
			lines:    textStreamLines("alpha", "bravo", "charlie", "delta", "echo", "foxtrot"),
			cfg:      streamGuardConfig{headChars: 1, minChars: 1},
			stopAt:   1,
			wantFall: fallbackClientDisconnected,
		},
		{
			name:     "a block loop retired by consecutive failures",
			lines:    textStreamLines("alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel"),
			cfg:      streamGuardConfig{headChars: 1, minChars: 1},
			runErr:   errors.New("guard unreachable"),
			wantFall: fallbackSegmentationUnavail,
			wantFin:  false,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runner := &scriptedRunner{outcome: tc.outcome, err: tc.runErr}
			g := newStreamGuard(runner, adapter.NewRegistry(), adapter.FormatOpenAI,
				stageInputFixture(), tc.cfg, newGuardLogger())

			out, pe := g.Run(context.Background(), invariantSource(t, g, tc.lines, nil))
			if pe == nil {
				drainUpTo(out, tc.stopAt)
			} else {
				drainUpTo(out, 0)
			}

			require.Len(t, runner.closings, 1, "the aggregate is written once, on every path")
			report := runner.closings[0].Report
			require.Equal(t, g.streamID, runner.closings[0].StreamID)
			require.Equal(t, runner.calls, report.Evals, "every block handed to the chain is an eval")
			require.Equal(t, tc.wantCut, report.CutAtEval)
			require.Equal(t, tc.wantFall, report.FallbackReason)
			require.Equal(t, tc.wantFin, report.FinalPass)
			if tc.runErr != nil {
				require.Zero(t, report.GuardCalls, "a call that never answered is not a guard call")
				require.Equal(t, degradeGuardTimeout, report.DegradedReason)
			} else {
				require.Equal(t, report.Evals, report.GuardCalls)
			}
			require.GreaterOrEqual(t, report.GuardLatency, report.GuardLatencyMax)
			if tc.wantCut == 0 && tc.wantFall == "" {
				require.GreaterOrEqual(t, report.AddedLatency, report.GuardLatency,
					"bytes were held for at least as long as the chain took to clear them")
			}
		})
	}
}

// drainUpTo consumes the sequence, stopping after stop lines when stop is
// positive. Stopping early is the only disconnect signal there is: propagation
// is pull-based, so a consumer that walks away is a yield that returns false.
func drainUpTo(out iter.Seq2[[]byte, error], stop int) {
	n := 0
	for range out {
		n++
		if stop > 0 && n >= stop {
			return
		}
	}
}

// The cut offset is what the client had already read, not what the provider had
// produced. It is the exposure a cut did not prevent, and the number an
// operator sets min_chars_between_evals against, so it must never be read off
// the accumulated buffer.
func TestStreamGuard_CutOffsetCountsReleasedTextOnly(t *testing.T) {
	t.Parallel()

	runner := &scriptedRunner{}
	g := loopGuard(t, runner, adapter.NewRegistry(), streamGuardConfig{minChars: 1})
	runner.probe = func() {
		if runner.calls >= 3 {
			runner.outcome = &appplugins.SegmentOutcome{Block: true, Type: "jailbreak"}
		}
	}

	out, pe := g.Run(context.Background(), invariantSource(t, g, textStreamLines("alpha", "bravo", "charlie", "delta", "echo", "foxtrot"), nil))
	require.Nil(t, pe)
	_, err := collectGuardOutput(t, g, out)
	require.NoError(t, err)

	require.Len(t, runner.closings, 1)
	report := runner.closings[0].Report
	require.Equal(t, 3, report.CutAtEval)
	require.Equal(t, g.releasedChars, report.CutOffsetChars)
	require.Less(t, report.CutOffsetChars, len(g.text.String()),
		"the client saw less than the provider produced, or the cut prevented nothing")
}

// The set is the guard's because the guard is the only object whose lifetime is
// the stream's. An alert-only chain never cuts and every call carries the whole
// accumulated text, so the same finding comes back on every block after the one
// that first tripped it; what reaches the closing segment is the fold, in
// first-seen order. The key is the entry together with the fingerprint, so one
// detection reported by two policies on the same stream stays two findings and
// the executor can hand each entry its own.
func TestStreamGuard_FoldsRepeatedFindingsIntoOneSet(t *testing.T) {
	t.Parallel()

	first := appplugins.StreamFinding{Entry: "cfg-1", Fingerprint: "a"}
	second := appplugins.StreamFinding{Entry: "cfg-1", Fingerprint: "b"}

	tests := []struct {
		name string
		per  func(call int) []appplugins.StreamFinding
		want []appplugins.StreamFinding
	}{
		{
			name: "the same finding on every block",
			per:  func(int) []appplugins.StreamFinding { return []appplugins.StreamFinding{first} },
			want: []appplugins.StreamFinding{first},
		},
		{
			name: "a second finding a later block is the first to carry",
			per: func(call int) []appplugins.StreamFinding {
				if call < 2 {
					return []appplugins.StreamFinding{first}
				}
				return []appplugins.StreamFinding{first, second}
			},
			want: []appplugins.StreamFinding{first, second},
		},
		{
			name: "the same key from a second policy on the stream",
			per: func(int) []appplugins.StreamFinding {
				return []appplugins.StreamFinding{first, {Entry: "cfg-2", Fingerprint: "a"}}
			},
			want: []appplugins.StreamFinding{first, {Entry: "cfg-2", Fingerprint: "a"}},
		},
		{
			name: "a stream nothing was reported on",
			per:  func(int) []appplugins.StreamFinding { return nil },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			runner := &scriptedRunner{}
			g := loopGuard(t, runner, adapter.NewRegistry(), streamGuardConfig{minChars: 1})
			runner.probe = func() {
				runner.outcome = &appplugins.SegmentOutcome{Fingerprints: tt.per(runner.calls)}
			}

			out, pe := g.Run(context.Background(),
				invariantSource(t, g, textStreamLines("alpha", "bravo", "charlie", "delta", "echo"), nil))
			require.Nil(t, pe)
			_, err := collectGuardOutput(t, g, out)
			require.NoError(t, err)

			require.Greater(t, runner.calls, 1, "one call cannot show a repeat being collapsed")
			require.Len(t, runner.closings, 1)
			assert.Equal(t, tt.want, runner.closings[0].Findings)
		})
	}
}

// streamedText is the content a client would assemble from what the guard
// released. The masked event is the one thing on the wire the guard encoded
// itself, so asserting it by its bytes would pin the dialect's encoder rather
// than the rewrite; what the rewrite owes the client is the text.
func streamedText(t *testing.T, format adapter.Format, lines []string) string {
	t.Helper()
	registry := adapter.NewRegistry()
	var text strings.Builder
	for _, line := range lines {
		payload, ok := dataPayload([]byte(line))
		if !ok || isSSEDone([]byte(line)) {
			continue
		}
		chunk, err := registry.DecodeStreamChunkFor(payload, format)
		if err != nil || chunk == nil {
			continue
		}
		text.WriteString(chunk.Delta)
	}
	return text.String()
}

func toolCallStreamLines() []string {
	return []string{
		`data: {"id":"c1","choices":[{"index":0,"delta":{"content":"a1"}}]}`, "",
		`data: {"id":"c1","choices":[{"index":0,"delta":{"content":"b2"}}]}`, "",
		`data: {"id":"c1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1",` +
			`"type":"function","function":{"name":"lookup","arguments":"{\"q\":\"b2\"}"}}]}}]}`, "",
		"data: [DONE]", "",
	}
}

// TestStreamGuard_TransformRewritesTheHeldBuffer is B11.2. A masking policy on
// a streamed response has to reach the client, and the head is where it can
// still do so without a single byte having gone out: the flagged span never
// reaches the wire, the events that carried it are re-encoded as the masked
// text, and the buffer the next call accumulates onto is the masked one.
func TestStreamGuard_TransformRewritesTheHeldBuffer(t *testing.T) {
	t.Parallel()
	lines := textStreamLines("Hello ", "secret")
	runner := &scriptedRunner{
		outcome: &appplugins.SegmentOutcome{HasTransform: true, Transformed: "Hello ****"},
	}
	g := newStreamGuard(runner, adapter.NewRegistry(), adapter.FormatOpenAI,
		stageInputFixture(), streamGuardConfig{}, newGuardLogger())

	out, pe := g.Run(context.Background(), invariantSource(t, g, lines, nil))
	require.Nil(t, pe, "a mask the guard can apply is not a block")
	got, err := collectGuardOutput(t, g, out)
	require.NoError(t, err)

	assert.Equal(t, "Hello ****", streamedText(t, adapter.FormatOpenAI, got))
	assert.NotContains(t, strings.Join(got, "\n"), "secret", "the flagged span must not reach the wire")
	assert.Equal(t, lines[len(lines)-2:], got[len(got)-2:], "the terminal event is released byte for byte")
	assert.Equal(t, "Hello ****", g.text.String(), "the accumulated buffer is rewritten in place")
	assert.Equal(t, 1, runner.calls)
}

// TestStreamGuard_TransformEscalatesOnWhatItCannotRewrite is B11.3: one rule,
// two triggers. The rule is that a masked buffer may differ from the produced
// one only inside text the guard still holds. Text the client has already read
// breaks it because the wire cannot be retracted, and a span the buffer does
// not carry breaks it because the mask would land on a thought or on JSON
// arguments — which the guard sees as a buffer the verdict left untouched, or
// as a held event carrying tool-call deltas of its own.
func TestStreamGuard_TransformEscalatesOnWhatItCannotRewrite(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		lines       []string
		cfg         streamGuardConfig
		transformed string
		wantHead    []string
	}{
		{
			name:        "the masked span reaches text already released",
			lines:       textStreamLines("a1", "b2", "c3"),
			cfg:         streamGuardConfig{minChars: 1},
			transformed: "**b2",
			wantHead:    textStreamLines("a1")[:2],
		},
		{
			name:        "the masked span lands in a tool-call region",
			lines:       toolCallStreamLines(),
			cfg:         streamGuardConfig{minChars: 1 << 10},
			transformed: "a1**",
			wantHead:    toolCallStreamLines()[:2],
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runner := &scriptedRunner{}
			g := loopGuard(t, runner, adapter.NewRegistry(), tc.cfg)
			runner.probe = func() {
				if runner.calls == 2 {
					runner.outcome = &appplugins.SegmentOutcome{
						HasTransform: true,
						Transformed:  tc.transformed,
					}
				}
			}

			out, pe := g.Run(context.Background(), invariantSource(t, g, tc.lines, nil))
			require.Nil(t, pe, "past the head the status is already committed")
			got, err := collectGuardOutput(t, g, out)
			require.NoError(t, err)

			require.Equal(t, tc.wantHead, got[:len(tc.wantHead)], "only the head block reaches the client")
			assert.Equal(t, openAICutLines(streamMaskedMessage), got[len(tc.wantHead):],
				"a mask that cannot be applied ends the stream on the terminator")
			assert.Equal(t, 2, runner.calls, "a stop issues no further calls")
			assert.True(t, g.stopped)
		})
	}
}

// TestStreamGuard_MaskedFindingIsNotReDetected is B11.4's last case and the
// proof B11.5 rests on. The payload is cumulative, so without the in-place
// rewrite an enforce-mode masking policy — which no longer cuts — would put the
// flagged span in front of the engine again on every later block, with neither
// the dedupe set nor a published one behind it. The rewrite is what removes it
// from the payload, which is as far as the gateway's half of the guarantee
// reaches.
func TestStreamGuard_MaskedFindingIsNotReDetected(t *testing.T) {
	t.Parallel()
	runner := &scriptedRunner{}
	g := loopGuard(t, runner, adapter.NewRegistry(), streamGuardConfig{minChars: 1})
	runner.probe = func() {
		if runner.calls == 1 {
			runner.outcome = &appplugins.SegmentOutcome{HasTransform: true, Transformed: "[MASK]"}
			return
		}
		runner.outcome = nil
	}

	out, pe := g.Run(context.Background(),
		invariantSource(t, g, textStreamLines("secret", "tail"), nil))
	require.Nil(t, pe)
	got, err := collectGuardOutput(t, g, out)
	require.NoError(t, err)

	require.Greater(t, runner.calls, 1, "one call cannot show a finding failing to come back")
	for _, seg := range runner.segments[1:] {
		assert.NotContains(t, seg.Accumulated, "secret", "the masked span must not be inspected again")
		assert.Contains(t, seg.Accumulated, "[MASK]", "the engine sees what the client sees")
	}
	assert.Equal(t, "[MASK]tail", streamedText(t, adapter.FormatOpenAI, got))
	assert.Equal(t, "tail", runner.segments[1].Text, "the block delta follows the rewritten buffer")
}

// packedTerminalStreamLines is the shape textStreamLines cannot produce: a
// provider that puts the finish reason, and the usage report with it, on the
// chunk that still carries the last of the text. Gemini/Vertex, Bedrock,
// Mistral and the chat-completions family all end this way, and Gemini has no
// [DONE] behind it, so that one event is the whole ending of the response.
func packedTerminalStreamLines(format adapter.Format, head, tail string) []string {
	if format == adapter.FormatGemini {
		return []string{
			`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"` + head + `"}]}}]}`, "",
			`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"` + tail + `"}]},` +
				`"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":1,` +
				`"candidatesTokenCount":2,"totalTokenCount":3}}`, "",
		}
	}
	return []string{
		`data: {"id":"c1","choices":[{"index":0,"delta":{"content":"` + head + `"}}]}`, "",
		`data: {"id":"c1","choices":[{"index":0,"delta":{"content":"` + tail + `"},` +
			`"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":2,` +
			`"total_tokens":3}}`, "",
		"data: [DONE]", "",
	}
}

// TestStreamGuard_MaskWillNotRewriteAnEventCarryingMoreThanText is the rule
// that keeps the rewrite from ending a response. maskLines encodes one text
// delta, so an event whose text rides with a finish reason and a usage report
// cannot be rebuilt from its text: re-encoding it drops the ending, and
// dropping it whole drops the ending too. On Gemini, where there is no [DONE]
// behind it, the stream would then simply stop on a bare text delta — no finish
// reason, no usage, nothing for a client to end on.
//
// The last case is the control. The same text with an ending of its own is
// masked, because there the held text events really do carry nothing else, and
// the ending is released byte for byte because the rewrite never touches it.
func TestStreamGuard_MaskWillNotRewriteAnEventCarryingMoreThanText(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		format     adapter.Format
		lines      []string
		wantMasked bool
	}{
		{
			name:   "the chat-completions family packs the finish reason onto the last text chunk",
			format: adapter.FormatOpenAI,
			lines:  packedTerminalStreamLines(adapter.FormatOpenAI, "Hello ", "secret"),
		},
		{
			name:   "gemini packs the finish reason and the usage metadata onto it",
			format: adapter.FormatGemini,
			lines:  packedTerminalStreamLines(adapter.FormatGemini, "Hello ", "secret"),
		},
		{
			name:       "an ending of its own leaves the text events carrying only text",
			format:     adapter.FormatOpenAI,
			lines:      textStreamLines("Hello ", "secret"),
			wantMasked: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runner := &scriptedRunner{
				outcome: &appplugins.SegmentOutcome{HasTransform: true, Transformed: "Hello ****"},
			}
			g := newStreamGuard(runner, adapter.NewRegistry(), tc.format,
				stageInputFixture(), streamGuardConfig{}, newGuardLogger())

			out, pe := g.Run(context.Background(), invariantSource(t, g, tc.lines, nil))
			got, err := collectGuardOutput(t, g, out)
			require.NoError(t, err)

			if !tc.wantMasked {
				require.NotNil(t, pe, "a mask that would cost the response its ending is a block")
				assert.Equal(t, streamMaskedType, pe.Type)
				// What Run returns after a head-gate block is the undrained
				// remainder, not output: the caller drains and discards it. No
				// text of the response is in it, which is the whole claim.
				assert.Empty(t, streamedText(t, tc.format, got), "a head-gate block releases no text")
				return
			}
			require.Nil(t, pe)
			assert.Equal(t, "Hello ****", streamedText(t, tc.format, got))
			assert.Equal(t, tc.lines[len(tc.lines)-2:], got[len(got)-2:],
				"the event that ends the response is released byte for byte")
		})
	}
}

// TestStreamGuard_MaskedDeltaNamesTheItemTheClientHasOpen is the Responses half
// of what terminator already does for a cut. The dialect carries no content
// block index at all — structure there is the output item — and the encoder
// writes output index 0 with no item_id for any delta that names none. A client
// accumulating by item_id then attaches the masked text to nothing, which is a
// mask that never reaches the reader it was written for.
func TestStreamGuard_MaskedDeltaNamesTheItemTheClientHasOpen(t *testing.T) {
	t.Parallel()
	lines := responsesItemStreamLines(2, "message")
	runner := &scriptedRunner{
		outcome: &appplugins.SegmentOutcome{HasTransform: true, Transformed: "Hello ****"},
	}
	g := newStreamGuard(runner, adapter.NewRegistry(), adapter.FormatOpenAIResponses,
		stageInputFixture(), streamGuardConfig{}, newGuardLogger())

	out, pe := g.Run(context.Background(), invariantSource(t, g, lines, nil))
	require.Nil(t, pe)
	got, err := collectGuardOutput(t, g, out)
	require.NoError(t, err)

	wire := strings.Join(got, "\n")
	assert.NotContains(t, wire, " world", "the flagged span must not reach the wire")
	require.Contains(t, wire, `"type":"response.output_text.delta"`)
	assert.Contains(t, wire, `"item_id":"msg_1"`, "the masked delta names the item the client saw added")
	assert.Contains(t, wire, `"output_index":2`, "and the index that item was added at")
	assert.Equal(t, lines[:3], got[:3], "the item the mask belongs to is announced byte for byte")
}

// TestStreamGuard_TransformRewritesABlockBehindTheReleasePointer is the rewrite
// where released text exists. Every other passing-rewrite case runs on the head
// block, where nothing has gone out and the released text is empty, so the
// released-text rule is only ever satisfied vacuously and the buffer is only
// ever rewritten from a zero base.
//
// Here the head has already been written. The masked buffer has to carry the
// released prefix unchanged for B11.3 to let it through, the held text is what
// is left once that prefix is taken off, and the block delta the next call
// carries is measured from the rewritten buffer rather than the produced one.
func TestStreamGuard_TransformRewritesABlockBehindTheReleasePointer(t *testing.T) {
	t.Parallel()
	lines := textStreamLines("a1", "secret", "tail")
	runner := &scriptedRunner{}
	g := loopGuard(t, runner, adapter.NewRegistry(), streamGuardConfig{minChars: 1})
	runner.probe = func() {
		if runner.calls == 2 {
			runner.outcome = &appplugins.SegmentOutcome{HasTransform: true, Transformed: "a1[REDACTED]"}
			return
		}
		runner.outcome = nil
	}

	out, pe := g.Run(context.Background(), invariantSource(t, g, lines, nil))
	require.Nil(t, pe, "the rewrite lands, so the block loop releases rather than cuts")
	got, err := collectGuardOutput(t, g, out)
	require.NoError(t, err)

	require.Equal(t, lines[:2], got[:2], "the head was released before the verdict and is untouched")
	assert.Equal(t, "a1[REDACTED]tail", streamedText(t, adapter.FormatOpenAI, got))
	assert.NotContains(t, strings.Join(got, "\n"), "secret")
	assert.Equal(t, "a1[REDACTED]tail", g.text.String(),
		"the buffer keeps the released prefix, replaces the rest and accumulates onto that")

	require.Greater(t, len(runner.segments), 2, "a later call is what proves the new base")
	assert.Equal(t, "tail", runner.segments[2].Text,
		"the block delta is measured from the rewritten buffer, not the produced one")
	assert.Equal(t, "a1[REDACTED]tail", runner.segments[2].Accumulated)
}

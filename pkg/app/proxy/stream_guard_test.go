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
}

func (r *scriptedRunner) RunStreamSegment(
	_ context.Context,
	in appplugins.StageInput,
	seg appplugins.StreamSegment,
) (*appplugins.SegmentOutcome, error) {
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
			// The buffer rewrite is a later slice, so until then the head
			// escalates rather than releasing the text the guard asked to mask.
			name:        "a transform verdict escalates instead of releasing unmasked text",
			format:      adapter.FormatOpenAI,
			lines:       openAIStreamLines(),
			outcome:     &appplugins.SegmentOutcome{HasTransform: true, Transformed: "[MASKED]"},
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
			var codec streamCodec = adapter.NewRegistry()
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
	inner streamCodec
	ok    int
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
func loopGuard(t *testing.T, runner segmentRunner, codec streamCodec, cfg streamGuardConfig) *streamGuard {
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
// The cap is the one thing this cannot be combined with: once window returns a
// tail, payload[i] stops being a prefix of payload[i+1] and the payload stops
// being everything admitted. That is by design — overlapping tails still expose
// cross-block findings within max_accumulated_bytes, which is what Truncated
// and degraded_reason: accumulation_cap announce — so a capped payload gets a
// message here rather than an unexplained failure.
func assertContiguousPrefixes(t *testing.T, segs []appplugins.StreamSegment, admitted []string) {
	t.Helper()
	require.NotEmpty(t, segs)
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
	assertContiguousPrefixes(t, runner.segments, *admitted)
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
			assertContiguousPrefixes(t, runner.segments, *admitted)
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
// cannot yet apply, and a fail_closed policy are the three things the loop
// cannot answer by releasing text, so the held events are not written and no
// further call is issued. The honest per-format terminator for that stop is
// B8; until it lands the stream simply ends.
func TestStreamGuard_StopsTheStreamOnWhatItCannotDegrade(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		outcome *appplugins.SegmentOutcome
		err     error
		onError streamOnError
	}{
		{name: "block verdict", outcome: &appplugins.SegmentOutcome{Block: true, Type: "guardrail_violation"}},
		{name: "transform escalates to a block", outcome: &appplugins.SegmentOutcome{HasTransform: true, Transformed: "x"}},
		{name: "fail_closed on a failing call", err: errors.New("guard timeout"), onError: streamFailClosed},
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
			require.Equal(t, lines[:2], got, "only the block the head cleared reaches the client")
			require.Equal(t, 2, runner.calls, "a stop issues no further calls")
			require.True(t, g.stopped)
			checkInvariant(t, g)
		})
	}
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

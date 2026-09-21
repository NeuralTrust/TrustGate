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

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
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// previousHeadHeldBytes is the held-bytes ceiling before it was raised.
// A tool call between it and maxHeadHeldBytes used to be released while still
// open; it is now held until the call closes.
const previousHeadHeldBytes = 256 << 10

func frameWire(frames [][]byte) int {
	n := 0
	for _, f := range frames {
		n += len(f)
	}
	return n
}

func sseWire(lines []string) int {
	n := 0
	for _, line := range lines {
		n += len(line)
	}
	return n
}

// toolDeltaWire is the wire size of a Converse tool call up to and including
// its last input fragment, and not the stop frame. That is the size the hold
// has already buffered while the call is still open.
func toolDeltaWire(t *testing.T, frags []string) int {
	t.Helper()
	frames := converseToolFrames(t, 1, frags...)
	require.GreaterOrEqual(t, len(frames), 2)
	return frameWire(frames[:len(frames)-1])
}

func TestNativeToolCallBetweenOldAndNewHoldCapIsInspected(t *testing.T) {
	t.Parallel()
	require.Greater(t, maxHeadHeldBytes, previousHeadHeldBytes)

	const marker = "HOLD-CAP-MARKER"
	pad := strings.Repeat("a", 32<<10)
	body := []string{`{"cmd":"look","pad":"`}
	for toolDeltaWire(t, body) <= previousHeadHeldBytes {
		body = append(body, pad)
	}
	frags := append(append([]string{}, body...), marker+`"}`)
	tool := converseToolFrames(t, 1, frags...)
	require.Greater(t, toolDeltaWire(t, body), previousHeadHeldBytes,
		"without the marker the call already passes the old ceiling, so the old hold would have released it")
	require.Less(t, frameWire(tool), maxHeadHeldBytes,
		"the whole call, marker included, fits the new ceiling")

	joined := strings.Join(frags, "")
	require.Contains(t, joined, marker)
	frames := append([][]byte{deltaFrame(t, "Sending it")}, tool...)
	frames = append(frames, testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`))

	// The chain window has to be able to read the view. A smaller window
	// releases the call instead of sending a segment the chain will refuse.
	cfg := toolBlocks
	cfg.maxAccumBytes = maxAccumulatedCeiling
	require.LessOrEqual(t, len(joined), cfg.maxAccumBytes)
	runner := &countRunner{inner: &blockRunner{needle: marker}}
	g := nativeGuardFor(runner, cfg)
	got, pe := runNativeGuard(t, g, frames)

	require.Nil(t, pe)
	require.True(t, g.wasCut(), "the policy saw the marker and blocked the call")
	require.NotContains(t, releasedText(t, got), marker)
	require.Empty(t, g.degradedReason)
	require.Contains(t, runner.segs, joined, "the chain was shown the whole tool call, not a window of it")
}

func chatHoldDeltasUntil(t *testing.T, floor int) (deltas []string, args string) {
	t.Helper()
	opening := `{"cmd":"look","pad":"`
	var b strings.Builder
	b.WriteString(opening)
	deltas = []string{chatToolDelta(t, 0, "call_1", "run_shell", opening)}
	frag := strings.Repeat("a", 256)
	for sseWire(deltas) <= floor {
		deltas = append(deltas, chatToolDelta(t, 0, "", "", frag))
		b.WriteString(frag)
	}
	return deltas, b.String()
}

func TestChatToolCallBetweenOldAndNewHoldCapIsInspected(t *testing.T) {
	t.Parallel()
	require.Greater(t, maxHeadHeldBytes, previousHeadHeldBytes)

	const marker = "HOLD-CAP-MARKER"
	deltas, prefix := chatHoldDeltasUntil(t, previousHeadHeldBytes)
	tail := marker + `"}`
	deltas = append(deltas, chatToolDelta(t, 0, "", "", tail))
	args := prefix + tail
	require.Less(t, len(args), defaultMaxAccumulatedBytes,
		"the argument text has to fit the inspection budget, or the chain is shown a tail instead of the call")
	require.Greater(t, sseWire(deltas[:len(deltas)-1]), previousHeadHeldBytes)
	require.Less(t, sseWire(deltas), maxHeadHeldBytes)

	runner := &toolGuardStub{pattern: marker}
	g := chatToolGuard(runner, adapter.FormatOpenAI, streamGuardConfig{
		headChars: 5, minChars: 1 << 20, maxHold: time.Hour,
		onError: streamFailOpen, holdChatTools: true,
	})
	run := runChatToolGuard(t, g, chatToolStream(deltas...), nil)

	require.Nil(t, run.pe)
	require.True(t, g.wasCut(), "the policy saw the marker and blocked the call")
	require.Zero(t, run.argLines, "no fragment of the call reaches the client")
	require.NotContains(t, strings.Join(run.out, "\n"), marker)
	require.Empty(t, g.degradedReason)
	var saw bool
	for _, seg := range runner.segments {
		for _, tc := range seg.ToolCalls {
			if tc.Arguments == args {
				saw = true
			}
		}
	}
	require.True(t, saw, "the chain was shown the whole tool call, not a window of it")
}

func TestChatToolCallAboveHoldCapFailsOpen(t *testing.T) {
	t.Parallel()
	deltas, _ := chatHoldDeltasUntil(t, maxHeadHeldBytes)
	require.Greater(t, sseWire(deltas), maxHeadHeldBytes,
		"the call is still open when the held bytes cross the ceiling")
	lines := chatToolStream(deltas...)

	logs := &bytes.Buffer{}
	g := newStreamGuard(&toolGuardStub{}, adapter.NewRegistry(), adapter.FormatOpenAI, stageInputFixture(),
		streamGuardConfig{
			headChars: 5, minChars: 1 << 20, maxHold: time.Hour,
			onError: streamFailOpen, holdChatTools: true,
		},
		slog.New(slog.NewTextHandler(logs, nil)))
	run := runChatToolGuard(t, g, lines, nil)

	require.Nil(t, run.pe)
	assert.False(t, g.wasCut(), "fail-open releases the call")
	assert.Equal(t, lines, run.out)
	assert.Equal(t, degradeToolInputUninspected, g.degradedReason)
	assert.Contains(t, logs.String(), "tool call released without inspecting its input")
	assert.Contains(t, logs.String(), "cause=size")
}

// windowRunner is the enforcing chain: a segment longer than its window is a
// block, which is what trustguard does with stream_block_too_large.
type windowRunner struct {
	limit int
	sizes []int
}

func (r *windowRunner) RunStreamSegment(
	_ context.Context,
	_ appplugins.StageInput,
	seg appplugins.StreamSegment,
) (*appplugins.SegmentOutcome, error) {
	if seg.Closing {
		return &appplugins.SegmentOutcome{}, nil
	}
	n := max(len(seg.Accumulated), len(seg.Text))
	r.sizes = append(r.sizes, n)
	if n > r.limit {
		return &appplugins.SegmentOutcome{Block: true, Type: "stream_block_too_large", Message: "too large"}, nil
	}
	return &appplugins.SegmentOutcome{}, nil
}

// A native call the hold can now keep, but whose normalised view is past the
// chain window, used to be sent whole. An enforcing chain refuses that segment
// and the refusal cuts the stream. It is released instead.
func TestNativeToolCallPastChainWindowFailsOpen(t *testing.T) {
	t.Parallel()
	const window = 64 << 10
	const want = 400 << 10
	pad := strings.Repeat("a", 16<<10)
	opening := `{"cmd":"look","pad":"`
	frags := []string{opening}
	var n int
	n += len(opening)
	for n < want {
		frags = append(frags, pad)
		n += len(pad)
	}
	frags = append(frags, `"}`)
	n += len(`"}`)
	require.Greater(t, n, window)
	require.Less(t, n, maxHeadHeldBytes)

	tool := converseToolFrames(t, 1, frags...)
	require.Less(t, frameWire(tool), maxHeadHeldBytes, "the hold keeps the call; the window is what refuses it")
	frames := append([][]byte{deltaFrame(t, "Sending it")}, tool...)
	frames = append(frames, testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`))

	runner := &windowRunner{limit: window}
	cfg := toolBlocks
	cfg.maxAccumBytes = window
	g, logs := loggedGuard(runner, cfg)
	got, pe := runNativeGuard(t, g, frames)

	require.Nil(t, pe)
	assert.False(t, g.wasCut(), "the oversized view is released, not cut")
	requireReleasedUninspected(t, g, logs, frames, got, "size")
	for _, size := range runner.sizes {
		assert.LessOrEqual(t, size, window, "the unreadable view was not sent")
	}
}

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
	"errors"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"iter"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countRunner records what the chain was handed, and answers as inner does.
type countRunner struct {
	inner segmentRunner
	segs  []string
	tools int
}

func (r *countRunner) RunStreamSegment(ctx context.Context, in appplugins.StageInput, seg appplugins.StreamSegment) (*appplugins.SegmentOutcome, error) {
	if !seg.Closing {
		r.segs = append(r.segs, seg.Accumulated)
		r.tools += len(seg.ToolCalls)
	}
	return r.inner.RunStreamSegment(ctx, in, seg)
}

// failJSONRunner fails every segment that is a JSON document, which is what a
// tool input is, and allows the rest.
type failJSONRunner struct{}

func (failJSONRunner) RunStreamSegment(_ context.Context, _ appplugins.StageInput, seg appplugins.StreamSegment) (*appplugins.SegmentOutcome, error) {
	if !seg.Closing && strings.HasPrefix(strings.TrimSpace(seg.Accumulated), "{") {
		return nil, errors.New("provider down")
	}
	return &appplugins.SegmentOutcome{}, nil
}

// loggedGuard is a native guard whose log lines can be read back.
func loggedGuard(runner segmentRunner, cfg streamGuardConfig) (*streamGuard, *bytes.Buffer) {
	logs := &bytes.Buffer{}
	g := nativeGuardFor(runner, cfg)
	g.logger = slog.New(slog.NewTextHandler(logs, nil))
	return g, logs
}

// requireReleasedUninspected checks the visible part of a tool call released
// without its input having been read: the stream is not cut, every frame is
// released as it came, the stream is flagged, and the cause is logged once.
func requireReleasedUninspected(t *testing.T, g *streamGuard, logs *bytes.Buffer, frames, got [][]byte, cause string) {
	t.Helper()
	assert.Equal(t, frames, got, "released as it came: this is the behaviour that is kept")
	assert.Equal(t, "tool_input_uninspected", g.degradedReason)
	assert.Equal(t, 1, strings.Count(logs.String(), "tool call released without inspecting its input"), "one WARN per stream")
	assert.Contains(t, logs.String(), "cause="+cause)
}

// P1: a tool call that takes longer than the tool hold.
func TestNativeToolDegrade_SlowCallIsFlaggedNotCut(t *testing.T) {
	t.Parallel()
	frames := [][]byte{deltaFrame(t, "Sending it")}
	frames = append(frames, converseToolFrames(t, 1, `{"to":"bo`, `b@x`, `.io"}`)...)
	frames = append(frames, testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`))

	var late atomic.Bool
	base := time.Now()
	r := &countRunner{inner: &maskRunner{from: streamEmail, to: "<EMAIL>"}}
	// A short max_hold_ms must not shorten the tool hold: only the absolute ceiling does.
	g, logs := loggedGuard(r, streamGuardConfig{headChars: 5, minChars: 1, maxHold: 100 * time.Millisecond})
	g.now = func() time.Time {
		if late.Load() {
			return base.Add(config.DefaultBedrockNative().ToolHold + time.Second)
		}
		return base
	}
	src := func(yield func([]byte, error) bool) {
		for i, f := range frames {
			if i == 2 {
				late.Store(true)
			}
			if !yield(f, nil) {
				return
			}
		}
	}
	out, pe := g.Run(context.Background(), iter.Seq2[[]byte, error](src))
	require.Nil(t, pe)
	requireReleasedUninspected(t, g, logs, frames, collectFrames(t, out), "time")
	assert.NotContains(t, strings.Join(r.segs, "|"), `"to"`, "the chain never read the input as a text")
}

// A small max_hold_ms does not switch tool inspection off.
func TestNativeToolDegrade_ShortMaxHoldStillInspectsTheCall(t *testing.T) {
	t.Parallel()
	frames := append([][]byte{deltaFrame(t, "Sending it")}, converseToolFrames(t, 1, `{"to":"bo`, `b@x.io"}`)...)
	frames = append(frames, testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`))
	base := time.Now()
	var step atomic.Int64
	g, _ := loggedGuard(&maskRunner{from: streamEmail, to: "<EMAIL>"},
		streamGuardConfig{headChars: 5, minChars: 100000, maxHold: 50 * time.Millisecond})
	g.now = func() time.Time { return base.Add(time.Duration(step.Load()) * 400 * time.Millisecond) }
	src := func(yield func([]byte, error) bool) {
		for i, f := range frames {
			if i >= 2 {
				step.Add(1) // 400ms per frame: far past max_hold_ms, far under the ceiling
			}
			if !yield(f, nil) {
				return
			}
		}
	}
	out, pe := g.Run(context.Background(), iter.Seq2[[]byte, error](src))
	require.Nil(t, pe)
	got := collectFrames(t, out)
	assert.NotContains(t, releasedText(t, got), streamEmail)
	assert.Equal(t, `{"to":"<EMAIL>"}`, fragmentsOf(got)[0])
	assert.Empty(t, g.degradedReason)
}

// P2: the stream ends before the call is closed.
func TestNativeToolDegrade_CallThatIsNeverClosedIsFlagged(t *testing.T) {
	t.Parallel()
	tool := converseToolFrames(t, 1, `{"to":"bo`, `b@x.io"}`)
	frames := append([][]byte{deltaFrame(t, "Sending it")}, tool[:len(tool)-1]...)
	g, logs := loggedGuard(&maskRunner{from: streamEmail, to: "<EMAIL>"}, toolBlocks)
	got, pe := runNativeGuard(t, g, frames)
	require.Nil(t, pe)
	requireReleasedUninspected(t, g, logs, frames, got, "no_stop")
}

// P8: another frame sits inside the call.
func TestNativeToolDegrade_UncleanCallIsFlagged(t *testing.T) {
	t.Parallel()
	tool := converseToolFrames(t, 1, `{"to":"bo`, `b@x.io"}`)
	frames := [][]byte{deltaFrame(t, "Sending it"), tool[0], tool[1], deltaFrame(t, "x"), tool[2], tool[3],
		testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`)}
	g, logs := loggedGuard(&maskRunner{from: streamEmail, to: "<EMAIL>"}, toolBlocks)
	got, pe := runNativeGuard(t, g, frames)
	require.Nil(t, pe)
	requireReleasedUninspected(t, g, logs, frames, got, "unclean")
}

// P9: the input is larger than the bytes the guard may hold.
func TestNativeToolDegrade_CallLargerThanTheByteBoundIsFlagged(t *testing.T) {
	t.Parallel()
	frags := []string{`{"to":"bob@x.io","pad":"`}
	for range 80 {
		frags = append(frags, strings.Repeat("a", 4000))
	}
	frags = append(frags, `"}`)
	frames := append([][]byte{deltaFrame(t, "Sending it")}, converseToolFrames(t, 1, frags...)...)
	frames = append(frames, testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`))
	g, logs := loggedGuard(&maskRunner{from: streamEmail, to: "<EMAIL>"}, toolBlocks)
	got, pe := runNativeGuard(t, g, frames)
	require.Nil(t, pe)
	requireReleasedUninspected(t, g, logs, frames, got, "size")
}

// A family whose tool calls are not understood is flagged too.
func TestNativeToolDegrade_UnsupportedFamilyIsFlagged(t *testing.T) {
	t.Parallel()
	frames := [][]byte{
		chunkFrame(t, `{"choices":[{"index":0,"delta":{"content":"hello there friend"}}]}`),
		chunkFrame(t, `{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"send","arguments":"{\"to\":\"someone\"}"}}]}}]}`),
		chunkFrame(t, `{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`),
	}
	r := &countRunner{inner: &sequenceRunner{}}
	g, logs := loggedGuard(r, toolBlocks)
	got, pe := runNativeGuard(t, g, frames)
	require.Nil(t, pe)
	requireReleasedUninspected(t, g, logs, frames, got, "unsupported")
	assert.Positive(t, r.tools, "an unhandled call keeps flowing through ToolCalls")
}

// A call that was held and read is not a degrade.
func TestNativeToolDegrade_InspectedCallIsNotFlagged(t *testing.T) {
	t.Parallel()
	frames := append([][]byte{deltaFrame(t, "Sending it")}, converseToolFrames(t, 1, `{"to":"someone"}`)...)
	frames = append(frames, testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`))
	g, logs := loggedGuard(&sequenceRunner{}, toolBlocks)
	got, pe := runNativeGuard(t, g, frames)
	require.Nil(t, pe)
	assert.Equal(t, frames, got)
	assert.Empty(t, g.degradedReason)
	assert.NotContains(t, logs.String(), "without inspecting")
}

// P5: two calls, each is read once: as its own segment, and not again through the
// ToolCalls of the segments that follow.
func TestNativeToolDegrade_AHandledCallIsNotInspectedTwice(t *testing.T) {
	t.Parallel()
	frames := [][]byte{deltaFrame(t, "Sending it")}
	frames = append(frames, converseToolFrames(t, 1, `{"to":"al`, `ice"}`)...)
	frames = append(frames, converseToolFrames(t, 2, `{"to":"bo`, `b@x.io"}`)...)
	frames = append(frames, deltaFrame(t, "and that is all"), testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`))
	r := &countRunner{inner: &maskRunner{from: streamEmail, to: "<EMAIL>"}}
	got, pe := runNativeGuard(t, nativeGuardFor(r, toolBlocks), frames)
	require.Nil(t, pe)
	assert.Zero(t, r.tools, "no segment carries a call the tool pass already read")
	var tools int
	for _, s := range r.segs {
		if strings.HasPrefix(s, "{") {
			tools++
		}
	}
	assert.Equal(t, 2, tools, "each call is a segment of its own, once")
	assert.Contains(t, strings.Join(fragmentsOf(got), ""), `{"to":"<EMAIL>"}`)
}

// A failed tool segment counts as a failure, like a failed block, and a success
// clears the count.
func TestNativeToolDegrade_FailuresAreCountedAndRetire(t *testing.T) {
	t.Parallel()
	admitAll := func(g *streamGuard, frames [][]byte) {
		for _, f := range frames {
			g.admit(g.seg.feed(f))
		}
	}
	tool := converseToolFrames(t, 1, `{"to":"someone"}`)

	t.Run("a failure is counted and the call released", func(t *testing.T) {
		t.Parallel()
		g := nativeGuardFor(failJSONRunner{}, toolBlocks)
		admitAll(g, tool)
		v := g.inspectTools(context.Background())
		assert.False(t, v.stop)
		assert.Equal(t, 1, g.failures)
		assert.Equal(t, "guard_error", g.degradedReason)
		assert.False(t, g.silenced)
	})
	t.Run("a success clears the count", func(t *testing.T) {
		t.Parallel()
		g := nativeGuardFor(&sequenceRunner{}, toolBlocks)
		g.failures = 2
		admitAll(g, tool)
		g.inspectTools(context.Background())
		assert.Zero(t, g.failures)
	})
	t.Run("consecutive failures retire the block loop", func(t *testing.T) {
		t.Parallel()
		g := nativeGuardFor(failJSONRunner{}, toolBlocks)
		g.gate = newBlockGate(g, 1, time.Hour)
		g.failures = maxConsecutiveFailures - 1
		admitAll(g, tool)
		g.inspectTools(context.Background())
		assert.True(t, g.silenced)
		assert.Equal(t, fallbackSegmentationUnavail, g.fallbackReason)
	})
}

// P6: a string that does not survive being read and written back is not
// rewritten: a mask on such an input ends the stream, and an input nothing masks
// is released as it came.
func TestNativeToolMask_LoneSurrogateIsNeverAlteredAndFailsOpenOnAMask(t *testing.T) {
	t.Parallel()
	t.Run("a mask fails open", func(t *testing.T) {
		t.Parallel()
		frames := append([][]byte{deltaFrame(t, "Sending it")}, converseToolFrames(t, 1, `{"x":"\ud83d","to":"bob@x.io"}`)...)
		frames = append(frames, testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`))
		got, pe, rt := runNativeGuardTraced(t, nativeGuardFor(&maskRunner{from: streamEmail, to: "<EMAIL>"}, toolBlocks), frames)
		require.Nil(t, pe)
		requireStreamFailedOpen(t, got, frames, rt, "tool_input_not_maskable")
	})
	t.Run("nothing to mask is released as it came", func(t *testing.T) {
		t.Parallel()
		frames := append([][]byte{deltaFrame(t, "Sending it")}, converseToolFrames(t, 1, `{"x":"\ud83d","to":"nobody"}`)...)
		frames = append(frames, testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`))
		got, pe := runNativeGuard(t, nativeGuardFor(&maskRunner{from: streamEmail, to: "<EMAIL>"}, toolBlocks), frames)
		require.Nil(t, pe)
		assert.Equal(t, frames, got)
	})
}

// A tool call whose inspection fails honours the stream's on_error like every other
// block: fail_closed ends the stream with the exception frame and releases none of
// the call, fail_open releases it as it came.
func TestNativeToolInspectionFailureHonoursOnError(t *testing.T) {
	t.Parallel()
	frames := append([][]byte{deltaFrame(t, "Sending it now")}, converseToolFrames(t, 1, `{"to":"bo`, `b@x.io"}`)...)
	frames = append(frames, testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`))

	t.Run("fail_closed ends the stream and releases nothing of the call", func(t *testing.T) {
		t.Parallel()
		cfg := streamGuardConfig{headChars: 5, minChars: 1, maxHold: time.Hour, onError: streamFailClosed}
		got, pe, _ := runNativeGuardTraced(t, nativeGuardFor(failJSONRunner{}, cfg), frames)
		require.Nil(t, pe)
		excType, _ := decodeException(t, got[len(got)-1])
		assert.Equal(t, "validationException", excType)
		assert.Empty(t, fragmentsOf(got[:len(got)-1]), "no fragment of the call was released")
		assert.NotContains(t, releasedText(t, got[:len(got)-1]), "b@x.io")
	})
	t.Run("fail_open releases the call as it came", func(t *testing.T) {
		t.Parallel()
		cfg := streamGuardConfig{headChars: 5, minChars: 1, maxHold: time.Hour, onError: streamFailOpen}
		got, pe, _ := runNativeGuardTraced(t, nativeGuardFor(failJSONRunner{}, cfg), frames)
		require.Nil(t, pe)
		assert.Equal(t, frames, got)
	})
	t.Run("fail_closed in the head is a status before the first byte", func(t *testing.T) {
		t.Parallel()
		toolFirst := append(converseToolFrames(t, 0, `{"to":"bo`, `b@x.io"}`), testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`))
		cfg := streamGuardConfig{headChars: 1000, minChars: 1000, maxHold: time.Hour, onError: streamFailClosed}
		got, pe, _ := runNativeGuardTraced(t, nativeGuardFor(failJSONRunner{}, cfg), toolFirst)
		if pe == nil {
			t.Fatalf("the head was released: %d frames", len(got))
		}
		assert.GreaterOrEqual(t, pe.StatusCode, 400)
	})
}

// Marking a call as read takes only that call out of what later segments carry: one
// that could not be held keeps flowing through ToolCalls, in its place.
func TestNativeToolDegrade_OnlyTheHandledCallLeavesTheSegments(t *testing.T) {
	t.Parallel()
	clean := converseToolFrames(t, 1, `{"to":"al`, `ice"}`)
	unclean := converseToolFrames(t, 2, `{"to":"bo`, `b"}`)
	frames := [][]byte{deltaFrame(t, "Sending it")}
	frames = append(frames, clean...)
	frames = append(frames, unclean[0], unclean[1], deltaFrame(t, "x"), unclean[2], unclean[3])
	frames = append(frames, testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`))

	var carried []string
	runner := &captureCallsRunner{inner: &sequenceRunner{}, onSegment: func(seg appplugins.StreamSegment) {
		for _, c := range seg.ToolCalls {
			carried = append(carried, c.Arguments)
		}
	}}
	_, pe := runNativeGuard(t, nativeGuardFor(runner, toolBlocks), frames)
	require.Nil(t, pe)
	assert.NotContains(t, strings.Join(carried, "|"), `alice`, "the call that was read is not carried again")
	assert.Contains(t, strings.Join(carried, "|"), `{"to":"bob"}`, "the one that could not be held still is")
}

type captureCallsRunner struct {
	inner     segmentRunner
	onSegment func(appplugins.StreamSegment)
}

func (r *captureCallsRunner) RunStreamSegment(ctx context.Context, in appplugins.StageInput, seg appplugins.StreamSegment) (*appplugins.SegmentOutcome, error) {
	if !seg.Closing {
		r.onSegment(seg)
	}
	return r.inner.RunStreamSegment(ctx, in, seg)
}

// The per-call bookkeeping of the native tool pass is for native streams: every
// other guarded stream keeps one copy of its tool arguments, not three.
func TestStreamGuard_OnlyNativeStreamsKeepToolBookkeeping(t *testing.T) {
	t.Parallel()
	call := []adapter.StreamToolCallDelta{{Index: 0, ID: "call_1", Name: "lookup", ArgumentsDelta: `{"q":"x"}`}}
	for _, native := range []bool{false, true} {
		g := nativeGuardFor(&countRunner{inner: &maskRunner{}}, streamGuardConfig{})
		g.native = native
		g.admit(&streamEvent{toolCalls: call, toolIndex: 0}, nil)
		assert.Len(t, g.tools.calls(), 1)
		assert.Equal(t, native, len(g.unhandledTools.calls()) == 1, "native=%v", native)
		assert.Equal(t, native, len(g.toolEvents) == 1, "native=%v", native)
	}
}

// partialFailRunner answers the tool input with a mask and an error: an earlier
// entry masked it and a later entry failed.
type partialFailRunner struct{}

func (r partialFailRunner) RunStreamSegment(_ context.Context, _ appplugins.StageInput, seg appplugins.StreamSegment) (*appplugins.SegmentOutcome, error) {
	if !seg.Closing && strings.HasPrefix(strings.TrimSpace(seg.Accumulated), "{") {
		return &appplugins.SegmentOutcome{
			HasTransform: true,
			Transformed:  strings.Replace(seg.Accumulated, "bob@x.io", "[EMAIL]", 1),
		}, errors.New("later entry down")
	}
	return &appplugins.SegmentOutcome{}, nil
}

// A later entry failing after an earlier one masked the tool input follows the
// stream's on_error, as the head and the blocks do: fail_closed stops the stream,
// fail_open releases the call with the mask applied and never the raw input.
func TestNativeToolInspection_PartialMaskThenFailureFollowsOnError(t *testing.T) {
	t.Parallel()
	frames := append([][]byte{deltaFrame(t, "Sending it now")}, converseToolFrames(t, 1, `{"to":"bo`, `b@x.io"}`)...)
	frames = append(frames, testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`))

	t.Run("fail_closed stops the stream and releases nothing of the call", func(t *testing.T) {
		t.Parallel()
		cfg := streamGuardConfig{headChars: 5, minChars: 1, maxHold: time.Hour, onError: streamFailClosed}
		g := nativeGuardFor(partialFailRunner{}, cfg)
		got, pe, _ := runNativeGuardTraced(t, g, frames)
		require.Nil(t, pe)
		excType, _ := decodeException(t, got[len(got)-1])
		assert.Equal(t, "validationException", excType)
		assert.Empty(t, fragmentsOf(got[:len(got)-1]))
		assert.Positive(t, g.failures)
	})
	t.Run("fail_open releases the call masked, never raw", func(t *testing.T) {
		t.Parallel()
		cfg := streamGuardConfig{headChars: 5, minChars: 1, maxHold: time.Hour, onError: streamFailOpen}
		got, pe, _ := runNativeGuardTraced(t, nativeGuardFor(partialFailRunner{}, cfg), frames)
		require.Nil(t, pe)
		joined := strings.Join(fragmentsOf(got), "")
		assert.Contains(t, joined, "[EMAIL]")
		assert.NotContains(t, joined, "bob@x.io")
	})
}

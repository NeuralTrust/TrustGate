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

package plugins

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil/textchunk"
)

// chunkGuard is a stream inspector that answers each call from a function of the
// segment it was handed, safe for the concurrent calls a chunked block makes.
type chunkGuard struct {
	fakePlugin
	mu   sync.Mutex
	fn   func(seg StreamSegment) (*SegmentVerdict, error)
	segs []StreamSegment
	last StreamReport
}

func (g *chunkGuard) InspectSegment(_ context.Context, _ ExecInput, seg StreamSegment) (*SegmentVerdict, error) {
	g.mu.Lock()
	if seg.Closing {
		g.last = seg.Report
	} else {
		g.segs = append(g.segs, seg)
	}
	g.mu.Unlock()
	if seg.Closing {
		return nil, nil
	}
	return g.fn(seg)
}

func (g *chunkGuard) StreamSettings(settings map[string]any) (bool, StreamOptions) {
	window, _ := settings["max_accumulated_bytes"].(int)
	return true, StreamOptions{MaxAccumulatedBytes: window, OnError: "fail_open"}
}

func (g *chunkGuard) seen() []StreamSegment {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]StreamSegment(nil), g.segs...)
}

func chunkChain(t *testing.T, mode policy.Mode, window int, fn func(StreamSegment) (*SegmentVerdict, error)) (*executor, StageInput, *chunkGuard) {
	t.Helper()
	g := &chunkGuard{
		fakePlugin: fakePlugin{name: "guard", stages: []policy.Stage{policy.StagePreResponse}, result: &Result{StatusCode: 200}},
		fn:         fn,
	}
	pol := policies(t, polSpec{slug: "guard", enabled: true, priority: 10, stages: []policy.Stage{policy.StagePreResponse}})[0]
	pol.Mode = mode
	pol.Settings = map[string]any{"enabled": true, "max_accumulated_bytes": window}
	exec, ok := NewExecutor(newRegistry(t, g), nil).(*executor)
	require.True(t, ok)
	return exec, failureInput([]*policy.Policy{pol}), g
}

func words(n int) string {
	return strings.Repeat("a stream of ordinary words. ", n/28+1)[:n]
}

func allow(StreamSegment) (*SegmentVerdict, error) { return &SegmentVerdict{}, nil }

func TestRunStreamSegment_ABlockLargerThanTheWindowIsScreenedInChunks(t *testing.T) {
	t.Parallel()
	const window = 8192
	text := words(40000)
	exec, in, guard := chunkChain(t, policy.ModeEnforce, window, allow)
	ctx, _, publish := failureStreamCtx(t)
	seg := StreamSegment{StreamID: "s", Seq: 1, Text: text, Accumulated: text}

	out, err := exec.RunStreamSegment(ctx, in, seg)

	require.NoError(t, err)
	assert.False(t, out.Block)
	seen := guard.seen()
	assert.Len(t, seen, textchunk.Count(text, streamChunkSpec(window)))
	assert.Len(t, seen, 6)
	covered := 0
	for _, s := range seen {
		assert.LessOrEqual(t, len(s.Accumulated), window, "no call carries more than the entry's window")
		assert.True(t, s.Truncated)
		assert.Equal(t, s.Accumulated, s.Text, "the whole block is new text")
		covered = max(covered, len(s.Accumulated))
	}

	closing := StreamSegment{StreamID: "s", Seq: 2, Closing: true}
	_, err = exec.RunStreamSegment(ctx, in, closing)
	require.NoError(t, err)
	publish()
	assert.Equal(t, 1, guard.last.ChunkedEvals)
}

func TestRunStreamSegment_AMaskInTwoChunksBecomesOneTransform(t *testing.T) {
	t.Parallel()
	const window = 8192
	email := "victim@example.com"
	cut := window - len(email)/2
	text := words(cut) + email + words(20000)
	mask := func(seg StreamSegment) (*SegmentVerdict, error) {
		if !strings.Contains(seg.Accumulated, email) {
			return &SegmentVerdict{}, nil
		}
		return &SegmentVerdict{HasTransform: true, Transformed: strings.ReplaceAll(seg.Accumulated, email, "{EMAIL}")}, nil
	}
	exec, in, _ := chunkChain(t, policy.ModeEnforce, window, mask)
	seg := StreamSegment{StreamID: "s", Seq: 1, Text: text, Accumulated: text}

	out, err := exec.RunStreamSegment(context.Background(), in, seg)

	require.NoError(t, err)
	require.True(t, out.HasTransform)
	assert.Equal(t, strings.ReplaceAll(text, email, "{EMAIL}"), out.Transformed)
}

func TestRunStreamSegment_ABlockedChunkCutsTheStream(t *testing.T) {
	t.Parallel()
	const window = 8192
	text := words(10) + " BLOCKME " + words(50000)
	blocker := func(seg StreamSegment) (*SegmentVerdict, error) {
		if strings.Contains(seg.Accumulated, "BLOCKME") {
			return &SegmentVerdict{Block: true, Type: "guardrail_blocked", Message: "no"}, nil
		}
		time.Sleep(20 * time.Millisecond)
		return &SegmentVerdict{}, nil
	}
	exec, in, guard := chunkChain(t, policy.ModeEnforce, window, blocker)
	out, err := exec.RunStreamSegment(context.Background(), in, StreamSegment{StreamID: "s", Seq: 1, Text: text, Accumulated: text})

	require.NoError(t, err)
	assert.True(t, out.Block)
	assert.Equal(t, "guardrail_blocked", out.Type)
	assert.Less(t, len(guard.seen()), textchunk.Count(text, streamChunkSpec(window)), "the chunks after the block are skipped")
}

func TestRunStreamSegment_MoreThanEightChunksIsCutInEnforceAndAbsorbedInObserve(t *testing.T) {
	t.Parallel()
	const window = 8192
	spec := streamChunkSpec(window)
	text := words(100000)
	require.Greater(t, textchunk.Count(text, spec), maxStreamChunks)
	for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			exec, in, guard := chunkChain(t, mode, window, allow)
			ctx, _, publish := failureStreamCtx(t)
			defer publish()

			out, err := exec.RunStreamSegment(ctx, in, StreamSegment{StreamID: "s", Seq: 1, Text: text, Accumulated: text})

			require.NoError(t, err)
			assert.Empty(t, guard.seen(), "nothing is sent for a block that cannot be screened whole")
			if mode == policy.ModeEnforce {
				assert.True(t, out.Block)
				assert.Equal(t, TypeGuardrailInputUninspectable, out.Type)
				return
			}
			assert.False(t, out.Block)
			assert.Equal(t, 1, out.FailedEntries)
		})
	}
}

func TestRunStreamSegment_AnAvailabilityFailureKeepsTheMasksOfTheOtherChunks(t *testing.T) {
	t.Parallel()
	const window = 8192
	email := "victim@example.com"
	text := email + " " + words(30000)
	fn := func(seg StreamSegment) (*SegmentVerdict, error) {
		if strings.Contains(seg.Accumulated, email) {
			return &SegmentVerdict{HasTransform: true, Transformed: strings.ReplaceAll(seg.Accumulated, email, "{EMAIL}")}, nil
		}
		if strings.HasPrefix(seg.Accumulated, "a stream of ordinary words. a stream of ordinary words. a stream") && len(seg.Accumulated) > 0 {
			return nil, WrapExternalStreamFailure("guard", FailureTransport, "", errors.New("provider down"))
		}
		return &SegmentVerdict{}, nil
	}
	exec, in, _ := chunkChain(t, policy.ModeEnforce, window, fn)
	ctx, _, publish := failureStreamCtx(t)
	defer publish()

	out, err := exec.RunStreamSegment(ctx, in, StreamSegment{StreamID: "s", Seq: 1, Text: text, Accumulated: text})

	require.NoError(t, err)
	require.True(t, out.HasTransform, "forwarding the original would send what the first chunk masked")
	assert.Equal(t, strings.ReplaceAll(text, email, "{EMAIL}"), out.Transformed)
}

func TestRunStreamSegment_AMaskThatCannotBeMappedBackCuts(t *testing.T) {
	t.Parallel()
	const window = 8192
	text := words(30000)
	garble := func(seg StreamSegment) (*SegmentVerdict, error) {
		var b strings.Builder
		for i := 0; i < 700; i++ {
			b.WriteString("x" + strings.Repeat("y", i%5) + " ")
		}
		return &SegmentVerdict{HasTransform: true, Transformed: b.String()}, nil
	}
	exec, in, _ := chunkChain(t, policy.ModeEnforce, window, garble)
	ctx, _, publish := failureStreamCtx(t)
	defer publish()

	out, err := exec.RunStreamSegment(ctx, in, StreamSegment{StreamID: "s", Seq: 1, Text: text, Accumulated: text})

	require.NoError(t, err)
	assert.True(t, out.Block, "a mask over a finding that cannot be applied cuts instead of releasing the original")
}

func TestRunStreamSegment_ABlockWithinTheWindowIsNotChunked(t *testing.T) {
	t.Parallel()
	exec, in, guard := chunkChain(t, policy.ModeEnforce, 8192, allow)
	text := words(8000)

	_, err := exec.RunStreamSegment(context.Background(), in, StreamSegment{StreamID: "s", Seq: 1, Text: text, Accumulated: text})

	require.NoError(t, err)
	require.Len(t, guard.seen(), 1)
	assert.False(t, guard.seen()[0].Truncated)
}

// sequentialGuard is a chunkGuard that declares one piece at a time and records
// the most calls it saw in flight.
type sequentialGuard struct {
	*chunkGuard
	parallel int
	inflight atomic.Int32
	peak     atomic.Int32
}

func (g *sequentialGuard) StreamChunkParallel() int { return g.parallel }

func (g *sequentialGuard) InspectSegment(ctx context.Context, in ExecInput, seg StreamSegment) (*SegmentVerdict, error) {
	if !seg.Closing {
		n := g.inflight.Add(1)
		defer g.inflight.Add(-1)
		for {
			p := g.peak.Load()
			if n <= p || g.peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return g.chunkGuard.InspectSegment(ctx, in, seg)
}

func sequentialChain(t *testing.T, window, parallel int, fn func(StreamSegment) (*SegmentVerdict, error)) (*executor, StageInput, *sequentialGuard) {
	t.Helper()
	base := &chunkGuard{
		fakePlugin: fakePlugin{name: "guard", stages: []policy.Stage{policy.StagePreResponse}, result: &Result{StatusCode: 200}},
		fn:         fn,
	}
	g := &sequentialGuard{chunkGuard: base, parallel: parallel}
	pol := policies(t, polSpec{slug: "guard", enabled: true, priority: 10, stages: []policy.Stage{policy.StagePreResponse}})[0]
	pol.Mode = policy.ModeEnforce
	pol.Settings = map[string]any{"enabled": true, "max_accumulated_bytes": window}
	exec, ok := NewExecutor(newRegistry(t, g), nil).(*executor)
	require.True(t, ok)
	return exec, failureInput([]*policy.Policy{pol}), g
}

func TestRunStreamSegment_AnInspectorThatDeclaresOneAtATimeIsSentPiecesSequentially(t *testing.T) {
	t.Parallel()
	const window = 8192
	text := words(40000)
	for parallel, wantPeak := range map[int]int32{1: 1, 4: 4} {
		exec, in, g := sequentialChain(t, window, parallel, allow)
		_, err := exec.RunStreamSegment(context.Background(), in, StreamSegment{StreamID: "s", Seq: 1, Text: text, Accumulated: text})
		require.NoError(t, err)
		assert.Len(t, g.seen(), 6)
		if wantPeak == 1 {
			assert.EqualValues(t, 1, g.peak.Load(), "the pieces were sent one at a time")
		} else {
			assert.Greater(t, g.peak.Load(), int32(1), "the default sends several at once")
		}
	}
}

// A throttle on the second piece of a sequential inspector waited behind the
// first, so the block's own size plausibly spent the quota: input. The same
// throttle on an inspector that sends four at once is in the first round.
func TestRunStreamSegment_AThrottleOnASequentialPieceIsInputAndOnAFirstRoundPieceIsNot(t *testing.T) {
	t.Parallel()
	const window = 8192
	var b strings.Builder
	for i := 0; b.Len() < 40000; i++ {
		fmt.Fprintf(&b, "w%06d ", i)
	}
	text := b.String()
	second := textchunk.Split(text, streamChunkSpec(window))[1].Text
	pick := func(seg StreamSegment) (*SegmentVerdict, error) {
		if seg.Accumulated == second {
			return nil, newExternalStreamFailure("guard", FailureTransport, DetailThrottled, errors.New("429"))
		}
		return &SegmentVerdict{}, nil
	}

	exec, in, _ := sequentialChain(t, window, 1, pick)
	out, err := exec.RunStreamSegment(context.Background(), in, StreamSegment{StreamID: "s", Seq: 1, Text: text, Accumulated: text})
	require.NoError(t, err)
	require.True(t, out.Block, "the piece that waited behind the first was throttled by the block's own size")
	assert.Equal(t, TypeGuardrailInputUninspectable, out.Type)

	exec, in, _ = sequentialChain(t, window, 4, pick)
	out, err = exec.RunStreamSegment(context.Background(), in, StreamSegment{StreamID: "s", Seq: 1, Text: text, Accumulated: text})
	require.NoError(t, err)
	assert.False(t, out.Block, "a first-round throttle is the provider's load and fails open")
	assert.Equal(t, 1, out.FailedEntries)
}

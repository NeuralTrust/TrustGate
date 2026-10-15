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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

// spacedGuard declares what a provider with a quota a second declares: pieces one
// at a time, spaced, with a throttle that is other traffic, and a short piece
// timeout.
type spacedGuard struct {
	*chunkGuard
	spacers atomic.Int32
	waits   atomic.Int32
	gap     time.Duration
	timeout time.Duration
	hang    bool
}

func (g *spacedGuard) InspectSegment(ctx context.Context, in ExecInput, seg StreamSegment) (*SegmentVerdict, error) {
	if g.hang && !seg.Closing {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return g.chunkGuard.InspectSegment(ctx, in, seg)
}

func (g *spacedGuard) StreamChunkParallel() int           { return 1 }
func (g *spacedGuard) StreamThrottleIsOtherTraffic() bool { return true }
func (g *spacedGuard) StreamGuardTimeout() time.Duration  { return g.timeout }
func (g *spacedGuard) SpaceStreamPieces(ExecInput) func(context.Context, int) error {
	g.spacers.Add(1)
	return func(ctx context.Context, _ int) error {
		g.waits.Add(1)
		select {
		case <-time.After(g.gap):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func spacedChain(t *testing.T, window int, g *spacedGuard) (*executor, StageInput) {
	t.Helper()
	pol := policies(t, polSpec{slug: "guard", enabled: true, priority: 10, stages: []policy.Stage{policy.StagePreResponse}})[0]
	pol.Mode = policy.ModeEnforce
	pol.Settings = map[string]any{"enabled": true, "max_accumulated_bytes": window}
	exec, ok := NewExecutor(newRegistry(t, g), nil).(*executor)
	require.True(t, ok)
	return exec, failureInput([]*policy.Policy{pol})
}

func newSpacedGuard(fn func(StreamSegment) (*SegmentVerdict, error)) *spacedGuard {
	return &spacedGuard{
		chunkGuard: &chunkGuard{
			fakePlugin: fakePlugin{name: "guard", stages: []policy.Stage{policy.StagePreResponse}, result: &Result{StatusCode: 200}},
			fn:         fn,
		},
		timeout: 150 * time.Millisecond,
	}
}

// The pieces of one block are spaced by one spacer made for that block, and a
// throttle on a piece behind the first is other traffic: the stream is not cut.
func TestRunStreamSegment_SpacedPiecesShareOneSpacerAndAThrottleOnOneIsAvailability(t *testing.T) {
	t.Parallel()
	text := words(40000)
	g := newSpacedGuard(func(seg StreamSegment) (*SegmentVerdict, error) {
		if seg.Part == 3 {
			return nil, newExternalStreamFailure("guard", FailureTransport, DetailThrottled, errors.New("429"))
		}
		return &SegmentVerdict{}, nil
	})
	exec, in := spacedChain(t, 8192, g)

	out, err := exec.RunStreamSegment(context.Background(), in, StreamSegment{StreamID: "s", Seq: 1, Text: text, Accumulated: text})

	require.NoError(t, err)
	assert.False(t, out.Block, "a throttle on a spaced piece is other traffic")
	assert.EqualValues(t, 1, out.FailedEntries)
	assert.EqualValues(t, 1, g.spacers.Load(), "one spacer for the block")
	assert.EqualValues(t, 6, g.waits.Load(), "every piece waits for the spacer")
}

// The block is bounded by a deadline of GuardTimeout per round, at most four of
// them: a provider that hangs on every call holds the stream for that and no
// longer, and is the provider being slow, so the stream is not cut.
func TestRunStreamSegment_AHangOnEveryPieceHoldsTheBlockForABoundedTimeAndFailsOpen(t *testing.T) {
	t.Parallel()
	text := words(40000)
	g := newSpacedGuard(allow)
	g.hang = true
	exec, in := spacedChain(t, 8192, g)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := time.Now()
	out, err := exec.RunStreamSegment(ctx, in, StreamSegment{StreamID: "s", Seq: 1, Text: text, Accumulated: text})

	require.NoError(t, err)
	assert.Less(t, time.Since(started), 4*g.timeout+time.Second, "the block's deadline is four piece timeouts at most")
	assert.False(t, out.Block, "a hang is availability")
	assert.EqualValues(t, 1, out.FailedEntries)
}

// Pieces that every spacing wait delays past the block's deadline, with calls that
// answer at once, ran the deadline out with the block's own size: the block is cut
// as chunk_budget, and the stream is held no longer than the deadline.
func TestRunStreamSegment_PiecesSpacedPastTheBlockDeadlineAreCutAsInput(t *testing.T) {
	t.Parallel()
	text := words(40000)
	g := newSpacedGuard(func(StreamSegment) (*SegmentVerdict, error) {
		return nil, newExternalStreamFailure("guard", FailureTransport, DetailThrottled, errors.New("429"))
	})
	g.gap = 400 * time.Millisecond
	exec, in := spacedChain(t, 8192, g)

	started := time.Now()
	out, err := exec.RunStreamSegment(context.Background(), in, StreamSegment{StreamID: "s", Seq: 1, Text: text, Accumulated: text})

	require.NoError(t, err)
	assert.Less(t, time.Since(started), 4*g.timeout+time.Second)
	assert.True(t, out.Block, "the block's own size used the time")
	assert.Equal(t, TypeGuardrailInputUninspectable, out.Type)
}

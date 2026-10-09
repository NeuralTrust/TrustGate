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

package textchunk

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func chunksOf(n int) []Chunk {
	out := make([]Chunk, n)
	for i := range out {
		out[i] = Chunk{Start: i, End: i + 1, Text: "x"}
	}
	return out
}

func TestRunNeverExceedsParallel(t *testing.T) {
	t.Parallel()
	var inFlight, peak atomic.Int32
	out := Run(context.Background(), chunksOf(20), RunOptions{Parallel: 3},
		func(_ context.Context, i int, _ Chunk) (int, error) {
			n := inFlight.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			inFlight.Add(-1)
			return i, nil
		})
	require.Len(t, out, 20)
	assert.LessOrEqual(t, peak.Load(), int32(3))
	assert.Equal(t, int32(3), peak.Load(), "the bound is used")
	for i, o := range out {
		assert.True(t, o.Started)
		assert.Equal(t, i, o.Value, "outcomes keep chunk order")
	}
}

func TestRunStopOnSkipsTheRestAndCancelsTheCallsInFlight(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	started := map[int]bool{}
	out := Run(context.Background(), chunksOf(10), RunOptions{Parallel: 2, StopOn: func(i int) bool { return i == 1 }},
		func(ctx context.Context, i int, _ Chunk) (string, error) {
			mu.Lock()
			started[i] = true
			mu.Unlock()
			if i == 1 {
				return "blocked", nil
			}
			<-ctx.Done()
			return "", ctx.Err()
		})
	assert.Equal(t, "blocked", out[1].Value)
	assert.ErrorIs(t, out[0].Err, context.Canceled, "the call in flight is cancelled")
	skipped := 0
	for i, o := range out {
		if !o.Started {
			skipped++
			assert.False(t, started[i])
		}
	}
	assert.Positive(t, skipped, "chunks after the stop are never sent")
}

func TestRunReportsChunksThatNeverStartedWhenTheBudgetEnds(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	out := Run(ctx, chunksOf(8), RunOptions{Parallel: 1},
		func(ctx context.Context, _ int, _ Chunk) (int, error) {
			<-ctx.Done()
			return 0, ctx.Err()
		})
	assert.True(t, out[0].Started)
	assert.ErrorIs(t, out[0].Err, context.DeadlineExceeded)
	for _, o := range out[1:] {
		assert.False(t, o.Started)
	}
}

func TestRunKeepsGoingAfterAFailedChunk(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	out := Run(context.Background(), chunksOf(4), RunOptions{Parallel: 1},
		func(_ context.Context, i int, _ Chunk) (int, error) {
			if i == 1 {
				return 0, boom
			}
			return i, nil
		})
	assert.ErrorIs(t, out[1].Err, boom)
	assert.True(t, out[3].Started)
	assert.NoError(t, out[3].Err)
}

func TestRunTurnsAPanicIntoThatChunksError(t *testing.T) {
	t.Parallel()
	out := Run(context.Background(), chunksOf(2), RunOptions{Parallel: 2},
		func(_ context.Context, i int, _ Chunk) (int, error) {
			if i == 0 {
				panic("bad")
			}
			return 1, nil
		})
	assert.Error(t, out[0].Err)
	assert.NoError(t, out[1].Err)
}

func TestRunDoesNotStartAChunkThatWaitedWhenLessThanTheReserveRemains(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	out := Run(ctx, chunksOf(8), RunOptions{Parallel: 2, Reserve: 300 * time.Millisecond},
		func(_ context.Context, _ int, _ Chunk) (int, error) {
			time.Sleep(150 * time.Millisecond)
			return 0, nil
		})

	assert.True(t, out[0].Started && out[1].Started, "the first round never waits and is never held back")
	assert.False(t, out[0].Waited)
	assert.True(t, out[2].Started, "250ms remain, above the 100ms the reserve is capped at (a quarter of the budget)")
	assert.True(t, out[2].Waited)
	started := 0
	for _, o := range out {
		if o.Started {
			started++
		}
	}
	assert.Less(t, started, 8, "the chunks behind the reserve are left")
	assert.False(t, out[7].Started)
}

func TestRunCapsTheReserveAtAQuarterOfTheBudget(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out := Run(ctx, chunksOf(6), RunOptions{Parallel: 2, Reserve: time.Hour},
		func(_ context.Context, _ int, _ Chunk) (int, error) { return 0, nil })

	for i, o := range out {
		assert.True(t, o.Started, "chunk %d: an operator's short budget must not refuse every request of several rounds", i)
	}
}

func TestRunMarksAChunkCutByTheDeadlineAfterWaiting(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	out := Run(ctx, chunksOf(4), RunOptions{Parallel: 2},
		func(ctx context.Context, i int, _ Chunk) (int, error) {
			if i == 2 {
				<-ctx.Done()
				return 0, ctx.Err()
			}
			if i == 0 {
				return 0, errors.New("provider says no")
			}
			return 0, nil
		})

	assert.True(t, out[2].Waited)
	assert.True(t, out[2].BudgetCut, "ended on the deadline after queueing behind the run's own chunks")
	assert.False(t, out[0].BudgetCut, "an error that is not the deadline's is not a budget cut")
	assert.False(t, out[1].BudgetCut)
}

func TestRunDoesNotCallAStopOnCancelABudgetCut(t *testing.T) {
	t.Parallel()
	out := Run(context.Background(), chunksOf(4), RunOptions{Parallel: 4, StopOn: func(i int) bool { return i == 0 }},
		func(ctx context.Context, i int, _ Chunk) (int, error) {
			if i == 0 {
				return 0, nil
			}
			<-ctx.Done()
			return 0, ctx.Err()
		})

	for i := 1; i < 4; i++ {
		assert.Error(t, out[i].Err)
		assert.False(t, out[i].BudgetCut, "a chunk cancelled by StopOn was not cut by a deadline")
	}
}

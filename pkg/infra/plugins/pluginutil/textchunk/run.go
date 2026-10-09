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
	"fmt"
	"sync"
	"time"
)

// RunOptions bounds a Run.
type RunOptions struct {
	// Parallel is the most calls in flight; values below 1 mean 1.
	Parallel int
	// StopOn is called, one call at a time, after chunk i completes. When it
	// returns true the chunks that have not started are skipped and the calls
	// in flight are cancelled through their context.
	StopOn func(i int) bool
	// Reserve is the least time a chunk that has to wait for a slot may start
	// with: when ctx's deadline is closer than that the chunk, and every one
	// behind it, is not started. A chunk of the first round (index below
	// Parallel) never waits and is not held back, and the reserve is capped at a
	// quarter of the time ctx had when the run began, so a short budget that an
	// operator configured shrinks the reserve instead of refusing every request
	// of more than one round. Zero means no reserve.
	Reserve time.Duration
	// Before is called in the chunk's goroutine, once the chunk has a slot and
	// before its call, to hold a chunk back (spacing a quota, say). Its time is
	// not part of Outcome.Took, which is the provider's alone, and an error from
	// it is the chunk's error.
	Before func(ctx context.Context, i int, c Chunk) error
}

// EffectiveReserve is the reserve a Run really holds back: Run caps it at a
// quarter of the budget, so a short budget that an operator configured shrinks
// the reserve instead of refusing every request of more than one round.
func EffectiveReserve(reserve, budget time.Duration) time.Duration {
	return min(reserve, budget/4)
}

// SlowCall is how long one call has to take before it is the provider being
// slow and not the request: twice the effective reserve, which is itself about
// twice a call's usual latency. See ClassifyChunks in the plugins package.
func SlowCall(reserve, budget time.Duration) time.Duration {
	return 2 * EffectiveReserve(reserve, budget)
}

// SlowCallOf is SlowCall for a Run over ctx, whose reserve Run itself caps at a
// quarter of the time ctx has left: it reads that time from ctx's deadline, so a
// parent's earlier deadline shortens the threshold with the reserve. It is zero,
// which no call exceeds, when ctx has no deadline. Call it before Run.
func SlowCallOf(ctx context.Context, reserve time.Duration) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	return SlowCall(reserve, time.Until(deadline))
}

// Rounds is how many rounds of at most parallel calls n chunks take.
func Rounds(n, parallel int) int {
	return (n + max(1, parallel) - 1) / max(1, parallel)
}

// Admits reports whether n chunks sent parallel at a time fit a budget with
// headroom: their estimate, one effective reserve per round, is at most half of
// it. Half is what lets a provider answer in up to twice the reserve on every
// round, which SlowCall treats as normal, without the budget cutting a chunk
// whose time the request's own size used. A single chunk is always admitted.
func Admits(n, parallel int, reserve, budget time.Duration) bool {
	if n <= 1 {
		return true
	}
	return time.Duration(Rounds(n, parallel))*EffectiveReserve(reserve, budget) <= budget/2
}

// MaxChunks is the most chunks Admits for a budget, at most limit and never
// fewer than one. A ceiling taken from it is the same as the estimate's, so a
// text above it is refused as chunk_limit and a text at it always fits.
func MaxChunks(limit, parallel int, reserve, budget time.Duration) int {
	r := EffectiveReserve(reserve, budget)
	if r <= 0 {
		return max(1, limit)
	}
	return max(1, min(limit, int((budget/2)/r)*max(1, parallel)))
}

// Outcome is what evaluating one chunk produced. Started is false when the
// chunk was never sent because the context ended, the reserve was not there or
// StopOn fired first: the caller decides what that means, this package does not.
//
// Waited says the chunk was queued behind chunks of the same run (its index is
// at least Parallel), and BudgetCut says its call returned an error while
// ctx's deadline had passed. Both together are a chunk whose time the request's
// own earlier chunks used up. A chunk of the first round that is cut was the
// provider being slow, and a call that ended on its own timeout leaves
// BudgetCut false because ctx's deadline had not passed.
//
// Took is how long the call itself ran, without what RunOptions.Before held it
// back for and without what the call spent in Pause: the provider's time, which
// says whether it was slow.
type Outcome[T any] struct {
	Value     T
	Err       error
	Started   bool
	Waited    bool
	BudgetCut bool
	Took      time.Duration
}

// Run evaluates fn over chunks in index order with at most o.Parallel calls in
// flight and returns one Outcome per chunk, in chunk order. A failed chunk does
// not stop the others; only StopOn and the end of ctx do. A panic in fn is
// returned as that chunk's error.
func Run[T any](ctx context.Context, chunks []Chunk, o RunOptions,
	fn func(ctx context.Context, i int, c Chunk) (T, error),
) []Outcome[T] {
	out := make([]Outcome[T], len(chunks))
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	parallel := max(1, o.Parallel)
	reserve := o.Reserve
	if deadline, ok := ctx.Deadline(); ok {
		reserve = min(reserve, time.Until(deadline)/4)
	}
	sem := make(chan struct{}, parallel)
	var wg, stopMu = sync.WaitGroup{}, sync.Mutex{}
dispatch:
	for i := range chunks {
		select {
		case sem <- struct{}{}:
		case <-runCtx.Done():
			break dispatch
		}
		if runCtx.Err() != nil || (i >= parallel && lacksReserve(runCtx, reserve)) {
			<-sem
			break
		}
		out[i].Started = true
		out[i].Waited = i >= parallel
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			var v T
			var err error
			if o.Before != nil {
				err = o.Before(runCtx, i, chunks[i])
			}
			if err == nil {
				pauses := &pauseClock{reserve: reserve}
				began := time.Now()
				v, err = call(context.WithValue(runCtx, pauseKey{}, pauses), i, chunks[i], fn)
				out[i].Took = max(0, time.Since(began)-pauses.total())
			}
			out[i].Value, out[i].Err = v, err
			out[i].BudgetCut = err != nil && errors.Is(runCtx.Err(), context.DeadlineExceeded)
			if o.StopOn != nil {
				stopMu.Lock()
				stop := o.StopOn(i)
				stopMu.Unlock()
				if stop {
					cancel()
				}
			}
		}()
	}
	wg.Wait()
	return out
}

type pauseKey struct{}

// pauseClock is what a call spent waiting in Pause, and the effective reserve
// its waits are capped at.
type pauseClock struct {
	reserve time.Duration
	mu      sync.Mutex
	waited  time.Duration
}

func (c *pauseClock) total() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.waited
}

// PauseCap is the longest a call of a Run over ctx may wait in Pause: the
// effective reserve of that Run. It is zero, no cap, outside a Run or when the
// Run has no reserve.
func PauseCap(ctx context.Context) time.Duration {
	if c, ok := ctx.Value(pauseKey{}).(*pauseClock); ok {
		return c.reserve
	}
	return 0
}

// Pause waits d, or until ctx ends, and reports whether the whole wait was
// taken. Inside a Run the wait is not part of the call's Outcome.Took: a call
// that backs off before a retry waits for its own reasons, and Took is only the
// provider's time.
func Pause(ctx context.Context, d time.Duration) bool {
	began := time.Now()
	timer := time.NewTimer(d)
	defer timer.Stop()
	var done bool
	select {
	case <-ctx.Done():
	case <-timer.C:
		done = true
	}
	if c, ok := ctx.Value(pauseKey{}).(*pauseClock); ok {
		c.mu.Lock()
		c.waited += time.Since(began)
		c.mu.Unlock()
	}
	return done
}

func lacksReserve(ctx context.Context, reserve time.Duration) bool {
	if reserve <= 0 {
		return false
	}
	deadline, ok := ctx.Deadline()
	return ok && time.Until(deadline) < reserve
}

func call[T any](ctx context.Context, i int, c Chunk,
	fn func(ctx context.Context, i int, c Chunk) (T, error),
) (v T, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("textchunk: chunk %d panicked: %v", i, r)
		}
	}()
	return fn(ctx, i, c)
}

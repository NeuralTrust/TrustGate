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
	"net"
	"sync"
	"sync/atomic"
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
	// behind it, is not started. A chunk of the first round never waits and is
	// not held back (index below Parallel, or under LeadAlone 1..Parallel,
	// released with the first free slots and queued behind no chunk but the
	// lead, whose time is its own call and retry, not the text's size), and the
	// reserve is capped at a
	// quarter of the time ctx had when the run began, so a short budget that an
	// operator configured shrinks the reserve instead of refusing every request
	// of more than one round. Zero means no reserve.
	Reserve time.Duration
	// Before is called in the chunk's goroutine, once the chunk has a slot and
	// before its call, to hold a chunk back (spacing a quota, say). Its time is
	// not part of Outcome.Took, which is the provider's alone, and an error from
	// it is the chunk's error.
	Before func(ctx context.Context, i int, c Chunk) error
	// LeadAlone runs chunk 0, with whatever retry fn gives it, to completion
	// before any other chunk starts: the chunks are then sent in the order of the
	// text, so a throttle on chunk 0 can only be other traffic, never its
	// siblings' calls that reached the provider first. Chunks 1 and on are then
	// released with the normal parallelism, unless StopOn fired on chunk 0.
	LeadAlone bool
	// SlowCall, when positive, stops new chunks from starting once a call has
	// ended in an error after taking longer than it, or on its own timeout: the
	// provider is slow or hung, so the evaluation can only be availability unless
	// a block wins, and starting more calls only holds the request. The calls in
	// flight run on.
	SlowCall time.Duration
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

// Rounds is how many rounds of calls n chunks take in a Run with LeadAlone:
// chunk 0 alone, then the rest at most parallel at a time.
func Rounds(n, parallel int) int {
	if n <= 0 {
		return 0
	}
	return 1 + (n-1+max(1, parallel)-1)/max(1, parallel)
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
	rounds := int((budget / 2) / r)
	return max(1, min(limit, (rounds-1)*max(1, parallel)+1))
}

// FirstReleased reports whether chunk i is sent in the first round the schedule
// releases: the chunks below parallel, or, when lead is set (RunOptions.LeadAlone,
// with parallel above one), chunk 0 alone and then chunks 1 through parallel.
// Under LeadAlone that round is released with the first free slots and queued
// behind no chunk but the lead, whose time is its own call and retry, not the
// text's size. FirstRound is this fact for the call being run.
func FirstReleased(i, parallel int, lead bool) bool {
	parallel = max(1, parallel)
	if lead && parallel > 1 {
		return i <= parallel
	}
	return i < parallel
}

// Outcome is what evaluating one chunk produced. Started is false when the
// chunk was never sent because the context ended, the reserve was not there or
// StopOn fired first: the caller decides what that means, this package does not.
//
// Waited says the chunk was queued behind chunks of the same run (it is not in
// the first round of the schedule, see FirstReleased: under LeadAlone that is
// 1..Parallel, released with the first free slots and queued behind no chunk
// but the lead, whose time is its own call and retry, not the text's size), and
// BudgetCut says its call returned an error while ctx's deadline had passed. Both together are a chunk whose time the request's
// own earlier chunks used up. A chunk of the first round that is cut was the
// provider being slow, and a call that ended on its own timeout leaves
// BudgetCut false because ctx's deadline had not passed.
//
// Took is how long the longest single attempt of the call ran, without what
// RunOptions.Before held it back for and without what the call spent in Pause
// (which is also where one attempt ends and the next begins): the provider's
// time, which says whether it was slow. TimedOut says the call ended on its own
// timeout, with ctx's deadline not passed: the provider never answered.
type Outcome[T any] struct {
	Value     T
	Err       error
	Started   bool
	Waited    bool
	BudgetCut bool
	TimedOut  bool
	Took      time.Duration
}

// Run evaluates fn over chunks in index order with at most o.Parallel calls in
// flight and returns one Outcome per chunk, in chunk order. A failed chunk does
// not stop the others; only StopOn, a slow failure (SlowCall) and the end of ctx
// do. A panic in fn is returned as that chunk's error.
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
	var slowFailure atomic.Bool
	lead := o.LeadAlone && parallel > 1
dispatch:
	for i := range chunks {
		select {
		case sem <- struct{}{}:
		case <-runCtx.Done():
			break dispatch
		}
		if runCtx.Err() != nil || slowFailure.Load() || (!FirstReleased(i, parallel, lead) && lacksReserve(runCtx, reserve)) {
			<-sem
			break
		}
		out[i].Started = true
		first := FirstReleased(i, parallel, lead)
		out[i].Waited = !first
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
				pauses := &pauseClock{reserve: reserve, first: first, attemptStart: time.Now()}
				v, err = call(context.WithValue(runCtx, pauseKey{}, pauses), i, chunks[i], fn)
				out[i].Took = pauses.longest(time.Now())
			}
			out[i].Value, out[i].Err = v, err
			out[i].BudgetCut = err != nil && errors.Is(runCtx.Err(), context.DeadlineExceeded)
			out[i].TimedOut = err != nil && runCtx.Err() == nil && timedOut(err)
			if o.SlowCall > 0 && err != nil && (out[i].TimedOut || out[i].Took > o.SlowCall) {
				slowFailure.Store(true)
			}
			if o.StopOn != nil {
				stopMu.Lock()
				stop := o.StopOn(i)
				stopMu.Unlock()
				if stop {
					cancel()
				}
			}
		}()
		if lead && i == 0 {
			wg.Wait()
		}
	}
	wg.Wait()
	return out
}

func timedOut(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

type pauseKey struct{}

// pauseClock is where a call's attempts begin and end (a Pause is the boundary
// between two), the longest of them, the effective reserve its waits are
// capped at, and whether it is of the first round.
type pauseClock struct {
	reserve      time.Duration
	first        bool
	mu           sync.Mutex
	attemptStart time.Time
	longestSoFar time.Duration
}

// pause closes the attempt that ran until began and opens the next at resumed.
func (c *pauseClock) pause(began, resumed time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.longestSoFar = max(c.longestSoFar, began.Sub(c.attemptStart))
	c.attemptStart = resumed
}

// longest is the longest attempt, the one still running closed at end.
func (c *pauseClock) longest(end time.Time) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return max(0, c.longestSoFar, end.Sub(c.attemptStart))
}

// FirstRound reports whether the call ctx belongs to is of the first round its
// Run's schedule releases (FirstReleased, with the Run's own Parallel and
// LeadAlone). It is false outside a Run.
func FirstRound(ctx context.Context) bool {
	c, ok := ctx.Value(pauseKey{}).(*pauseClock)
	return ok && c.first
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
// taken. Inside a Run the wait is not part of the call's Outcome.Took and ends
// the attempt before it: a call that backs off before a retry waits for its own
// reasons, and Took is only the provider's time, at its longest attempt.
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
		c.pause(began, time.Now())
	}
	return done
}

// RetryBackoff is the wait before a throttled call is sent again, before the
// limits RetryWait puts on it.
const RetryBackoff = 250 * time.Millisecond

// RetryWait is the wait before a throttled call is sent again:
// RetryBackoff capped at a quarter of the time ctx has left, or the provider's
// own retryAfter when it fits in half of it; never more than the reserve of the
// Run the call belongs to.
func RetryWait(ctx context.Context, retryAfter time.Duration) time.Duration {
	wait := RetryBackoff
	if deadline, ok := ctx.Deadline(); ok {
		left := time.Until(deadline)
		wait = min(wait, left/4)
		if retryAfter > 0 && retryAfter <= left/2 {
			wait = retryAfter
		}
	}
	if limit := PauseCap(ctx); limit > 0 {
		wait = min(wait, limit)
	}
	return max(wait, 0)
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

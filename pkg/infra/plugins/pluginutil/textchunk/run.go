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
type Outcome[T any] struct {
	Value     T
	Err       error
	Started   bool
	Waited    bool
	BudgetCut bool
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
			v, err := call(runCtx, i, chunks[i], fn)
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

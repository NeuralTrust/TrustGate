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
	"fmt"
	"sync"
)

// RunOptions bounds a Run.
type RunOptions struct {
	// Parallel is the most calls in flight; values below 1 mean 1.
	Parallel int
	// StopOn is called, one call at a time, after chunk i completes. When it
	// returns true the chunks that have not started are skipped and the calls
	// in flight are cancelled through their context.
	StopOn func(i int) bool
}

// Outcome is what evaluating one chunk produced. Started is false when the
// chunk was never sent because the context ended or StopOn fired first: the
// caller decides what that means, this package does not.
type Outcome[T any] struct {
	Value   T
	Err     error
	Started bool
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

	sem := make(chan struct{}, max(1, o.Parallel))
	var wg, stopMu = sync.WaitGroup{}, sync.Mutex{}
dispatch:
	for i := range chunks {
		select {
		case sem <- struct{}{}:
		case <-runCtx.Done():
			break dispatch
		}
		if runCtx.Err() != nil {
			<-sem
			break
		}
		out[i].Started = true
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			v, err := call(runCtx, i, chunks[i], fn)
			out[i].Value, out[i].Err = v, err
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

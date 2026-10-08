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

package catalog

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type reentrantHandler struct{ onWarn func() }

func (reentrantHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h reentrantHandler) Handle(_ context.Context, rec slog.Record) error {
	if rec.Level == slog.LevelWarn {
		h.onWarn()
	}
	return nil
}
func (h reentrantHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h reentrantHandler) WithGroup(string) slog.Handler      { return h }

// A slow or re-entrant log sink must not stall every native request: the warning
// is written after the resolver's lock is released.
func TestBedrockModelResolver_WarnsWithoutHoldingTheLock(t *testing.T) {
	t.Parallel()
	lookup := &fakeLookup{}
	lookup.on(arnApp).returns("", errors.New("denied")).times(1)
	var r *bedrockModelResolver
	reached := make(chan struct{})
	handler := reentrantHandler{onWarn: func() {
		r.warnedSize()
		close(reached)
	}}
	r = NewBedrockModelResolver(lookup, slog.New(handler)).(*bedrockModelResolver)

	r.Lookup(context.Background(), bedrockRegistry(), arnApp)
	select {
	case <-reached:
	case <-time.After(2 * time.Second):
		t.Fatal("the warning was logged while the resolver's lock was held")
	}
}

func (r *bedrockModelResolver) cacheCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.caches)
}

// A registry that is never asked about again must not keep its entries for the
// life of the process: expired entries are dropped as the resolver is used, and a
// registry left with none stops being tracked.
func TestBedrockModelResolver_ExpiredEntriesAndEmptyRegistriesArePruned(t *testing.T) {
	t.Parallel()
	lookup := &fakeLookup{}
	lookup.on(anyARN).returns(arnFoundation, nil)
	r := NewBedrockModelResolver(lookup, slog.New(slog.DiscardHandler)).(*bedrockModelResolver)
	var mu sync.Mutex
	now := time.Now()
	r.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }

	gone, kept := bedrockRegistry(), bedrockRegistry()
	_, ok := waitFor(t, r, gone, arnApp)
	require.True(t, ok)
	require.Equal(t, 1, r.cacheCount())

	mu.Lock()
	now = now.Add(DefaultBedrockResolverLimits().ResolvedTTL + time.Minute)
	mu.Unlock()
	_, ok = waitFor(t, r, kept, arnProv)
	require.True(t, ok)

	assert.Equal(t, 1, r.cacheCount(), "the registry nobody asks about is forgotten once its entries expire")
}

// Close waits for the lookups in flight, bounded by its context, and nothing
// starts after it: a lookup is never cut off mid-call by the process exiting
// while the shutdown path was not waiting for it.
func TestBedrockModelResolver_CloseWaitsForInFlightLookups(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	release := make(chan struct{})
	lookup := &fakeLookup{}
	lookup.on(arnApp).runsAndReturns(func(context.Context, BedrockCredentials, string) (string, error) {
		close(started)
		<-release
		return arnFoundation, nil
	}).times(1)
	r := NewBedrockModelResolver(lookup, slog.New(slog.DiscardHandler))
	reg := bedrockRegistry()

	r.Lookup(context.Background(), reg, arnApp)
	<-started

	short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, r.Close(short), context.DeadlineExceeded, "an in-flight lookup holds Close, until its context ends")

	closed := make(chan error, 1)
	go func() { closed <- r.Close(context.Background()) }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned %v before the lookup finished", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return once the lookup finished")
	}

	id, ok := r.Lookup(context.Background(), reg, arnApp)
	assert.True(t, ok, "what was learned stays answerable")
	assert.Equal(t, baseModel, id)
	_, ok = r.Lookup(context.Background(), bedrockRegistry(), arnProv)
	assert.False(t, ok)
	assert.Equal(t, 1, lookup.calls, "no lookup starts after Close")
}

// Callers of the same ARN share one control plane call, however many arrive.
func TestBedrockModelResolver_ConcurrentCallsShareOneLookup(t *testing.T) {
	t.Parallel()
	lookup := &fakeLookup{}
	lookup.on(arnApp).runsAndReturns(func(context.Context, BedrockCredentials, string) (string, error) {
		time.Sleep(100 * time.Millisecond)
		return arnFoundation, nil
	})
	r := NewBedrockModelResolver(lookup, slog.New(slog.DiscardHandler))
	reg := bedrockRegistry()

	var wg sync.WaitGroup
	results := make([]string, 20)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], _ = r.Resolve(context.Background(), reg, arnApp, 2*time.Second)
		}()
	}
	wg.Wait()
	for _, id := range results {
		assert.Equal(t, baseModel, id)
	}
	lookup.mu.Lock()
	defer lookup.mu.Unlock()
	assert.Equal(t, 1, lookup.calls)
}

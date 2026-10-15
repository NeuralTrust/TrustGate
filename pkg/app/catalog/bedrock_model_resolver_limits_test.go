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
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func appARN(i int) string {
	return fmt.Sprintf("arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/p%05d", i)
}

// A client chooses the ARN of every call, so the lookups it can start are bounded:
// past the limit a lookup is skipped (the model stays unpriced) instead of another
// goroutine holding a connection for ten seconds.
func TestBedrockModelResolver_LookupsRunUnderABound(t *testing.T) {
	t.Parallel()
	var running, peak atomic.Int32
	release := make(chan struct{})
	cp := &fakeLookup{}
	cp.on(anyARN).
		runsAndReturns(func(context.Context, BedrockCredentials, string) (string, error) {
			now := running.Add(1)
			for {
				old := peak.Load()
				if now <= old || peak.CompareAndSwap(old, now) {
					break
				}
			}
			<-release
			running.Add(-1)
			return "", nil
		})
	r := NewBedrockModelResolver(cp, slog.New(slog.DiscardHandler))

	for i := range 200 {
		_, ok := r.Lookup(context.Background(), bedrockRegistry(), appARN(i))
		assert.False(t, ok)
	}
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 8, int(peak.Load()), "at most eight control plane calls at once, across registries")
	close(release)
}

// One tenant's misses must not evict another's resolved models: eviction is per
// registry, and a resolved model outlives a failed lookup.
func TestBedrockModelResolver_OneRegistryCannotEvictAnothers(t *testing.T) {
	t.Parallel()
	r := NewBedrockModelResolver(&fakeLookup{}, slog.New(slog.DiscardHandler)).(*bedrockModelResolver)
	victim, flooder := bedrockRegistry(), bedrockRegistry()
	now := time.Now()
	r.now = func() time.Time { return now }

	r.mu.Lock()
	r.store(victim.ID.String(), arnApp, resolvedModel{model: baseModel, expires: now.Add(time.Hour)})
	for i := range 30000 {
		r.store(flooder.ID.String(), appARN(i), resolvedModel{expires: now.Add(time.Hour)})
	}
	r.mu.Unlock()

	id, ok := r.Lookup(context.Background(), victim, arnApp)
	assert.True(t, ok, "the other tenant's resolved model is still cached")
	assert.Equal(t, baseModel, id)
}

// Within one registry a resolved model is kept over a failed lookup.
func TestBedrockModelResolver_ResolvedModelsOutliveFailedLookups(t *testing.T) {
	t.Parallel()
	r := NewBedrockModelResolver(&fakeLookup{}, slog.New(slog.DiscardHandler)).(*bedrockModelResolver)
	reg := bedrockRegistry()
	now := time.Now()
	r.now = func() time.Time { return now }

	r.mu.Lock()
	r.store(reg.ID.String(), arnApp, resolvedModel{model: baseModel, expires: now.Add(time.Hour)})
	for i := range 30000 {
		r.store(reg.ID.String(), appARN(i), resolvedModel{expires: now.Add(time.Hour)})
	}
	r.mu.Unlock()

	id, ok := r.Lookup(context.Background(), reg, arnApp)
	assert.True(t, ok)
	assert.Equal(t, baseModel, id)
}

// The fetch is the request's own work finishing in the background: it keeps the
// request's values (the trace) and is not cancelled with the request.
func TestBedrockModelResolver_FetchKeepsTheRequestContextButNotItsCancellation(t *testing.T) {
	t.Parallel()
	type key struct{}
	seen := make(chan any, 1)
	cancelled := make(chan bool, 1)
	cp := &fakeLookup{}
	cp.on(arnApp).
		runsAndReturns(func(ctx context.Context, _ BedrockCredentials, _ string) (string, error) {
			time.Sleep(50 * time.Millisecond) // the request has been cancelled by now
			seen <- ctx.Value(key{})
			cancelled <- ctx.Err() != nil
			return arnFoundation, nil
		}).times(1)
	r := NewBedrockModelResolver(cp, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), key{}, "request-trace"))
	_, _ = r.Resolve(ctx, bedrockRegistry(), arnApp, 5*time.Millisecond)
	cancel()
	assert.Equal(t, "request-trace", <-seen)
	assert.False(t, <-cancelled, "a request that ended does not cancel the lookup it started")
}

// The set of ARNs already warned about is bounded and keeps warning: the oldest
// are forgotten, never the ability to warn about a new one.
func TestBedrockModelResolver_WarnedSetIsBoundedAndKeepsWarning(t *testing.T) {
	t.Parallel()
	logs := &lockedBuffer{}
	cp := &fakeLookup{}
	cp.on(anyARN).returns("", fmt.Errorf("denied"))
	r := NewBedrockModelResolver(cp, slog.New(slog.NewTextHandler(logs, nil)))
	reg := bedrockRegistry()
	for i := range 3000 {
		_, _ = r.Resolve(context.Background(), reg, appARN(i), 2*time.Second)
	}
	assert.Equal(t, 3000, strings.Count(logs.String(), "could not be resolved"), "every new ARN is warned about once")
	require.LessOrEqual(t, r.(*bedrockModelResolver).warnedSize(), DefaultBedrockResolverLimits().MaxEntries, "and the set is bounded")
}

// The bound on lookups is not only global: one registry sending ARNs nobody has
// seen cannot hold every slot, so another registry's lookup still runs.
func TestBedrockModelResolver_OneRegistryCannotStarveAnother(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	started := map[string]int{}
	release := make(chan struct{})
	cp := &fakeLookup{}
	cp.on(anyARN).
		runsAndReturns(func(_ context.Context, _ BedrockCredentials, arn string) (string, error) {
			mu.Lock()
			started[arn]++
			mu.Unlock()
			<-release
			return "", nil
		})
	r := NewBedrockModelResolver(cp, slog.New(slog.DiscardHandler))
	flooder, other := bedrockRegistry(), bedrockRegistry()

	for i := range 50 {
		r.Lookup(context.Background(), flooder, appARN(i))
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	floodStarted := len(started)
	mu.Unlock()
	assert.LessOrEqual(t, floodStarted, 2, "one registry holds at most two lookups at once")

	r.Lookup(context.Background(), other, arnApp)
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	assert.Equal(t, 1, started[arnApp], "the other registry's lookup ran")
	mu.Unlock()
	close(release)
}

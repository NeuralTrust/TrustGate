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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func bedrockRegistry() *registrydomain.Registry {
	return &registrydomain.Registry{
		ID: ids.New[ids.RegistryKind](),
		LLMTarget: &registrydomain.LLMTarget{
			Provider: "bedrock",
			Auth: &registrydomain.TargetAuth{
				Type: registrydomain.AuthTypeAWS,
				AWS:  &registrydomain.AWSAuth{Region: "us-east-1", AccessKeyID: "AKIA", SecretAccessKey: "secret"},
			},
		},
	}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitFor polls a lookup, which never blocks, until the background call lands.
func waitFor(t *testing.T, resolver BedrockModelResolver, reg *registrydomain.Registry, arn string) (string, bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if id, ok := resolver.Lookup(context.Background(), reg, arn); ok {
			return id, true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return "", false
}

func TestBedrockModelResolver_ResolvesAnApplicationProfileInTheBackground(t *testing.T) {
	t.Parallel()
	cp := &fakeLookup{}
	cp.on(arnApp).returns(arnFoundation, nil).times(1)
	resolver := NewBedrockModelResolver(cp, slog.New(slog.DiscardHandler))
	reg := bedrockRegistry()

	id, ok := resolver.Lookup(context.Background(), reg, arnApp)
	assert.False(t, ok, "the first lookup never waits: the call is made in the background")
	assert.Empty(t, id)

	id, ok = waitFor(t, resolver, reg, arnApp)
	require.True(t, ok)
	assert.Equal(t, baseModel, id)

	// A cache hit makes no further control plane call (Once above would fail).
	id, ok = resolver.Lookup(context.Background(), reg, arnApp)
	assert.True(t, ok)
	assert.Equal(t, baseModel, id)
}

func TestBedrockModelResolver_ProvisionedModel(t *testing.T) {
	t.Parallel()
	cp := &fakeLookup{}
	cp.on(arnProv).returns(arnFoundation, nil).times(1)
	resolver := NewBedrockModelResolver(cp, slog.New(slog.DiscardHandler))
	reg := bedrockRegistry()
	resolver.Lookup(context.Background(), reg, arnProv)
	id, ok := waitFor(t, resolver, reg, arnProv)
	require.True(t, ok)
	assert.Equal(t, baseModel, id)
}

func TestBedrockModelResolver_FailureIsNegativelyCachedAndLoggedOnce(t *testing.T) {
	t.Parallel()
	cp := &fakeLookup{}
	cp.on(arnApp).
		returns("", errors.New("AccessDeniedException: not authorized to perform bedrock:GetInferenceProfile")).times(1)
	logs := &lockedBuffer{}
	resolver := NewBedrockModelResolver(cp, slog.New(slog.NewTextHandler(logs, nil)))
	reg := bedrockRegistry()

	resolver.Lookup(context.Background(), reg, arnApp)
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(logs.String(), "could not be resolved") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	require.Contains(t, logs.String(), "bedrock:GetInferenceProfile")

	for range 5 {
		id, ok := resolver.Lookup(context.Background(), reg, arnApp)
		assert.False(t, ok, "no cost, no failure")
		assert.Empty(t, id)
	}
	assert.Equal(t, 1, strings.Count(logs.String(), "could not be resolved"), "one WARN per ARN")
}

func TestBedrockModelResolver_NegativeEntryExpiresAndIsRetried(t *testing.T) {
	t.Parallel()
	cp := &fakeLookup{}
	cp.on(arnApp).returns("", errors.New("denied")).times(1)
	cp.on(arnApp).returns(arnFoundation, nil).times(1)
	r := NewBedrockModelResolver(cp, slog.New(slog.DiscardHandler)).(*bedrockModelResolver)
	clock := &struct {
		mu sync.Mutex
		t  time.Time
	}{t: time.Now()}
	r.now = func() time.Time {
		clock.mu.Lock()
		defer clock.mu.Unlock()
		return clock.t
	}
	reg := bedrockRegistry()

	r.Lookup(context.Background(), reg, arnApp)
	require.Eventually(t, func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.active == 0 && len(r.caches) == 1
	}, 3*time.Second, 5*time.Millisecond)

	clock.mu.Lock()
	clock.t = clock.t.Add(DefaultBedrockResolverLimits().UnresolvedTTL + time.Second)
	clock.mu.Unlock()
	r.Lookup(context.Background(), reg, arnApp)
	id, ok := waitFor(t, r, reg, arnApp)
	require.True(t, ok)
	assert.Equal(t, baseModel, id)
}

func TestBedrockModelResolver_CacheIsPerRegistryAndBounded(t *testing.T) {
	t.Parallel()
	cp := &fakeLookup{}
	cp.on(anyARN).returns(arnFoundation, nil)
	r := NewBedrockModelResolver(cp, slog.New(slog.DiscardHandler)).(*bedrockModelResolver)

	a, b := bedrockRegistry(), bedrockRegistry()
	r.Lookup(context.Background(), a, arnApp)
	_, ok := waitFor(t, r, a, arnApp)
	require.True(t, ok)
	_, ok = r.Lookup(context.Background(), b, arnApp)
	assert.False(t, ok, "another registry's credentials are another entry")

	r.mu.Lock()
	for i := 0; i < DefaultBedrockResolverLimits().MaxEntries+50; i++ {
		r.store(a.ID.String(), "k"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+time.Duration(i).String(), resolvedModel{model: "m", expires: time.Now().Add(time.Hour)})
	}
	size := len(r.caches[a.ID.String()].entries)
	r.mu.Unlock()
	assert.LessOrEqual(t, size, DefaultBedrockResolverLimits().MaxEntries)
}

func TestBedrockModelResolver_IgnoresWhatItCannotResolve(t *testing.T) {
	t.Parallel()
	cp := &fakeLookup{} // no call is expected
	r := NewBedrockModelResolver(cp, slog.New(slog.DiscardHandler))
	reg := bedrockRegistry()
	for _, arn := range []string{arnFoundation, arnSystemUS, "plain.model-v1:0", "arn:malformed"} {
		_, ok := r.Lookup(context.Background(), reg, arn)
		assert.False(t, ok, arn)
	}
	_, ok := r.Lookup(context.Background(), &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), LLMTarget: &registrydomain.LLMTarget{Provider: "bedrock", Auth: registrydomain.NewAPIKeyAuth("k")}}, arnApp)
	assert.False(t, ok, "a registry with no AWS credentials has nothing to look up with")
	_, ok = r.Lookup(context.Background(), nil, arnApp)
	assert.False(t, ok)
}

func TestBedrockModelResolver_RepeatedFailureAfterExpiryIsStillLoggedOnce(t *testing.T) {
	t.Parallel()
	cp := &fakeLookup{}
	cp.on(arnApp).returns("", errors.New("denied")).times(2)
	logs := &lockedBuffer{}
	r := NewBedrockModelResolver(cp, slog.New(slog.NewTextHandler(logs, nil))).(*bedrockModelResolver)
	var mu sync.Mutex
	now := time.Now()
	r.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	reg := bedrockRegistry()

	settle := func() {
		require.Eventually(t, func() bool {
			r.mu.Lock()
			defer r.mu.Unlock()
			return r.active == 0 && len(r.caches) == 1
		}, 3*time.Second, 5*time.Millisecond)
	}
	r.Lookup(context.Background(), reg, arnApp)
	settle()
	mu.Lock()
	now = now.Add(DefaultBedrockResolverLimits().UnresolvedTTL + time.Second)
	mu.Unlock()
	r.Lookup(context.Background(), reg, arnApp)
	require.Eventually(t, func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		var expires time.Time
		if c := r.caches[reg.ID.String()]; c != nil {
			if el := c.entries[arnApp]; el != nil {
				expires = el.Value.(*cacheEntry).expires
			}
		}
		return r.active == 0 && expires.After(now)
	}, 3*time.Second, 5*time.Millisecond)
	assert.Equal(t, 1, strings.Count(logs.String(), "could not be resolved"))
}

func TestBedrockModelResolver_ResolveWaitsForAColdCache(t *testing.T) {
	t.Parallel()
	cp := &fakeLookup{}
	cp.on(arnApp).
		runs(func(context.Context, BedrockCredentials, string) { time.Sleep(50 * time.Millisecond) }).
		returns(arnFoundation, nil).times(1)
	r := NewBedrockModelResolver(cp, slog.New(slog.DiscardHandler))

	id, ok := r.Resolve(context.Background(), bedrockRegistry(), arnApp, 2*time.Second)
	require.True(t, ok, "the first call gets the model, not a miss")
	assert.Equal(t, baseModel, id)
}

func TestBedrockModelResolver_ConcurrentFirstCallsShareOneLookup(t *testing.T) {
	t.Parallel()
	cp := &fakeLookup{}
	cp.on(arnApp).
		runs(func(context.Context, BedrockCredentials, string) { time.Sleep(100 * time.Millisecond) }).
		returns(arnFoundation, nil).times(1) // a second call would fail the mock
	r := NewBedrockModelResolver(cp, slog.New(slog.DiscardHandler))
	reg := bedrockRegistry()

	var wg sync.WaitGroup
	results := make([]string, 8)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], _ = r.Resolve(context.Background(), reg, arnApp, 2*time.Second)
		}()
	}
	wg.Wait()
	for _, got := range results {
		assert.Equal(t, baseModel, got)
	}
}

func TestBedrockModelResolver_ResolveGivesUpAfterTheBoundButTheLookupFinishes(t *testing.T) {
	t.Parallel()
	cp := &fakeLookup{}
	cp.on(arnApp).
		runs(func(context.Context, BedrockCredentials, string) { time.Sleep(300 * time.Millisecond) }).
		returns(arnFoundation, nil).times(1)
	r := NewBedrockModelResolver(cp, slog.New(slog.DiscardHandler))
	reg := bedrockRegistry()

	started := time.Now()
	_, ok := r.Resolve(context.Background(), reg, arnApp, 20*time.Millisecond)
	assert.False(t, ok)
	assert.Less(t, time.Since(started), 200*time.Millisecond, "the bound is the bound")

	id, ok := waitFor(t, r, reg, arnApp)
	require.True(t, ok, "the lookup went on in the background and filled the cache")
	assert.Equal(t, baseModel, id)
}

func TestBedrockModelResolver_NegativeEntryDoesNotWait(t *testing.T) {
	t.Parallel()
	cp := &fakeLookup{}
	cp.on(arnApp).returns("", errors.New("denied")).times(1)
	r := NewBedrockModelResolver(cp, slog.New(slog.DiscardHandler))
	reg := bedrockRegistry()

	_, ok := r.Resolve(context.Background(), reg, arnApp, 2*time.Second)
	assert.False(t, ok)

	started := time.Now()
	_, ok = r.Resolve(context.Background(), reg, arnApp, 5*time.Second)
	assert.False(t, ok)
	assert.Less(t, time.Since(started), 100*time.Millisecond, "a negative entry returns at once")
}

func TestBedrockModelResolver_ResolveHonoursTheContext(t *testing.T) {
	t.Parallel()
	cp := &fakeLookup{}
	cp.on(arnApp).
		runs(func(context.Context, BedrockCredentials, string) { time.Sleep(200 * time.Millisecond) }).
		returns(arnFoundation, nil).times(1)
	r := NewBedrockModelResolver(cp, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	_, ok := r.Resolve(ctx, bedrockRegistry(), arnApp, 5*time.Second)
	assert.False(t, ok)
	assert.Less(t, time.Since(started), 100*time.Millisecond)
	time.Sleep(250 * time.Millisecond) // let the mock's call finish before the test ends
}

func TestBedrockModelResolver_RecoversFromAPanicInTheLookup(t *testing.T) {
	t.Parallel()
	cp := &fakeLookup{}
	cp.on(arnApp).
		runsAndReturns(func(context.Context, BedrockCredentials, string) (string, error) {
			panic("boom")
		}).times(1)
	logs := &lockedBuffer{}
	resolver := NewBedrockModelResolver(cp, slog.New(slog.NewTextHandler(logs, nil)))
	reg := bedrockRegistry()

	// A cold Resolve parks on the lookup: the panic must release it.
	done := make(chan struct{})
	go func() {
		defer close(done)
		id, ok := resolver.Resolve(context.Background(), reg, arnApp, 2*time.Second)
		assert.False(t, ok)
		assert.Empty(t, id)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("a waiter stayed parked after the lookup panicked")
	}
	assert.Contains(t, logs.String(), "level=ERROR")
	assert.Contains(t, logs.String(), "recovered from a panic")

	// The failure is negatively cached: no second call (Once above), no wait.
	id, ok := resolver.Lookup(context.Background(), reg, arnApp)
	assert.False(t, ok)
	assert.Empty(t, id)
}

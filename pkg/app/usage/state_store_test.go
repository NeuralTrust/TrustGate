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

package usage

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
)

type memoryCache struct {
	mu          sync.Mutex
	saved       []domain.TenantState
	stored      []domain.TenantState
	saveErr     error
	loadErr     error
	loads       int
	saveGate    chan struct{}
	saveStarted chan struct{}
	loadGate    chan struct{}
	loadStart   chan struct{}
	calls       int
}

func (c *memoryCache) SaveAll(ctx context.Context, states []domain.TenantState) error {
	if c.saveStarted != nil {
		c.saveStarted <- struct{}{}
	}
	if c.saveGate != nil {
		<-c.saveGate
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.saveErr != nil {
		return c.saveErr
	}
	c.saved = append(c.saved, states...)
	return nil
}

func (c *memoryCache) setSaveErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.saveErr = err
}

func (c *memoryCache) saveCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func (c *memoryCache) LoadAll(context.Context) ([]domain.TenantState, error) {
	if c.loadStart != nil {
		close(c.loadStart)
	}
	if c.loadGate != nil {
		<-c.loadGate
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loads++
	if c.loadErr != nil {
		return nil, c.loadErr
	}
	return c.stored, nil
}

func (c *memoryCache) savedStates() []domain.TenantState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]domain.TenantState(nil), c.saved...)
}

func state(t *testing.T, tenant string, exhausted bool, version int64) domain.TenantState {
	t.Helper()
	status, reason := domain.StatusHealthy, domain.ReasonNone
	if exhausted {
		status, reason = domain.StatusExhausted, domain.ReasonWalletEmpty
	}
	s, err := domain.NewTenantState(tenant, status, reason, version)
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	return s
}

func TestStoreApplyKeepsHighestVersion(t *testing.T) {
	t.Parallel()
	cache := &memoryCache{}
	store := NewStore(cache, nil, time.Second)
	changes, release := store.Subscribe()
	defer release()

	if store.Ready() {
		t.Fatal("store ready before any list")
	}
	if err := store.Apply(context.Background(), []domain.TenantState{state(t, "a", true, 5), state(t, "b", true, 2)}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !store.Ready() {
		t.Fatal("store not ready after Apply")
	}
	select {
	case <-changes:
	default:
		t.Fatal("no change notification")
	}

	if err := store.Apply(context.Background(), []domain.TenantState{state(t, "a", false, 4)}); err != nil {
		t.Fatalf("Apply stale: %v", err)
	}
	select {
	case <-changes:
		t.Fatal("a stale state notified subscribers")
	default:
	}
	if err := store.Apply(context.Background(), []domain.TenantState{state(t, "b", false, 7)}); err != nil {
		t.Fatalf("Apply unblock: %v", err)
	}

	all := store.SnapshotAll()
	if len(all.Exhausted) != 1 || all.Exhausted[0].TenantID != "a" || all.Exhausted[0].Version != 5 {
		t.Fatalf("all = %+v, want only a@5", all)
	}
	if one := store.SnapshotTenant("b"); len(one.Exhausted) != 0 {
		t.Fatalf("b = %+v, want none", one)
	}
	if one := store.SnapshotTenant("a"); len(one.Exhausted) != 1 {
		t.Fatalf("a = %+v, want a", one)
	}
	store.FlushPending(context.Background())
	if saved := cache.savedStates(); len(saved) != 2 {
		t.Fatalf("cache saves = %+v, want the latest state of a and b (the stale one is never queued)", saved)
	}
	if reason, ok := store.Exhausted("a"); !ok || reason != domain.ReasonWalletEmpty {
		t.Fatalf("Exhausted(a) = %v %v, want wallet_empty", reason, ok)
	}
	if _, ok := store.Exhausted("b"); ok {
		t.Fatal("b reported exhausted after its unblock")
	}
	if one := store.SnapshotTenant(""); len(one.Exhausted) != 0 {
		t.Fatalf("empty tenant = %+v, want none", one)
	}
}

func TestStoreApplySurvivesCacheFailure(t *testing.T) {
	t.Parallel()
	store := NewStore(&memoryCache{saveErr: errors.New("redis down")}, nil, time.Second)
	if err := store.Apply(context.Background(), []domain.TenantState{state(t, "a", true, 1)}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := store.SnapshotTenant("a"); len(got.Exhausted) != 1 {
		t.Fatalf("state lost on cache failure: %+v", got)
	}
}

func TestStoreRestoreUntilReadyRetries(t *testing.T) {
	t.Parallel()
	cache := &memoryCache{loadErr: errors.New("redis down"), stored: []domain.TenantState{state(t, "a", true, 9)}}
	store := NewStore(cache, nil, time.Second)
	done := make(chan struct{})
	go func() {
		store.RestoreUntilReady(context.Background(), RestoreOptions{Interval: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond})
		close(done)
	}()
	time.Sleep(30 * time.Millisecond)
	if store.Ready() {
		t.Fatal("ready while the cache fails")
	}
	cache.mu.Lock()
	cache.loadErr = nil
	cache.mu.Unlock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RestoreUntilReady did not finish once the cache answered")
	}
	if got := store.SnapshotAll(); len(got.Exhausted) != 1 || got.AsOfVersion != 0 {
		t.Fatalf("restored = %+v, want a listed with no as_of: the cache alone is not a complete list", got)
	}
}

func TestReadinessCheckWaitsThenGivesUp(t *testing.T) {
	t.Parallel()
	ready := false
	check := ReadinessCheck(func() bool { return ready }, 50*time.Millisecond, nil)
	if err := check(context.Background()); !errors.Is(err, ErrListNotReady) {
		t.Fatalf("err = %v, want ErrListNotReady", err)
	}
	time.Sleep(60 * time.Millisecond)
	if err := check(context.Background()); err != nil {
		t.Fatalf("after timeout: %v, want ready", err)
	}
	ready = true
	if err := check(context.Background()); err != nil {
		t.Fatalf("ready list: %v", err)
	}
}

func TestReadinessCheckCountsTheWaitFromTheFirstNotReadyProbe(t *testing.T) {
	t.Parallel()
	ready := true
	check := ReadinessCheck(func() bool { return ready }, 50*time.Millisecond, nil)
	if err := check(context.Background()); err != nil {
		t.Fatalf("ready plane: %v", err)
	}
	time.Sleep(60 * time.Millisecond)
	ready = false
	if err := check(context.Background()); !errors.Is(err, ErrListNotReady) {
		t.Fatalf("err = %v, want ErrListNotReady: the wait starts when the plane stops being ready, not at boot", err)
	}
	time.Sleep(60 * time.Millisecond)
	if err := check(context.Background()); err != nil {
		t.Fatalf("after timeout: %v, want ready", err)
	}
	ready = true
	if err := check(context.Background()); err != nil {
		t.Fatalf("ready again: %v", err)
	}
	ready = false
	if err := check(context.Background()); !errors.Is(err, ErrListNotReady) {
		t.Fatalf("err = %v, want ErrListNotReady: a new wait starts after the plane was ready again", err)
	}
}

func TestStoreEmptyRestoreWaitsForUsageSync(t *testing.T) {
	t.Parallel()
	store := NewStore(&memoryCache{}, nil, time.Second)
	if err := store.restore(context.Background(), true); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if store.Ready() {
		t.Fatal("an empty cache made the store ready while a UsageSync snapshot is expected")
	}
	if err := store.ApplySnapshot(context.Background(), nil, 4); err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}
	if !store.Ready() {
		t.Fatal("store not ready after the first snapshot")
	}

	cached := NewStore(&memoryCache{stored: []domain.TenantState{state(t, "a", true, 3)}}, nil, time.Second)
	if err := cached.restore(context.Background(), true); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if !cached.Ready() {
		t.Fatal("a cache with states did not make the store ready")
	}
}

func TestStoreRestoreSkipsStatesASnapshotAlreadyCovers(t *testing.T) {
	t.Parallel()
	cache := &memoryCache{
		stored:    []domain.TenantState{state(t, "a", true, 50), state(t, "b", true, 70)},
		loadGate:  make(chan struct{}),
		loadStart: make(chan struct{}),
	}
	store := NewStore(cache, nil, time.Second)
	ctx := context.Background()
	done := make(chan error, 1)
	go func() { done <- store.restore(ctx, true) }()
	<-cache.loadStart

	if err := store.ApplySnapshot(ctx, nil, 60); err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}
	close(cache.loadGate)
	if err := <-done; err != nil {
		t.Fatalf("Restore: %v", err)
	}

	if _, ok := store.Exhausted("a"); ok {
		t.Fatal("a cached block the snapshot already cleared came back")
	}
	if _, ok := store.Exhausted("b"); !ok {
		t.Fatal("a cached block newer than the snapshot was dropped")
	}
}

func TestStoreApplyNeverWaitsOnTheCache(t *testing.T) {
	t.Parallel()
	cache := &memoryCache{saveGate: make(chan struct{})}
	store := NewStore(cache, nil, time.Second)
	changes, release := store.Subscribe()
	defer release()
	done := make(chan error, 1)
	go func() { done <- store.Apply(context.Background(), []domain.TenantState{state(t, "a", true, 1)}) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Apply waited on the cache")
	}
	select {
	case <-changes:
	default:
		t.Fatal("subscribers were not woken")
	}
	select {
	case <-store.CacheWrites():
	default:
		t.Fatal("the cache writer was not woken")
	}
	flushed := make(chan struct{})
	go func() {
		store.FlushPending(context.Background())
		close(flushed)
	}()
	close(cache.saveGate)
	<-flushed
	if len(cache.savedStates()) != 1 {
		t.Fatal("state not cached")
	}
}

func TestStoreBecomingReadyWakesSubscribersWithoutChanges(t *testing.T) {
	t.Parallel()
	store := NewStore(&memoryCache{}, nil, time.Second)
	changes, release := store.Subscribe()
	defer release()
	if err := store.restore(context.Background(), false); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	select {
	case <-changes:
	default:
		t.Fatal("restoring an empty cache with no UsageSync stream did not wake subscribers")
	}
	if err := store.Apply(context.Background(), nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	select {
	case <-changes:
		t.Fatal("an empty Apply on a ready store notified subscribers")
	default:
	}
}

func TestStoreApplySnapshotUnblocksMissingTenantsAtTheWatermark(t *testing.T) {
	t.Parallel()
	cache := &memoryCache{}
	store := NewStore(cache, nil, time.Second)
	ctx := context.Background()
	if err := store.ApplySnapshot(ctx, []domain.TenantState{state(t, "a", true, 5), state(t, "b", true, 6)}, 6); err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}
	if !store.Ready() || store.Watermark() != 6 {
		t.Fatalf("ready=%v watermark=%d", store.Ready(), store.Watermark())
	}
	if err := store.Apply(ctx, []domain.TenantState{state(t, "c", true, 12)}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := store.ApplySnapshot(ctx, []domain.TenantState{state(t, "b", true, 6)}, 10); err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}
	all := store.SnapshotAll()
	got := map[string]int64{}
	for _, s := range all.Exhausted {
		got[s.TenantID] = s.Version
	}
	if _, ok := got["a"]; ok {
		t.Fatalf("a still exhausted after dropping out of the list: %+v", all)
	}
	if got["b"] != 6 || got["c"] != 12 {
		t.Fatalf("exhausted = %v, want b@6 kept and c@12 kept (newer than the list)", got)
	}
	if store.Watermark() != 12 {
		t.Fatalf("watermark = %d, want 12", store.Watermark())
	}
	store.FlushPending(ctx)
	unblocked := false
	for _, saved := range cache.savedStates() {
		if saved.TenantID == "a" && !saved.Exhausted() && saved.Version == 10 {
			unblocked = true
		}
	}
	if !unblocked {
		t.Fatalf("the unblock of a at 10 was not cached: %+v", cache.saved)
	}
}

func manyStates(t *testing.T, n int, version int64) []domain.TenantState {
	t.Helper()
	states := make([]domain.TenantState, 0, n)
	for i := range n {
		states = append(states, state(t, fmt.Sprintf("tenant-%05d", i), true, version))
	}
	return states
}

func TestStoreRetriesStatesAFailedWriteLeftBehind(t *testing.T) {
	t.Parallel()
	cache := &memoryCache{saveErr: errors.New("redis down")}
	store := NewStore(cache, nil, time.Second)
	ctx := context.Background()

	if err := store.Apply(ctx, []domain.TenantState{state(t, "a", true, 1)}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	store.FlushPending(ctx)
	if err := store.Apply(ctx, []domain.TenantState{state(t, "a", false, 2), state(t, "b", true, 3)}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	store.FlushPending(ctx)
	if got := cache.savedStates(); len(got) != 0 {
		t.Fatalf("saved = %+v while the cache fails", got)
	}

	cache.setSaveErr(nil)
	store.FlushPending(ctx)

	saved := map[string]int64{}
	for _, st := range cache.savedStates() {
		saved[st.TenantID] = st.Version
	}
	if len(saved) != 2 || saved["a"] != 2 || saved["b"] != 3 {
		t.Fatalf("saved = %v, want the latest pending state of each tenant: a@2 and b@3", saved)
	}
	store.FlushPending(ctx)
	if got := len(cache.savedStates()); got != 2 {
		t.Fatalf("saved %d states after a second flush, want nothing left pending", got)
	}
}

func TestStoreWritesLargeListsInChunks(t *testing.T) {
	t.Parallel()
	cache := &memoryCache{}
	store := NewStore(cache, nil, time.Second)
	if err := store.ApplySnapshot(context.Background(), manyStates(t, 2*cacheChunk+1, 5), 5); err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}
	store.FlushPending(context.Background())
	if calls := cache.saveCalls(); calls != 3 {
		t.Fatalf("SaveAll calls = %d, want 3 chunks for %d states", calls, 2*cacheChunk+1)
	}
	if got := len(cache.savedStates()); got != 2*cacheChunk+1 {
		t.Fatalf("saved %d states", got)
	}
}

func TestStoreFlushStopsBetweenChunksOnceCancelled(t *testing.T) {
	t.Parallel()
	cache := &memoryCache{saveStarted: make(chan struct{}, 4), saveGate: make(chan struct{})}
	store := NewStore(cache, nil, time.Second)
	if err := store.ApplySnapshot(context.Background(), manyStates(t, cacheChunk+10, 5), 5); err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		store.FlushPending(ctx)
		close(done)
	}()

	<-cache.saveStarted
	cancel()
	close(cache.saveGate)
	<-done
	if got := len(cache.savedStates()); got != cacheChunk {
		t.Fatalf("saved %d states, want only the chunk in flight (%d) once cancelled", got, cacheChunk)
	}

	store.FlushPending(context.Background())
	if got := len(cache.savedStates()); got != cacheChunk+10 {
		t.Fatalf("saved %d states after the next flush, want all %d", got, cacheChunk+10)
	}
}

func TestStoreUnblockAtTheSameVersionSupersedesAPendingBlock(t *testing.T) {
	t.Parallel()
	cache := &memoryCache{saveErr: errors.New("redis down")}
	store := NewStore(cache, nil, time.Second)
	ctx := context.Background()

	if err := store.Apply(ctx, []domain.TenantState{state(t, "a", true, 9)}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	store.FlushPending(ctx)
	if err := store.ApplySnapshot(ctx, nil, 9); err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}
	cache.setSaveErr(nil)
	store.FlushPending(ctx)

	saved := cache.savedStates()
	if len(saved) != 1 || saved[0].Exhausted() || saved[0].Version != 9 {
		t.Fatalf("saved = %+v, want a healthy at 9: the unblock applied after the failed block", saved)
	}
}

func TestReadinessCheckUnderConcurrentProbes(t *testing.T) {
	t.Parallel()
	var ready atomic.Bool
	check := ReadinessCheck(ready.Load, time.Hour, nil)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 500 {
				if (i+j)%7 == 0 {
					ready.Store(!ready.Load())
				}
				if err := check(context.Background()); err != nil && !errors.Is(err, ErrListNotReady) {
					t.Errorf("check: %v", err)
				}
			}
		}()
	}
	wg.Wait()
	ready.Store(false)
	if err := check(context.Background()); !errors.Is(err, ErrListNotReady) {
		t.Fatalf("err = %v, want ErrListNotReady: a probe that raced a ready one must not give up within the hour", err)
	}
}

func TestStoreStopsWritingAfterTheFirstFailedChunk(t *testing.T) {
	t.Parallel()
	cache := &memoryCache{saveErr: errors.New("redis hung")}
	store := NewStore(cache, nil, time.Second)
	if err := store.ApplySnapshot(context.Background(), manyStates(t, 2*cacheChunk+1, 5), 5); err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}
	store.FlushPending(context.Background())
	if calls := cache.saveCalls(); calls != 1 {
		t.Fatalf("SaveAll calls = %d, want 1: the write stops at the first failed chunk", calls)
	}

	cache.setSaveErr(nil)
	store.FlushPending(context.Background())
	if got := len(cache.savedStates()); got != 2*cacheChunk+1 {
		t.Fatalf("saved %d states after the flush, want all %d", got, 2*cacheChunk+1)
	}
}

func TestStoreListsClaimNoWatermarkBeforeTheFirstSnapshot(t *testing.T) {
	t.Parallel()
	store := NewStore(&memoryCache{stored: []domain.TenantState{state(t, "a", true, 9)}}, nil, time.Second)
	ctx := context.Background()
	if err := store.restore(ctx, true); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if all := store.SnapshotAll(); all.AsOfVersion != 0 || len(all.Exhausted) != 1 {
		t.Fatalf("restored list = %+v, want a listed with as_of 0", all)
	}
	if store.Watermark() != 9 {
		t.Fatalf("watermark = %d, want 9: Usage System still learns what the cache held", store.Watermark())
	}
	if err := store.ApplySnapshot(ctx, []domain.TenantState{state(t, "a", true, 9)}, 12); err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}
	if all := store.SnapshotAll(); all.AsOfVersion != 12 {
		t.Fatalf("list after the first snapshot = %+v, want as_of 12", all)
	}
}

func TestStoreResyncCacheRewritesEveryHeldState(t *testing.T) {
	t.Parallel()
	cache := &memoryCache{}
	store := NewStore(cache, nil, time.Second)
	ctx := context.Background()
	if err := store.ApplySnapshot(ctx, []domain.TenantState{state(t, "a", true, 3)}, 3); err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}
	if err := store.Apply(ctx, []domain.TenantState{state(t, "b", false, 4)}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	store.FlushPending(ctx)
	before := len(cache.savedStates())

	store.ResyncCache()
	store.FlushPending(ctx)
	if got := len(cache.savedStates()) - before; got != 2 {
		t.Fatalf("resync wrote %d states, want both held states, healthy ones included", got)
	}
}

func tenantsOf(states []domain.TenantState) []string {
	out := make([]string, 0, len(states))
	for _, s := range states {
		out = append(out, s.TenantID)
	}
	return out
}

func TestStoreChangesSinceReturnsEachChangedTenantOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewStore(&memoryCache{}, nil, time.Second)
	_ = store.Apply(ctx, []domain.TenantState{state(t, "a", true, 1), state(t, "b", true, 2)})
	cursor := store.Cursor()

	_ = store.Apply(ctx, []domain.TenantState{state(t, "c", true, 3)})
	_ = store.Apply(ctx, []domain.TenantState{state(t, "a", true, 4)})
	_ = store.Apply(ctx, []domain.TenantState{state(t, "c", false, 5)})
	_ = store.Apply(ctx, []domain.TenantState{state(t, "b", true, 1)})

	changes, next := store.ChangesSince(cursor)
	if got := tenantsOf(changes); !slices.Equal(got, []string{"a", "c"}) {
		t.Fatalf("changed = %v, want a then c, each once and the stale b skipped", got)
	}
	if changes[1].Exhausted() || changes[1].Version != 5 {
		t.Fatalf("c = %+v, want its latest state", changes[1])
	}
	if again, _ := store.ChangesSince(next); len(again) != 0 {
		t.Fatalf("changed since the latest cursor = %v, want nothing", again)
	}
}

func TestStoreChangesSinceSeesAnUnblockAtTheSameVersion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewStore(&memoryCache{}, nil, time.Second)
	_ = store.ApplySnapshot(ctx, []domain.TenantState{state(t, "a", true, 10), state(t, "b", true, 9)}, 10)
	cursor := store.Cursor()

	_ = store.ApplySnapshot(ctx, []domain.TenantState{state(t, "b", true, 9)}, 10)
	changes, _ := store.ChangesSince(cursor)
	if len(changes) != 1 || changes[0].TenantID != "a" || changes[0].Exhausted() || changes[0].Version != 10 {
		t.Fatalf("changes = %+v, want a unblocked at version 10", changes)
	}
}

func TestStoreChangesSinceSurvivesLogCompaction(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewStore(&memoryCache{}, nil, time.Second)
	_ = store.Apply(ctx, []domain.TenantState{state(t, "early", true, 1)})
	cursor := store.Cursor()

	for v := int64(2); v < 3*changeLogSlack; v++ {
		_ = store.Apply(ctx, []domain.TenantState{state(t, "hot", v%2 == 0, v)})
	}
	_ = store.Apply(ctx, []domain.TenantState{state(t, "late", true, 3*changeLogSlack)})

	store.mu.RLock()
	logged := len(store.changeLog)
	store.mu.RUnlock()
	if logged > 2*3+changeLogSlack {
		t.Fatalf("change log holds %d entries, want it compacted", logged)
	}
	changes, _ := store.ChangesSince(cursor)
	if got := tenantsOf(changes); !slices.Equal(got, []string{"hot", "late"}) {
		t.Fatalf("changed = %v, want hot then late", got)
	}
	if all, _ := store.ChangesSince(0); !slices.Equal(tenantsOf(all), []string{"early", "hot", "late"}) {
		t.Fatalf("changed since 0 = %v, want every tenant", tenantsOf(all))
	}
}

func TestStoreWakesSubscribersWhenItsListsBecomeComplete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cache := &memoryCache{stored: []domain.TenantState{state(t, "x", true, 5)}}
	store := NewStore(cache, nil, time.Second)
	store.RestoreUntilReady(ctx, RestoreOptions{Interval: time.Millisecond, MaxBackoff: time.Millisecond, AwaitSync: true})
	if !store.Ready() || store.SnapshotAll().AsOfVersion != 0 {
		t.Fatalf("restored store = ready %v as_of %d, want ready with no as_of version", store.Ready(), store.SnapshotAll().AsOfVersion)
	}
	changes, release := store.Subscribe()
	defer release()

	_ = store.ApplySnapshot(ctx, []domain.TenantState{state(t, "x", true, 5)}, 5)
	select {
	case <-changes:
	default:
		t.Fatal("a snapshot that completed the lists woke nobody")
	}
	if got := store.SnapshotAll().AsOfVersion; got != 5 {
		t.Fatalf("as_of = %d, want 5", got)
	}

	_ = store.ApplySnapshot(ctx, []domain.TenantState{state(t, "x", true, 5)}, 5)
	select {
	case <-changes:
		t.Fatal("a later snapshot that changed nothing woke the subscribers")
	default:
	}
}

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
	"sync"
	"testing"
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
)

type memoryCache struct {
	mu      sync.Mutex
	saved   []domain.TenantState
	stored  []domain.TenantState
	saveErr error
	loadErr error
	loads   int
}

func (c *memoryCache) Save(_ context.Context, state domain.TenantState) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.saveErr != nil {
		return false, c.saveErr
	}
	c.saved = append(c.saved, state)
	return true, nil
}

func (c *memoryCache) LoadAll(context.Context) ([]domain.TenantState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loads++
	if c.loadErr != nil {
		return nil, c.loadErr
	}
	return c.stored, nil
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
	store := NewStore(cache, nil)
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

	all := store.SnapshotFor("", true)
	if all.AsOfVersion != 7 || len(all.Exhausted) != 1 || all.Exhausted[0].TenantID != "a" || all.Exhausted[0].Version != 5 {
		t.Fatalf("all = %+v, want only a@5 as of 7", all)
	}
	if one := store.SnapshotFor("b", false); len(one.Exhausted) != 0 || one.AsOfVersion != 7 {
		t.Fatalf("b = %+v, want none as of 7", one)
	}
	if one := store.SnapshotFor("a", false); len(one.Exhausted) != 1 {
		t.Fatalf("a = %+v, want a", one)
	}
	if len(cache.saved) != 3 {
		t.Fatalf("cache saves = %d, want 3 (the stale state is not saved)", len(cache.saved))
	}
}

func TestStoreApplySurvivesCacheFailure(t *testing.T) {
	t.Parallel()
	store := NewStore(&memoryCache{saveErr: errors.New("redis down")}, nil)
	if err := store.Apply(context.Background(), []domain.TenantState{state(t, "a", true, 1)}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := store.SnapshotFor("a", false); len(got.Exhausted) != 1 {
		t.Fatalf("state lost on cache failure: %+v", got)
	}
}

func TestStoreRestoreUntilReadyRetries(t *testing.T) {
	t.Parallel()
	cache := &memoryCache{loadErr: errors.New("redis down"), stored: []domain.TenantState{state(t, "a", true, 9)}}
	store := NewStore(cache, nil)
	done := make(chan struct{})
	go func() {
		store.RestoreUntilReady(context.Background(), 10*time.Millisecond)
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
	if got := store.SnapshotFor("", true); len(got.Exhausted) != 1 || got.AsOfVersion != 9 {
		t.Fatalf("restored = %+v", got)
	}
}

func TestReadinessCheckWaitsThenGivesUp(t *testing.T) {
	t.Parallel()
	ready := false
	check := ReadinessCheck(func() bool { return ready }, 50*time.Millisecond, nil)
	if err := check(context.Background()); !errors.Is(err, ErrListNotReady) {
		t.Fatalf("err = %v, want ErrListNotReady", err)
	}
	ready = true
	if err := check(context.Background()); err != nil {
		t.Fatalf("ready list: %v", err)
	}
	ready = false
	time.Sleep(60 * time.Millisecond)
	if err := check(context.Background()); err != nil {
		t.Fatalf("after timeout: %v, want ready", err)
	}
}

func TestStoreBecomingReadyWakesSubscribersWithoutChanges(t *testing.T) {
	t.Parallel()
	store := NewStore(&memoryCache{}, nil)
	changes, release := store.Subscribe()
	defer release()
	if err := store.Restore(context.Background()); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	select {
	case <-changes:
	default:
		t.Fatal("restoring an empty cache did not wake subscribers")
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
	store := NewStore(cache, nil)
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
	all := store.SnapshotFor("", true)
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
	unblocked := false
	for _, saved := range cache.saved {
		if saved.TenantID == "a" && !saved.Exhausted() && saved.Version == 10 {
			unblocked = true
		}
	}
	if !unblocked {
		t.Fatalf("the unblock of a at 10 was not cached: %+v", cache.saved)
	}
}

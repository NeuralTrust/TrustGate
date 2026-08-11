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

package ratelimit

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func testStore(t *testing.T) (*Store, *miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewStore(rc, logger), mr, rc
}

func TestStoreIncrBurstFirstHitSetsTTL(t *testing.T) {
	store, mr, _ := testStore(t)
	gatewayID := ids.New[ids.GatewayKind]()

	n, ttl, err := store.IncrBurst(context.Background(), gatewayID)
	if err != nil {
		t.Fatalf("IncrBurst: %v", err)
	}
	if n != 1 {
		t.Fatalf("count = %d, want 1", n)
	}
	if ttl <= 0 || ttl > time.Minute {
		t.Fatalf("ttl = %v, want (0, 1m]", ttl)
	}
	key := fmt.Sprintf(burstKeyPattern, gatewayID.String())
	if !mr.Exists(key) {
		t.Fatalf("missing key %s", key)
	}
	if mr.TTL(key) <= 0 {
		t.Fatalf("key TTL not set")
	}
}

func TestStoreIncrBurstIncrementsSameKey(t *testing.T) {
	store, _, _ := testStore(t)
	gatewayID := ids.New[ids.GatewayKind]()

	for want := int64(1); want <= 5; want++ {
		n, _, err := store.IncrBurst(context.Background(), gatewayID)
		if err != nil {
			t.Fatalf("IncrBurst: %v", err)
		}
		if n != want {
			t.Fatalf("count = %d, want %d", n, want)
		}
	}
}

func TestStoreIncrBurstIsolatesGateways(t *testing.T) {
	store, _, _ := testStore(t)
	a, b := ids.New[ids.GatewayKind](), ids.New[ids.GatewayKind]()

	na, _, err := store.IncrBurst(context.Background(), a)
	if err != nil {
		t.Fatalf("IncrBurst a: %v", err)
	}
	nb, _, err := store.IncrBurst(context.Background(), b)
	if err != nil {
		t.Fatalf("IncrBurst b: %v", err)
	}
	if na != 1 || nb != 1 {
		t.Fatalf("want independent counters, got a=%d b=%d", na, nb)
	}
}

func TestStoreIncrQuotaUsesMonthKey(t *testing.T) {
	store, mr, _ := testStore(t)
	store.now = func() time.Time {
		return time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	}
	gatewayID := ids.New[ids.GatewayKind]()

	n, err := store.IncrQuota(context.Background(), gatewayID, "2026-07")
	if err != nil {
		t.Fatalf("IncrQuota: %v", err)
	}
	if n != 1 {
		t.Fatalf("count = %d, want 1", n)
	}
	key := fmt.Sprintf(quotaKeyPattern, gatewayID.String(), "2026-07")
	if !mr.Exists(key) {
		t.Fatalf("missing key %s", key)
	}
	if mr.TTL(key) <= 0 {
		t.Fatalf("quota key TTL not set")
	}
}

func TestStoreNilRedisUnavailable(t *testing.T) {
	store := NewStore(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, _, err := store.IncrBurst(context.Background(), ids.New[ids.GatewayKind]()); err == nil {
		t.Fatal("want error for nil redis")
	}
	if _, err := store.IncrQuota(context.Background(), ids.New[ids.GatewayKind](), "2026-07"); err == nil {
		t.Fatal("want error for nil redis")
	}
}

func TestStoreIncrBurstConcurrent(t *testing.T) {
	store, _, _ := testStore(t)
	gatewayID := ids.New[ids.GatewayKind]()
	const workers = 40

	var wg sync.WaitGroup
	errs := make(chan error, workers)
	counts := make(chan int64, workers)
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			n, _, err := store.IncrBurst(context.Background(), gatewayID)
			if err != nil {
				errs <- err
				return
			}
			counts <- n
		}()
	}
	wg.Wait()
	close(errs)
	close(counts)
	for err := range errs {
		t.Fatalf("IncrBurst: %v", err)
	}
	seen := map[int64]bool{}
	for n := range counts {
		if seen[n] {
			t.Fatalf("duplicate count %d", n)
		}
		seen[n] = true
	}
	if len(seen) != workers {
		t.Fatalf("unique counts = %d, want %d", len(seen), workers)
	}
}

func TestMsUntilNextUTCMonth(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	ms := msUntilNextUTCMonth(now)
	want := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC).Sub(now).Milliseconds()
	if ms != want {
		t.Fatalf("ms = %d, want %d", ms, want)
	}
}

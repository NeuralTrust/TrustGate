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
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
)

func TestRedisStateCacheKeepsNewestVersion(t *testing.T) {
	t.Parallel()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	cache := NewRedisStateCache(client)
	ctx := context.Background()

	state := func(tenant string, status domain.Status, reason domain.Reason, version int64) domain.TenantState {
		t.Helper()
		got, err := domain.NewTenantState(tenant, status, reason, version)
		if err != nil {
			t.Fatalf("state: %v", err)
		}
		return got
	}
	saveAll := func(states ...domain.TenantState) {
		t.Helper()
		if err := cache.SaveAll(ctx, states); err != nil {
			t.Fatalf("SaveAll: %v", err)
		}
	}
	saveAll(state("tenant-a", domain.StatusExhausted, domain.ReasonWalletEmpty, 10), state("tenant-b", domain.StatusExhausted, domain.ReasonFreeLimitReached, 4))
	saveAll(state("tenant-a", domain.StatusHealthy, domain.ReasonNone, 9))
	if got := server.HGet(StatesKey, "tenant-a"); got != "10|exhausted|wallet_empty" {
		t.Fatalf("tenant-a = %q, an older version replaced a newer one", got)
	}
	saveAll(state("tenant-a", domain.StatusExhausted, domain.ReasonFreeLimitReached, 10))
	if got := server.HGet(StatesKey, "tenant-a"); got != "10|exhausted|wallet_empty" {
		t.Fatalf("tenant-a = %q, a block at the same version replaced the stored one", got)
	}
	saveAll(state("tenant-a", domain.StatusHealthy, domain.ReasonNone, 11), state("tenant-b", domain.StatusHealthy, domain.ReasonNone, 5))
	server.HSet(StatesKey, "tenant-corrupt", "garbage")

	states, err := cache.LoadAll(ctx)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(states) != 2 {
		t.Fatalf("states = %+v, want tenant-a and tenant-b with the corrupt entry skipped", states)
	}
	for _, got := range states {
		want := map[string]int64{"tenant-a": 11, "tenant-b": 5}[got.TenantID]
		if got.Version != want || got.Exhausted() {
			t.Fatalf("states = %+v, want both healthy at their newest version", states)
		}
	}
}

func TestRedisStateCacheSavesAfterTheScriptCacheIsFlushed(t *testing.T) {
	t.Parallel()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	cache := NewRedisStateCache(client)
	ctx := context.Background()
	state, err := domain.NewTenantState("tenant-a", domain.StatusExhausted, domain.ReasonWalletEmpty, 3)
	if err != nil {
		t.Fatalf("state: %v", err)
	}

	if err := client.ScriptFlush(ctx).Err(); err != nil {
		t.Fatalf("SCRIPT FLUSH: %v", err)
	}
	if err := cache.SaveAll(ctx, []domain.TenantState{state}); err != nil {
		t.Fatalf("SaveAll on a Redis without the script: %v", err)
	}
	if got := server.HGet(StatesKey, "tenant-a"); got != "3|exhausted|wallet_empty" {
		t.Fatalf("tenant-a = %q", got)
	}
}

func TestRedisStateCacheHealthyWinsAtTheSameVersion(t *testing.T) {
	t.Parallel()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	cache := NewRedisStateCache(client)
	ctx := context.Background()
	exhausted, err := domain.NewTenantState("tenant-a", domain.StatusExhausted, domain.ReasonWalletEmpty, 9)
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	healthy, err := domain.NewTenantState("tenant-a", domain.StatusHealthy, domain.ReasonNone, 9)
	if err != nil {
		t.Fatalf("state: %v", err)
	}

	if err := cache.SaveAll(ctx, []domain.TenantState{exhausted}); err != nil {
		t.Fatalf("SaveAll: %v", err)
	}
	if err := cache.SaveAll(ctx, []domain.TenantState{healthy}); err != nil {
		t.Fatalf("SaveAll: %v", err)
	}
	if got := server.HGet(StatesKey, "tenant-a"); got != "9|healthy|" {
		t.Fatalf("tenant-a = %q, want the unblock at the same version stored", got)
	}
	if err := cache.SaveAll(ctx, []domain.TenantState{exhausted}); err != nil {
		t.Fatalf("SaveAll: %v", err)
	}
	if got := server.HGet(StatesKey, "tenant-a"); got != "9|healthy|" {
		t.Fatalf("tenant-a = %q, a block at the same version must not undo the unblock", got)
	}
}

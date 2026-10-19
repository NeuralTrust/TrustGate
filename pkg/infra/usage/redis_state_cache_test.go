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

	save := func(status domain.Status, reason domain.Reason, version int64) bool {
		t.Helper()
		state, err := domain.NewTenantState("tenant-a", status, reason, version)
		if err != nil {
			t.Fatalf("state: %v", err)
		}
		stored, err := cache.Save(ctx, state)
		if err != nil {
			t.Fatalf("Save: %v", err)
		}
		return stored
	}
	if !save(domain.StatusExhausted, domain.ReasonWalletEmpty, 10) {
		t.Fatal("first save not stored")
	}
	if save(domain.StatusHealthy, domain.ReasonNone, 9) {
		t.Fatal("older version replaced a newer one")
	}
	if save(domain.StatusHealthy, domain.ReasonNone, 10) {
		t.Fatal("same version replaced the stored one")
	}
	if !save(domain.StatusHealthy, domain.ReasonNone, 11) {
		t.Fatal("newer version not stored")
	}
	server.HSet(StatesKey, "tenant-corrupt", "garbage")

	states, err := cache.LoadAll(ctx)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(states) != 1 || states[0].TenantID != "tenant-a" || states[0].Version != 11 || states[0].Exhausted() {
		t.Fatalf("states = %+v, want tenant-a healthy at 11 and the corrupt entry skipped", states)
	}
}
